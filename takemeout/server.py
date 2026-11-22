"""VPN server: accepts authorized peers, hands out tunnel IPs, forwards packets."""

import ipaddress
import os
import socket
import time

from . import protocol as p
from .crypto import pub_from_b64, pub_to_b64, public_bytes
from .net import HostConfig, NetError, open_tun
from .tui import RateMeter, ago, human_bytes, log


class Peer:
    def __init__(self, name, pub, ip):
        self.name, self.pub, self.ip = name, pub, ip
        self.endpoint = None
        self.last_ts = 0
        self.session = None    # used for sending
        self.pending = None    # new session, promoted once the client uses it
        self.last_handshake = None
        self.rx = self.tx = 0


def load_peers(path, subnet: ipaddress.IPv4Network, server_ip):
    """Peers file: one `name public_key [tunnel_ip]` per line, `#` for comments."""
    entries = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            parts = line.split("#", 1)[0].split()
            if not parts:
                continue
            if len(parts) not in (2, 3):
                raise ValueError(f"{path}:{n}: expected `name public_key [ip]`")
            try:
                pub = pub_from_b64(parts[1])
                ip = ipaddress.IPv4Address(parts[2]) if len(parts) == 3 else None
            except ValueError as e:
                raise ValueError(f"{path}:{n}: {e}") from None
            if ip is not None and (ip not in subnet or ip == server_ip):
                raise ValueError(f"{path}:{n}: {ip} is not a free address in {subnet}")
            entries.append((parts[0], pub, ip))

    taken = {server_ip} | {ip for _, _, ip in entries if ip}
    pool = (h for h in subnet.hosts() if h not in taken)
    peers, seen_pubs, seen_ips = [], set(), set()
    for name, pub, ip in entries:
        if pub in seen_pubs:
            raise ValueError(f"{path}: public key for {name!r} is listed twice")
        ip = ip or next(pool, None)
        if ip is None:
            raise ValueError(f"{path}: subnet {subnet} has no free addresses left")
        if ip in seen_ips:
            raise ValueError(f"{path}: address {ip} is assigned twice")
        seen_pubs.add(pub)
        seen_ips.add(ip)
        peers.append(Peer(name, pub, ip))
    return peers


class Server:
    def __init__(self, key, peers_path, listen, subnet, iface, mtu, nat):
        self.key = key
        self.pub = public_bytes(key)
        self.listen = listen
        self.subnet = ipaddress.IPv4Network(subnet, strict=False)
        self.server_ip = next(self.subnet.hosts())
        self.peers = load_peers(peers_path, self.subnet, self.server_ip)
        self.by_pub = {pr.pub: pr for pr in self.peers}
        self.by_ip = {pr.ip.packed: pr for pr in self.peers}
        self.sessions = {}  # sid -> (Session, Peer)
        self.iface_name, self.mtu, self.nat = iface, mtu, nat
        self.sock = self.tun_fd = None
        self.host = HostConfig(log)
        self.rates = RateMeter()
        self._next_timer = 0.0
        self.started = time.monotonic()

    # --- lifecycle --------------------------------------------------------------------

    def setup(self):
        self.tun_fd, self.iface = open_tun(self.iface_name)
        self.host.iface_up(self.iface, f"{self.server_ip}/{self.subnet.prefixlen}", self.mtu)
        if self.nat:
            self.host.enable_nat(str(self.subnet), self.iface)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind(self.listen)
        except OSError as e:
            raise NetError(f"cannot listen on {self.listen[0]}:{self.listen[1]}: {e}") from e
        self.sock.setblocking(False)
        log.info("listening on udp %s:%d, tunnel %s %s/%d, %d peer(s)", *self.listen,
                 self.iface, self.server_ip, self.subnet.prefixlen, len(self.peers))
        log.info("server public key: %s", pub_to_b64(self.pub))

    def close(self):
        self.host.cleanup()
        if self.sock:
            self.sock.close()
        if self.tun_fd is not None:
            os.close(self.tun_fd)

    # --- network events ---------------------------------------------------------------

    def on_udp(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as e:  # e.g. ICMP port unreachable surfaced on the socket
                log.debug("udp error: %s", e)
                continue
            if not data:
                continue
            if data[0] == p.MSG_INIT:
                self._handshake(data, addr)
            elif data[0] == p.MSG_DATA:
                self._data(data, addr)

    def _handshake(self, data, addr):
        sid = p.random_sid()
        while sid in self.sessions:
            sid = p.random_sid()
        try:
            peer, sess, resp = p.server_handshake(self.key, data, self._authorize, sid)
        except p.HandshakeError as e:
            log.debug("rejected handshake from %s:%d: %s", *addr, e)
            return
        self.sessions[sid] = (sess, peer)
        peer.pending = sess
        peer.endpoint = addr
        first = peer.last_handshake is None or peer.session is None
        peer.last_handshake = time.monotonic()
        self.sock.sendto(resp, addr)
        if first:
            log.info("%s connected from %s:%d as %s", peer.name, *addr, peer.ip)
        else:
            log.debug("%s rekeyed", peer.name)

    def _authorize(self, client_pub, ts):
        peer = self.by_pub.get(client_pub)
        if peer is None:
            raise p.HandshakeError(f"unknown key {pub_to_b64(client_pub)}")
        if ts <= peer.last_ts:
            raise p.HandshakeError(f"replayed handshake for {peer.name}")
        peer.last_ts = ts
        return peer, p.TunnelConfig(peer.ip, self.subnet.prefixlen, self.server_ip, self.mtu)

    def _data(self, data, addr):
        entry = self.sessions.get(p.packet_sid(data))
        if entry is None:
            return
        sess, peer = entry
        plain = sess.open(data)
        if plain is None:
            return
        if peer.pending is sess:
            peer.session, peer.pending = sess, None
        if peer.endpoint != addr:
            log.info("%s moved to %s:%d", peer.name, *addr)
            peer.endpoint = addr
        if not plain:
            return  # keepalive
        # Only accept IPv4 packets whose source is the peer's own tunnel address.
        if len(plain) < 20 or plain[0] >> 4 != 4 or plain[12:16] != peer.ip.packed:
            log.debug("dropped spoofed/non-IPv4 packet from %s", peer.name)
            return
        peer.rx += len(plain)
        try:
            os.write(self.tun_fd, plain)
        except OSError as e:
            log.debug("tun write failed: %s", e)

    def on_tun(self):
        while True:
            try:
                pkt = os.read(self.tun_fd, 65535)
            except (BlockingIOError, InterruptedError):
                return
            if len(pkt) < 20 or pkt[0] >> 4 != 4:
                continue
            peer = self.by_ip.get(pkt[16:20])
            if peer is None or peer.endpoint is None:
                continue
            sess = peer.session or peer.pending
            if sess is None or sess.expired():
                continue
            try:
                self.sock.sendto(sess.seal(pkt), peer.endpoint)
                peer.tx += len(pkt)
            except OSError as e:
                log.debug("send to %s failed: %s", peer.name, e)

    def on_timer(self):
        now = time.monotonic()
        if now < self._next_timer:
            return
        self._next_timer = now + 1
        for sid, (sess, peer) in list(self.sessions.items()):
            if sess.expired() or now - sess.last_rx > p.REJECT_AFTER_SECONDS / 2:
                del self.sessions[sid]
                if peer.pending is sess:
                    peer.pending = None
                if peer.session is sess:
                    peer.session = None
                    if peer.pending is None:
                        log.info("%s disconnected (timeout)", peer.name)

    # --- dashboard --------------------------------------------------------------------

    def snapshot(self):
        rows, rx_total, tx_total = [], 0, 0
        for pr in self.peers:
            online = pr.session is not None or pr.pending is not None
            rx_total += pr.rx
            tx_total += pr.tx
            ep = f"{pr.endpoint[0]}:{pr.endpoint[1]}" if pr.endpoint and online else "-"
            rows.append([
                ("● " if online else "○ ") + pr.name, str(pr.ip), ep,
                f"{human_bytes(pr.rx)} / {human_bytes(pr.tx)}",
                f"{human_bytes(self.rates.rate(pr.name + 'rx', pr.rx))}/s",
                ago(pr.last_handshake),
            ])
        online = sum(1 for pr in self.peers if pr.session or pr.pending)
        up = int(time.monotonic() - self.started)
        return {
            "title": "server",
            "state": "listening",
            "status": [
                ("listen", f"udp {self.listen[0]}:{self.listen[1]}"),
                ("tunnel", f"{self.iface}  {self.server_ip}/{self.subnet.prefixlen}  mtu {self.mtu}"),
                ("nat", "on" if self.nat else "off"),
                ("public key", pub_to_b64(self.pub)),
                ("peers", f"{online} online / {len(self.peers)} allowed"),
                ("traffic", f"↓ {human_bytes(rx_total)}  ↑ {human_bytes(tx_total)}"),
                ("uptime", f"{up // 3600}h {up // 60 % 60}m {up % 60}s"),
            ],
            "header": ["peer", "tunnel ip", "endpoint", "rx / tx", "rx rate", "handshake"],
            "widths": [16, 13, 22, 22, 12, 10],
            "rows": rows,
            "empty": "no peers in the peers file",
        }
