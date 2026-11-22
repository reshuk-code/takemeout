"""VPN client: handshakes with the server, configures the tunnel, keeps it alive."""

import os
import socket
import time

from . import protocol as p
from .crypto import pub_to_b64, public_bytes
from .net import HostConfig, NetError, open_tun, run
from .tui import RateMeter, ago, human_bytes, log

HANDSHAKE_RETRY = 5
KEEPALIVE = 10
DEAD_AFTER = 35


class Client:
    def __init__(self, key, server, server_pub, iface, full, dns):
        self.key = key
        self.server_host, self.server_port = server
        self.server_pub = server_pub
        self.iface_name, self.full, self.dns = iface, full, dns
        self.sock = self.tun_fd = None
        self.host = HostConfig(log)
        self.hs = None
        self.session = self.prev = None
        self.cfg = None
        self.configured_ip = None
        self.state = "connecting"
        self.rx = self.tx = 0
        self.last_tx = 0.0
        self.connected_at = None
        self.last_handshake = None
        self.attempts = 0
        self.rates = RateMeter()

    # --- lifecycle --------------------------------------------------------------------

    def setup(self):
        try:
            info = socket.getaddrinfo(self.server_host, self.server_port, socket.AF_INET, socket.SOCK_DGRAM)
        except socket.gaierror as e:
            raise NetError(f"cannot resolve {self.server_host}: {e}") from e
        self.server_addr = info[0][4]
        self.tun_fd, self.iface = open_tun(self.iface_name)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        log.info("connecting to %s:%d", *self.server_addr)
        self._start_handshake()

    def close(self):
        self.host.cleanup()
        if self.sock:
            self.sock.close()
        if self.tun_fd is not None:
            os.close(self.tun_fd)

    # --- handshake & tunnel config ----------------------------------------------------

    def _start_handshake(self):
        self.hs = p.ClientHandshake(self.key, self.server_pub)
        self.attempts += 1
        try:
            self.sock.sendto(self.hs.init_message(), self.server_addr)
        except OSError as e:
            log.warning("cannot reach server: %s", e)

    def _on_response(self, data):
        if self.hs is None:
            return
        try:
            sess, cfg = self.hs.process_response(data)
        except p.HandshakeError as e:
            log.warning("bad handshake response: %s", e)
            return
        self.hs = None
        self.attempts = 0
        self.prev, self.session = self.session, sess
        self.last_handshake = time.monotonic()
        self._send(b"")  # confirms the new session to the server
        if self.configured_ip != cfg.client_ip:
            self._configure(cfg)
        self.cfg = cfg
        if self.state != "connected":
            self.state = "connected"
            self.connected_at = time.monotonic()
            log.info("connected: tunnel ip %s, server %s", cfg.client_ip, cfg.server_ip)
        else:
            log.debug("rekeyed")

    def _configure(self, cfg):
        if self.configured_ip is not None:
            run("ip", "addr", "flush", "dev", self.iface, check=False)
        self.host.iface_up(self.iface, f"{cfg.client_ip}/{cfg.prefix}", cfg.mtu)
        first = self.configured_ip is None
        self.configured_ip = cfg.client_ip
        if first and self.full:
            self.host.full_tunnel(self.iface, self.server_addr[0])
        if first and self.dns:
            self.host.set_dns(self.dns)

    # --- network events ---------------------------------------------------------------

    def _send(self, payload):
        if self.session is None or self.session.expired():
            return
        try:
            self.sock.sendto(self.session.seal(payload), self.server_addr)
            self.last_tx = time.monotonic()
        except OSError as e:
            log.debug("send failed: %s", e)

    def on_udp(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as e:
                log.debug("udp error: %s", e)
                continue
            if addr != self.server_addr or not data:
                continue
            if data[0] == p.MSG_RESP:
                self._on_response(data)
            elif data[0] == p.MSG_DATA:
                sid = p.packet_sid(data)
                sess = next((s for s in (self.session, self.prev) if s and s.sid == sid), None)
                plain = sess.open(data) if sess else None
                if plain:
                    self.rx += len(plain)
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
            if self.session and len(pkt) >= 20 and pkt[0] >> 4 == 4:
                self.tx += len(pkt)
                self._send(pkt)

    def on_timer(self):
        now = time.monotonic()
        if self.hs and now - self.hs.sent_at > HANDSHAKE_RETRY:
            log.info("no answer from server, retrying (attempt %d)", self.attempts + 1)
            self._start_handshake()
        if self.session is None:
            if self.hs is None:
                self._start_handshake()
            return
        if now - self.session.last_rx > DEAD_AFTER:
            log.warning("server stopped responding, reconnecting")
            self.session = self.prev = None
            self.state = "connecting"
            self._start_handshake()
            return
        if self.hs is None and self.session.age > p.REKEY_AFTER_SECONDS:
            self._start_handshake()
        if now - self.last_tx > KEEPALIVE:
            self._send(b"")

    # --- dashboard --------------------------------------------------------------------

    def snapshot(self):
        up = int(time.monotonic() - self.connected_at) if self.connected_at and self.state == "connected" else 0
        server = f"{self.server_host}:{self.server_port}"
        if getattr(self, "server_addr", None) and self.server_addr[0] != self.server_host:
            server += f"  ({self.server_addr[0]})"
        status = [
            ("server", server),
            ("tunnel", f"{self.iface}  {self.cfg.client_ip}/{self.cfg.prefix}  mtu {self.cfg.mtu}" if self.cfg else "-"),
            ("routing", "full tunnel (all IPv4)" if self.full else "vpn subnet only"),
            ("dns", ", ".join(self.dns) if self.dns else "unchanged"),
            ("public key", pub_to_b64(public_bytes(self.key))),
            ("received", f"{human_bytes(self.rx)}   {human_bytes(self.rates.rate('rx', self.rx))}/s"),
            ("sent", f"{human_bytes(self.tx)}   {human_bytes(self.rates.rate('tx', self.tx))}/s"),
            ("handshake", ago(self.last_handshake)),
            ("uptime", f"{up // 3600}h {up // 60 % 60}m {up % 60}s"),
        ]
        return {"title": "client", "state": self.state, "status": status}
