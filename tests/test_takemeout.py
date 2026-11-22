import ipaddress
import os
import socket
import struct
import tempfile
import time
import unittest

from takemeout import protocol as p
from takemeout.client import Client
from takemeout.crypto import generate_private, pub_to_b64, public_bytes
from takemeout.server import Server, load_peers


def ipv4_packet(src, dst, payload=b"hello"):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, 17, 0,
                      ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return hdr + payload


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.s_key, self.c_key = generate_private(), generate_private()
        self.cfg = p.TunnelConfig(ipaddress.IPv4Address("10.8.0.2"), 24, ipaddress.IPv4Address("10.8.0.1"), 1400)
        self.last_ts = 0

    def authorize(self, pub, ts):
        if pub != public_bytes(self.c_key):
            raise p.HandshakeError("unknown")
        if ts <= self.last_ts:
            raise p.HandshakeError("replay")
        self.last_ts = ts
        return "peer", self.cfg

    def handshake(self):
        hs = p.ClientHandshake(self.c_key, public_bytes(self.s_key))
        init = hs.init_message()
        self.assertEqual(len(init), p.INIT_LEN)
        _, s_sess, resp = p.server_handshake(self.s_key, init, self.authorize, 42)
        self.assertEqual(len(resp), p.RESP_LEN)
        c_sess, cfg = hs.process_response(resp)
        return c_sess, s_sess, cfg, init

    def test_roundtrip(self):
        c, s, cfg, _ = self.handshake()
        self.assertEqual(cfg, self.cfg)
        self.assertEqual(s.open(c.seal(b"ping")), b"ping")
        self.assertEqual(c.open(s.seal(b"pong")), b"pong")
        self.assertEqual(s.open(c.seal(b"")), b"")

    def test_replayed_and_tampered_packets_rejected(self):
        c, s, _, _ = self.handshake()
        pkt = c.seal(b"data")
        self.assertEqual(s.open(pkt), b"data")
        self.assertIsNone(s.open(pkt))
        bad = bytearray(c.seal(b"data"))
        bad[-1] ^= 1
        self.assertIsNone(s.open(bytes(bad)))

    def test_out_of_order_within_window(self):
        c, s, _, _ = self.handshake()
        pkts = [c.seal(bytes([i])) for i in range(5)]
        for i in (3, 0, 4, 1, 2):
            self.assertEqual(s.open(pkts[i]), bytes([i]))

    def test_replayed_init_rejected(self):
        _, _, _, init = self.handshake()
        with self.assertRaises(p.HandshakeError):
            p.server_handshake(self.s_key, init, self.authorize, 43)

    def test_unknown_client_rejected(self):
        hs = p.ClientHandshake(generate_private(), public_bytes(self.s_key))
        with self.assertRaises(p.HandshakeError):
            p.server_handshake(self.s_key, hs.init_message(), self.authorize, 1)

    def test_wrong_server_key_fails(self):
        hs = p.ClientHandshake(self.c_key, public_bytes(generate_private()))
        with self.assertRaises(p.HandshakeError):
            p.server_handshake(self.s_key, hs.init_message(), self.authorize, 1)

    def test_replay_window_far_jump(self):
        w = p.ReplayWindow()
        for n in (0, 1, 5000):
            self.assertTrue(w.check(n))
            w.update(n)
        self.assertFalse(w.check(1))
        self.assertFalse(w.check(5000))
        self.assertTrue(w.check(4999))


class PeersFileTests(unittest.TestCase):
    def test_assignment(self):
        keys = [pub_to_b64(public_bytes(generate_private())) for _ in range(3)]
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(f"# comment\nalice {keys[0]}\nbob {keys[1]} 10.8.0.2\ncarol {keys[2]}\n")
        net = ipaddress.IPv4Network("10.8.0.0/24")
        peers = load_peers(f.name, net, ipaddress.IPv4Address("10.8.0.1"))
        os.unlink(f.name)
        self.assertEqual([str(x.ip) for x in peers], ["10.8.0.3", "10.8.0.2", "10.8.0.4"])


class FakeHost:
    def __init__(self):
        self.calls = []

    def iface_up(self, *a):
        self.calls.append(("iface_up",) + a)

    def cleanup(self):
        pass


class EndToEndTests(unittest.TestCase):
    """Real server and client talking over loopback UDP; socketpairs stand in for TUN devices."""

    def test_tunnel(self):
        s_key, c_key = generate_private(), generate_private()
        tmp = tempfile.NamedTemporaryFile("w", delete=False)
        tmp.write(f"laptop {pub_to_b64(public_bytes(c_key))}\n")
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)

        server = Server(s_key, tmp.name, ("127.0.0.1", 0), "10.8.0.0/24", "x", 1400, False)
        s_tun_app, s_tun = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        server.tun_fd, server.iface, server.host = s_tun.fileno(), "x", FakeHost()
        server.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.sock.bind(("127.0.0.1", 0))
        server.sock.setblocking(False)
        s_tun.setblocking(False)
        port = server.sock.getsockname()[1]

        client = Client(c_key, ("127.0.0.1", port), public_bytes(s_key), "y", False, None)
        c_tun_app, c_tun = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        c_tun.setblocking(False)
        client.tun_fd, client.iface, client.host = c_tun.fileno(), "y", FakeHost()
        client.server_addr = ("127.0.0.1", port)
        client.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.sock.setblocking(False)

        def pump(n=20):
            for _ in range(n):
                server.on_udp(); server.on_tun(); client.on_udp(); client.on_tun()
                time.sleep(0.005)

        client._start_handshake()
        pump()
        self.assertEqual(client.state, "connected")
        self.assertEqual(str(client.cfg.client_ip), "10.8.0.2")
        self.assertIn(("iface_up", "y", "10.8.0.2/24", 1400), client.host.calls)
        self.assertIsNotNone(server.peers[0].session)  # promoted by the confirming keepalive

        out = ipv4_packet("10.8.0.2", "10.8.0.1", b"to server")
        c_tun_app.send(out)
        pump()
        self.assertEqual(s_tun_app.recv(2000), out)

        back = ipv4_packet("10.8.0.1", "10.8.0.2", b"to client")
        s_tun_app.send(back)
        pump()
        self.assertEqual(c_tun_app.recv(2000), back)

        # A packet claiming another source address is dropped by the server.
        s_tun_app.setblocking(False)
        c_tun_app.send(ipv4_packet("10.8.0.99", "10.8.0.1"))
        pump()
        with self.assertRaises(BlockingIOError):
            s_tun_app.recv(2000)

        # Rekey: the new session takes over and traffic keeps flowing.
        old_sid = client.session.sid
        client._start_handshake()
        pump()
        self.assertNotEqual(client.session.sid, old_sid)
        c_tun_app.send(out)
        pump()
        self.assertEqual(s_tun_app.recv(2000), out)

        for s in (server.sock, client.sock, s_tun_app, s_tun, c_tun_app, c_tun):
            s.close()


if __name__ == "__main__":
    unittest.main()
