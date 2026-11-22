"""Wire protocol: a 1-RTT authenticated handshake plus encrypted data packets.

Handshake (client C, server S; both hold static X25519 keys, C knows S's public key):

  INIT  C->S : 0x01 | e_c(32) | AEAD(k1, s_c)(48) | AEAD(k2, timestamp)(24)
        k1 = HKDF(DH(e_c, S) || e_c || S)            -- hides C's identity
        k2 = HKDF(DH(e_c, S) || DH(s_c, S) || e_c)    -- proves C owns s_c; ts stops replays

  RESP  S->C : 0x02 | sid(4) | e_s(32) | AEAD(k_resp, tunnel config)(27)
        keys = HKDF(es || ee || se || ss, e_c || e_s) -> k_c2s, k_s2c, k_resp

The session keys mix ephemeral-ephemeral DH (forward secrecy) with both static keys
(mutual authentication).

  DATA  either way : 0x03 | sid(4) | counter(8) | AEAD(k_dir, ip packet)
        An empty payload is a keepalive. Counters are checked against a sliding replay window.
"""

import ipaddress
import os
import struct
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag

from .crypto import ChaCha20Poly1305, X25519PrivateKey, dh, hkdf, public_bytes

MSG_INIT = 1
MSG_RESP = 2
MSG_DATA = 3

ZERO_NONCE = bytes(12)
INIT_LEN = 1 + 32 + (32 + 16) + (8 + 16)
_CFG = struct.Struct("!4sB4sH")
RESP_LEN = 1 + 4 + 32 + _CFG.size + 16
DATA_HDR = struct.Struct("!BIQ")
DATA_OVERHEAD = DATA_HDR.size + 16

REKEY_AFTER_SECONDS = 120
REJECT_AFTER_SECONDS = 180
REJECT_AFTER_MESSAGES = 2**60


class HandshakeError(Exception):
    pass


@dataclass
class TunnelConfig:
    client_ip: ipaddress.IPv4Address
    prefix: int
    server_ip: ipaddress.IPv4Address
    mtu: int

    def pack(self) -> bytes:
        return _CFG.pack(self.client_ip.packed, self.prefix, self.server_ip.packed, self.mtu)

    @classmethod
    def unpack(cls, data: bytes) -> "TunnelConfig":
        cip, prefix, sip, mtu = _CFG.unpack(data)
        return cls(ipaddress.IPv4Address(cip), prefix, ipaddress.IPv4Address(sip), mtu)


class ReplayWindow:
    SIZE = 2048

    def __init__(self):
        self.top = -1
        self.bits = 0

    def check(self, n: int) -> bool:
        if n > self.top:
            return True
        off = self.top - n
        return off < self.SIZE and not (self.bits >> off) & 1

    def update(self, n: int) -> None:
        if n > self.top:
            shift = n - self.top
            self.bits = ((self.bits << shift) | 1) & ((1 << self.SIZE) - 1) if shift < self.SIZE else 1
            self.top = n
        else:
            self.bits |= 1 << (self.top - n)


class Session:
    def __init__(self, sid: int, send_key: bytes, recv_key: bytes):
        self.sid = sid
        self._tx = ChaCha20Poly1305(send_key)
        self._rx = ChaCha20Poly1305(recv_key)
        self.counter = 0
        self.window = ReplayWindow()
        self.created = time.monotonic()
        self.last_rx = self.created

    @property
    def age(self) -> float:
        return time.monotonic() - self.created

    def expired(self) -> bool:
        return self.age > REJECT_AFTER_SECONDS or self.counter >= REJECT_AFTER_MESSAGES

    def seal(self, payload: bytes) -> bytes:
        if self.expired():
            raise HandshakeError("session expired")
        hdr = DATA_HDR.pack(MSG_DATA, self.sid, self.counter)
        nonce = b"\0\0\0\0" + self.counter.to_bytes(8, "little")
        self.counter += 1
        return hdr + self._tx.encrypt(nonce, payload, hdr)

    def open(self, packet: bytes):
        """Return the decrypted payload, or None if the packet is forged, replayed or late."""
        if len(packet) < DATA_OVERHEAD or self.expired():
            return None
        _, _, ctr = DATA_HDR.unpack_from(packet)
        if not self.window.check(ctr):
            return None
        nonce = b"\0\0\0\0" + ctr.to_bytes(8, "little")
        try:
            plain = self._rx.decrypt(nonce, packet[DATA_HDR.size:], packet[:DATA_HDR.size])
        except InvalidTag:
            return None
        self.window.update(ctr)
        self.last_rx = time.monotonic()
        return plain


def packet_sid(packet: bytes):
    if len(packet) < DATA_OVERHEAD or packet[0] != MSG_DATA:
        return None
    return DATA_HDR.unpack_from(packet)[1]


def _session_keys(es, ee, se, ss, e_c, e_s):
    okm = hkdf(es + ee + se + ss, b"tmo session" + e_c + e_s, 96)
    return okm[:32], okm[32:64], okm[64:]


class ClientHandshake:
    def __init__(self, static: X25519PrivateKey, server_pub: bytes):
        self.static = static
        self.server_pub = server_pub
        self.eph = X25519PrivateKey.generate()
        self.e_c = public_bytes(self.eph)
        self.es = dh(self.eph, server_pub)
        self.ss = dh(static, server_pub)
        self.sent_at = 0.0

    def init_message(self) -> bytes:
        self.sent_at = time.monotonic()
        hdr = bytes([MSG_INIT]) + self.e_c
        k1 = hkdf(self.es + self.e_c + self.server_pub, b"tmo init id", 32)
        k2 = hkdf(self.es + self.ss + self.e_c, b"tmo init ts", 32)
        enc_static = ChaCha20Poly1305(k1).encrypt(ZERO_NONCE, public_bytes(self.static), hdr)
        enc_ts = ChaCha20Poly1305(k2).encrypt(ZERO_NONCE, struct.pack("!Q", time.time_ns()), hdr + enc_static)
        return hdr + enc_static + enc_ts

    def process_response(self, msg: bytes):
        if len(msg) != RESP_LEN or msg[0] != MSG_RESP:
            raise HandshakeError("malformed response")
        sid = struct.unpack("!I", msg[1:5])[0]
        e_s = msg[5:37]
        ee = dh(self.eph, e_s)
        se = dh(self.static, e_s)
        k_c2s, k_s2c, k_resp = _session_keys(self.es, ee, se, self.ss, self.e_c, e_s)
        try:
            cfg = ChaCha20Poly1305(k_resp).decrypt(ZERO_NONCE, msg[37:], msg[:37])
        except InvalidTag:
            raise HandshakeError("response failed authentication") from None
        return Session(sid, send_key=k_c2s, recv_key=k_s2c), TunnelConfig.unpack(cfg)


def server_handshake(static: X25519PrivateKey, msg: bytes, authorize, sid: int):
    """Process an INIT. `authorize(client_pub, timestamp_ns)` returns (peer, TunnelConfig)
    or raises HandshakeError. Returns (peer, session, response_bytes)."""
    if len(msg) != INIT_LEN or msg[0] != MSG_INIT:
        raise HandshakeError("malformed init")
    s_pub = public_bytes(static)
    hdr, e_c = msg[:33], msg[1:33]
    enc_static, enc_ts = msg[33:81], msg[81:]
    es = dh(static, e_c)
    k1 = hkdf(es + e_c + s_pub, b"tmo init id", 32)
    try:
        c_pub = ChaCha20Poly1305(k1).decrypt(ZERO_NONCE, enc_static, hdr)
        ss = dh(static, c_pub)
        k2 = hkdf(es + ss + e_c, b"tmo init ts", 32)
        ts = struct.unpack("!Q", ChaCha20Poly1305(k2).decrypt(ZERO_NONCE, enc_ts, hdr + enc_static))[0]
    except (InvalidTag, ValueError):
        raise HandshakeError("init failed authentication") from None

    peer, cfg = authorize(c_pub, ts)

    eph = X25519PrivateKey.generate()
    e_s = public_bytes(eph)
    ee = dh(eph, e_c)
    se = dh(eph, c_pub)
    k_c2s, k_s2c, k_resp = _session_keys(es, ee, se, ss, e_c, e_s)
    rhdr = bytes([MSG_RESP]) + struct.pack("!I", sid) + e_s
    resp = rhdr + ChaCha20Poly1305(k_resp).encrypt(ZERO_NONCE, cfg.pack(), rhdr)
    return peer, Session(sid, send_key=k_s2c, recv_key=k_c2s), resp


def random_sid() -> int:
    return int.from_bytes(os.urandom(4), "big")
