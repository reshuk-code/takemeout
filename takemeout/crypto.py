"""Key handling and primitives: X25519, HKDF-SHA256, ChaCha20-Poly1305."""

import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = [
    "X25519PrivateKey", "ChaCha20Poly1305", "generate_private", "private_to_b64",
    "private_from_b64", "public_bytes", "pub_to_b64", "pub_from_b64", "dh", "hkdf",
    "load_private_file", "write_private_file",
]

_RAW = serialization.Encoding.Raw


def generate_private() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def private_to_b64(key: X25519PrivateKey) -> str:
    raw = key.private_bytes(_RAW, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return base64.b64encode(raw).decode()


def private_from_b64(text: str) -> X25519PrivateKey:
    raw = base64.b64decode(text.strip(), validate=True)
    if len(raw) != 32:
        raise ValueError("private key must be 32 bytes")
    return X25519PrivateKey.from_private_bytes(raw)


def public_bytes(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(_RAW, serialization.PublicFormat.Raw)


def pub_to_b64(pub: bytes) -> str:
    return base64.b64encode(pub).decode()


def pub_from_b64(text: str) -> bytes:
    raw = base64.b64decode(text.strip(), validate=True)
    if len(raw) != 32:
        raise ValueError("public key must be 32 bytes")
    return raw


def dh(priv: X25519PrivateKey, pub: bytes) -> bytes:
    return priv.exchange(X25519PublicKey.from_public_bytes(pub))


def hkdf(ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=b"takemeout-v1", info=info).derive(ikm)


def load_private_file(path: str) -> X25519PrivateKey:
    with open(path) as f:
        return private_from_b64(f.read())


def write_private_file(path: str, key: X25519PrivateKey) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(private_to_b64(key) + "\n")
