"""Command-line entry point."""

import argparse
import ipaddress
import os
import sys

from . import __version__
from .crypto import (generate_private, load_private_file, pub_from_b64, pub_to_b64,
                     public_bytes, write_private_file)

DEFAULT_PORT = 51820


def _hostport(text, default_host=None):
    host, sep, port = text.rpartition(":")
    if not sep:
        host, port = (default_host, text) if default_host and text.isdigit() else (text, str(DEFAULT_PORT))
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise argparse.ArgumentTypeError(f"bad port in {text!r}")
    return host or default_host, int(port)


def _pubkey(text):
    try:
        return pub_from_b64(text)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"bad public key: {e}") from None


def _ipv4(text):
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an IPv4 address: {text!r}") from None


def _load_key(path):
    try:
        return load_private_file(path)
    except FileNotFoundError:
        sys.exit(f"takemeout: key file not found: {path}  (create one with `takemeout genkey -o {path}`)")
    except ValueError as e:
        sys.exit(f"takemeout: {path}: {e}")


def _give_to_sudo_user(path):
    """Files created under sudo should belong to the real user, not root."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() == 0 and uid and gid:
        os.chown(path, int(uid), int(gid))


def _load_or_create_key(path):
    """Load a private key, generating it on first run. Returns (key, created)."""
    if os.path.exists(path):
        return _load_key(path), False
    key = generate_private()
    write_private_file(path, key)
    _give_to_sudo_user(path)
    return key, True


def _need_root():
    if os.geteuid() != 0:
        sys.exit("takemeout: creating a tunnel needs root, run with sudo")


def cmd_genkey(a):
    key = generate_private()
    if a.output:
        try:
            write_private_file(a.output, key)
        except FileExistsError:
            sys.exit(f"takemeout: {a.output} already exists, refusing to overwrite")
        print(f"private key written to {a.output}", file=sys.stderr)
        print(pub_to_b64(public_bytes(key)))
    else:
        from .crypto import private_to_b64
        print(f"private: {private_to_b64(key)}")
        print(f"public:  {pub_to_b64(public_bytes(key))}")


def cmd_pubkey(a):
    print(pub_to_b64(public_bytes(_load_key(a.keyfile))))


def cmd_addpeer(a):
    line = f"{a.name} {pub_to_b64(a.public_key)}" + (f" {a.ip}" if a.ip else "") + "\n"
    if os.path.exists(a.peers):
        with open(a.peers) as f:
            existing = f.read()
        for row in existing.splitlines():
            parts = row.split("#", 1)[0].split()
            if parts and (parts[0] == a.name or parts[1:2] == [pub_to_b64(a.public_key)]):
                sys.exit(f"takemeout: {a.peers} already has an entry for that name or key")
        if existing and not existing.endswith("\n"):
            line = "\n" + line
    with open(a.peers, "a") as f:
        f.write(line)
    print(f"added {a.name} to {a.peers} (restart the server to apply)")


def _run(node, a):
    from .net import NetError
    from .runner import run
    from .tui import setup_logging

    logbuf = setup_logging(tui=not a.no_tui and sys.stdout.isatty(), verbose=a.verbose)
    try:
        run(node, logbuf)
    except NetError as e:
        sys.exit(f"takemeout: {e}")
    if logbuf:  # show what happened once curses is gone
        for _, line in list(logbuf.lines)[-8:]:
            print(line)


def cmd_server(a):
    from .server import Server
    _need_root()
    key, created = _load_or_create_key(a.key)
    if created:
        print(f"first run: created server key {a.key}")
    if not os.path.exists(a.peers):
        with open(a.peers, "w") as f:
            f.write("# takemeout peers: one `name public_key [tunnel_ip]` per line\n")
        _give_to_sudo_user(a.peers)
        print(f"first run: created empty peers file {a.peers}")
    if created or not _has_peers(a.peers):
        print(f"\nserver public key: {pub_to_b64(public_bytes(key))}\n"
              f"\nno clients are authorized yet. on each client run:\n"
              f"    sudo takemeout client <this-server-ip> -s {pub_to_b64(public_bytes(key))}\n"
              f"it will print its own public key; authorize it here with:\n"
              f"    takemeout addpeer <name> <client-public-key>\n"
              f"then restart the server. (open UDP port {a.listen[1]} in your firewall.)\n")
        if not _has_peers(a.peers):
            sys.exit(1)
    try:
        node = Server(key, a.peers, a.listen, a.subnet, a.iface, a.mtu, a.nat)
    except (OSError, ValueError) as e:
        sys.exit(f"takemeout: {e}")
    _run(node, a)


def cmd_client(a):
    from .client import Client
    _need_root()
    key, created = _load_or_create_key(a.key)
    if created:
        print(f"first run: created client key {a.key}\n"
              f"\nclient public key: {pub_to_b64(public_bytes(key))}\n"
              f"\nauthorize it on the server with:\n"
              f"    takemeout addpeer <name> {pub_to_b64(public_bytes(key))}\n"
              f"then restart the server and run this command again.\n")
        sys.exit(0)
    _run(Client(key, a.server, a.server_pub, a.iface, a.full, a.dns), a)


def _has_peers(path):
    with open(path) as f:
        return any(line.split("#", 1)[0].strip() for line in f)


def build_parser():
    ap = argparse.ArgumentParser(prog="takemeout", description="A small encrypted VPN with a terminal dashboard.")
    ap.add_argument("--version", action="version", version=f"takemeout {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="command")

    g = sub.add_parser("genkey", help="generate a key pair")
    g.add_argument("-o", "--output", help="write the private key to this file (mode 600) and print the public key")
    g.set_defaults(fn=cmd_genkey)

    pk = sub.add_parser("pubkey", help="print the public key for a private key file")
    pk.add_argument("keyfile")
    pk.set_defaults(fn=cmd_pubkey)

    ad = sub.add_parser("addpeer", help="authorize a client on the server")
    ad.add_argument("name")
    ad.add_argument("public_key", type=_pubkey)
    ad.add_argument("--ip", type=_ipv4, help="fixed tunnel address (default: next free one)")
    ad.add_argument("--peers", default="peers.txt", help="peers file (default: peers.txt)")
    ad.set_defaults(fn=cmd_addpeer)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--iface", default="tmo0", help="TUN interface name (default: tmo0)")
    common.add_argument("--no-tui", action="store_true", help="plain log output instead of the dashboard")
    common.add_argument("-v", "--verbose", action="store_true", help="debug logging")

    s = sub.add_parser("server", parents=[common], help="run the VPN server")
    s.add_argument("-k", "--key", default="server.key", help="private key file (default: server.key)")
    s.add_argument("-p", "--peers", default="peers.txt", help="authorized peers file (default: peers.txt)")
    s.add_argument("-l", "--listen", type=lambda t: _hostport(t, "0.0.0.0"), default=("0.0.0.0", DEFAULT_PORT),
                   help=f"udp address to listen on (default: 0.0.0.0:{DEFAULT_PORT})")
    s.add_argument("--subnet", default="10.8.0.0/24", help="tunnel subnet (default: 10.8.0.0/24)")
    s.add_argument("--mtu", type=int, default=1400, help="tunnel MTU (default: 1400)")
    s.add_argument("--nat", action="store_true", help="NAT client traffic out to the internet")
    s.set_defaults(fn=cmd_server)

    c = sub.add_parser("client", parents=[common], help="connect to a server")
    c.add_argument("server", type=_hostport, help=f"server host[:port] (default port {DEFAULT_PORT})")
    c.add_argument("-s", "--server-pub", type=_pubkey, required=True, help="server public key")
    c.add_argument("-k", "--key", default="client.key", help="private key file (default: client.key)")
    c.add_argument("--full", action="store_true", help="send all IPv4 traffic through the VPN")
    c.add_argument("--dns", type=_ipv4, action="append", help="use this DNS server while connected (repeatable)")
    c.set_defaults(fn=cmd_client)
    return ap


def main(argv=None):
    a = build_parser().parse_args(argv)
    a.fn(a)
