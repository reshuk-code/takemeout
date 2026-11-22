# takemeout

A small, readable VPN for Linux with a terminal dashboard. Pure Python, one
dependency (`cryptography`), about 1,200 lines.

```
 takemeout · server
  state       ● listening
  listen      udp 0.0.0.0:51820
  tunnel      tmo0  10.8.0.1/24  mtu 1400
  peers       1 online / 2 allowed

  peer            tunnel ip    endpoint              rx / tx               rx rate     handshake
  ● laptop        10.8.0.2     203.0.113.7:40211     1.1 MiB / 964.5 KiB   955.3 KiB/s 13s ago
  ○ phone         10.8.0.3     -                     0 B / 0 B             0 B/s       never
── log ─────────────────────────────────────────────────────────────────────────────
  20:53:10 INFO  laptop connected from 203.0.113.7:40211 as 10.8.0.2
```

## Install

On Kali / Debian / Ubuntu, system-wide `pip install` is blocked (PEP 668), so use a venv.
`--system-site-packages` lets it reuse the distro's `cryptography` package:

```sh
python3 -m venv --system-site-packages .venv
.venv/bin/pip install --no-build-isolation -e .
sudo ln -sf "$PWD/.venv/bin/takemeout" /usr/local/bin/takemeout   # so `sudo takemeout` works
```

Or skip installing and run it from the project folder: `sudo python3 -m takemeout ...`
(this needs `python3-cryptography`, which Kali ships by default).

## Quick start

**On the server** (a VPS with a public IP):

```sh
takemeout genkey -o server.key        # prints the server public key
sudo takemeout server --nat           # --nat lets clients reach the internet through it
```

Open UDP port 51820 in your firewall / cloud security group.

**On each client:**

```sh
takemeout genkey -o client.key        # prints the client public key
```

**Back on the server**, authorize that key, then restart the server:

```sh
takemeout addpeer laptop <CLIENT_PUBLIC_KEY>
```

**Connect:**

```sh
sudo takemeout client <server-ip> -s <SERVER_PUBLIC_KEY>                        # VPN subnet only
sudo takemeout client <server-ip> -s <SERVER_PUBLIC_KEY> --full --dns 1.1.1.1   # all traffic
```

Press `q` in the dashboard to disconnect. Everything takemeout changed (routes,
NAT rules, `ip_forward`, `resolv.conf`) is reverted on exit. Use `--no-tui` for
plain logs (e.g. under systemd).

## Commands

| command | what it does |
|---|---|
| `genkey [-o FILE]` | new X25519 key pair; with `-o` writes the private key (mode 600) and prints the public key |
| `pubkey FILE` | print the public key of a private key file |
| `addpeer NAME PUBKEY [--ip IP] [--peers FILE]` | append a client to the peers file |
| `server [-k KEY] [-p PEERS] [-l ADDR:PORT] [--subnet CIDR] [--mtu N] [--nat]` | run the server |
| `client HOST[:PORT] -s PUBKEY [-k KEY] [--full] [--dns IP]` | connect |

Both `server` and `client` accept `--iface`, `--no-tui`, `-v`.

The peers file has one `name public_key [tunnel_ip]` per line; addresses are
handed out from the subnet when not given.

## How it works

```
app ─▶ tmo0 (TUN) ─▶ takemeout ─▶ encrypt ─▶ UDP ─▶ takemeout ─▶ decrypt ─▶ tmo0 ─▶ server / NAT ─▶ internet
```

- **Handshake (1 round trip):** the client sends an ephemeral X25519 key, its
  static public key (encrypted) and a timestamp (encrypted under a key that
  needs the client's private key). The server checks the key is in the peers
  file and that the timestamp is newer than the last one, which stops replays.
  Session keys come from HKDF over four DH results (ephemeral–ephemeral,
  ephemeral–static, static–ephemeral, static–static), giving mutual
  authentication and forward secrecy.
- **Data:** ChaCha20-Poly1305 with a 64-bit counter nonce, a 2048-packet
  sliding replay window, and an empty-packet keepalive every 10 s.
- **Rekeying:** the client runs a new handshake every 2 minutes; sessions are
  rejected after 3 minutes.
- **Roaming:** the server follows a client to its new address after any
  authenticated packet.
- **Anti-spoofing:** the server drops packets whose inner source IP isn't that
  peer's tunnel address.

Code map: `protocol.py` (handshake + packets, no I/O), `crypto.py`, `net.py`
(TUN, routes, NAT, undo), `server.py`, `client.py`, `runner.py` (event loop),
`tui.py` (curses dashboard), `cli.py`.

## Tests

```sh
python3 -m unittest discover -s tests   # protocol + in-process client/server
./scripts/e2e-test.sh                    # real TUN tunnel in rootless namespaces, no sudo needed
```

## Limitations

IPv4 only inside the tunnel (with `--full`, IPv6 traffic still bypasses the VPN,
so disable IPv6 if that matters). Linux only. No DoS cookies or rate limiting
on handshakes. This is a learning project, not audited. Use WireGuard for anything
that matters.
