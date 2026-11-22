#!/usr/bin/env bash
# Rootless end-to-end test: runs a real server and client in throwaway network
# namespaces (via unshare), connected by a veth pair, then pings and pushes TCP
# through the tunnel. Needs unprivileged user namespaces (default on most distros).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if [[ "${1:-}" != "--inner" ]]; then
    exec unshare -Urn --kill-child "$0" --inner "$WORK"
fi
WORK=$2; cd "$WORK"
export PYTHONPATH=$ROOT
T="python3 -m takemeout"
ip link set lo up

SPUB=$($T genkey -o server.key 2>/dev/null)
CPUB=$($T genkey -o client.key 2>/dev/null)
$T addpeer laptop "$CPUB" --peers peers.txt >/dev/null

unshare -n sh -c "while [ ! -e go ]; do sleep 0.1; done
  ip link set lo up; ip addr add 192.0.2.2/24 dev vc; ip link set vc up
  exec $T client 192.0.2.1 -s $SPUB -k client.key --no-tui" > client.log 2>&1 &
CPID=$!
sleep 0.5
ip link add name vs type veth peer name vc
ip link set vc netns $CPID
ip addr add 192.0.2.1/24 dev vs; ip link set vs up
$T server --no-tui -k server.key -p peers.txt > server.log 2>&1 &
SPID=$!
sleep 0.5; touch go

for _ in $(seq 1 30); do grep -q "connected:" client.log && break; sleep 0.3; done

fail() { echo "FAIL: $1"; echo "--- server.log"; cat server.log; echo "--- client.log"; cat client.log; exit 1; }
nsenter -t $CPID -n ping -c 3 -W 2 10.8.0.1 >/dev/null || fail "client -> server ping"
echo "ok  client -> server ping"
ping -c 3 -W 2 10.8.0.2 >/dev/null || fail "server -> client ping"
echo "ok  server -> client ping"
python3 - "$CPID" <<'PY' || fail "tcp transfer"
import os, socket, subprocess, sys, threading
srv = socket.create_server(("10.8.0.1", 9000)); got = []
def accept():
    c, _ = srv.accept(); n = 0
    while (b := c.recv(65536)): n += len(b)
    got.append(n)
t = threading.Thread(target=accept); t.start()
subprocess.run(["nsenter", "-t", sys.argv[1], "-n", "python3", "-c",
    "import socket,os; c=socket.create_connection(('10.8.0.1',9000)); c.sendall(os.urandom(5_000_000)); c.close()"], check=True)
t.join(); assert got == [5_000_000], got
PY
echo "ok  5 MB tcp transfer through the tunnel"
kill -INT $CPID $SPID; wait 2>/dev/null || true
echo "PASS"
