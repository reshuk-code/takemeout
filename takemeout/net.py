"""TUN device and host network configuration (ip / iptables), with undo on exit."""

import fcntl
import json
import os
import shutil
import struct
import subprocess

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


class NetError(Exception):
    pass


def open_tun(name: str):
    try:
        fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    except OSError as e:
        raise NetError(f"cannot open /dev/net/tun: {e}") from e
    try:
        res = fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI))
    except OSError as e:
        os.close(fd)
        raise NetError(f"cannot create TUN device {name!r}: {e}") from e
    return fd, res[:16].rstrip(b"\0").decode()


def run(*cmd: str, check: bool = True) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        raise NetError(f"command not found: {cmd[0]}") from None
    if check and p.returncode != 0:
        raise NetError(f"`{' '.join(cmd)}` failed: {p.stderr.strip()}")
    return p.stdout


def route_get(dst: str) -> dict:
    return json.loads(run("ip", "-j", "route", "get", dst))[0]


class HostConfig:
    """Applies changes and remembers how to revert them, in reverse order."""

    def __init__(self, log):
        self.log = log
        self._undo = []

    def apply(self, cmd, undo=None):
        run(*cmd)
        if undo is not None:
            self._undo.append(undo)

    def on_cleanup(self, fn):
        self._undo.append(fn)

    def cleanup(self):
        while self._undo:
            undo = self._undo.pop()
            try:
                if callable(undo):
                    undo()
                else:
                    run(*undo, check=False)
            except Exception as e:  # keep reverting the rest
                self.log.warning("cleanup step failed: %s", e)

    # --- building blocks ----------------------------------------------------------

    def iface_up(self, iface: str, addr_cidr: str, mtu: int):
        run("ip", "addr", "add", addr_cidr, "dev", iface)
        run("ip", "link", "set", "dev", iface, "mtu", str(mtu), "up")

    def enable_nat(self, subnet: str, tun: str):
        if not shutil.which("iptables"):
            raise NetError("--nat needs iptables (apt install iptables)")
        egress = route_get("1.1.1.1").get("dev")
        if not egress:
            raise NetError("could not find the internet-facing interface for NAT")
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            old = f.read().strip()
        if old != "1":
            run("sysctl", "-qw", "net.ipv4.ip_forward=1")
            self.on_cleanup(lambda: run("sysctl", "-qw", f"net.ipv4.ip_forward={old}", check=False))
        rules = [
            ["-t", "nat", "POSTROUTING", "-s", subnet, "-o", egress, "-j", "MASQUERADE"],
            ["FORWARD", "-i", tun, "-j", "ACCEPT"],
            ["FORWARD", "-o", tun, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ]
        for r in rules:
            table, rest = (r[:2], r[2:]) if r[0] == "-t" else ([], r)
            self.apply(["iptables", *table, "-I", *rest], undo=["iptables", *table, "-D", *rest])
        self.log.info("NAT enabled: %s -> %s", subnet, egress)

    def full_tunnel(self, tun: str, server_ip: str):
        r = route_get(server_ip)
        if r.get("dev") == tun:
            raise NetError("route to server already goes through the tunnel")
        pin = ["ip", "route", "replace", f"{server_ip}/32", "dev", r["dev"]]
        if "gateway" in r:
            pin[5:5] = ["via", r["gateway"]]
        self.apply(pin, undo=["ip", "route", "del", f"{server_ip}/32"])
        # Two /1 routes beat the default route without deleting it.
        for net in ("0.0.0.0/1", "128.0.0.0/1"):
            run("ip", "route", "add", net, "dev", tun)
        self.log.info("full tunnel: all IPv4 traffic now goes through %s", tun)

    def set_dns(self, servers):
        path = "/etc/resolv.conf"
        real = os.path.realpath(path)
        with open(real) as f:
            original = f.read()

        def restore():
            with open(real, "w") as f:
                f.write(original)

        with open(real, "w") as f:
            f.write("# written by takemeout; restored on exit\n")
            f.writelines(f"nameserver {s}\n" for s in servers)
        self.on_cleanup(restore)
        self.log.info("DNS set to %s", ", ".join(servers))
