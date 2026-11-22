"""Single-threaded event loop shared by client and server."""

import selectors
import signal

from .tui import Dashboard


class Quit(Exception):
    pass


def run(node, logbuf=None):
    """`node` provides setup(), close(), sock, tun_fd, on_udp(), on_tun(), on_timer(), snapshot()."""

    def _signal(*_):
        raise Quit

    old = {s: signal.signal(s, _signal) for s in (signal.SIGINT, signal.SIGTERM)}
    dash = Dashboard(node.snapshot, logbuf) if logbuf else None
    sel = selectors.DefaultSelector()
    try:
        node.setup()
        sel.register(node.sock, selectors.EVENT_READ, node.on_udp)
        sel.register(node.tun_fd, selectors.EVENT_READ, node.on_tun)
        if dash:
            dash.start()
        while True:
            for key, _ in sel.select(timeout=0.25):
                key.data()
            node.on_timer()
            if dash and dash.tick():
                break
    except Quit:
        pass
    finally:
        if dash:
            dash.stop()
        sel.close()
        node.close()
        for s, h in old.items():
            signal.signal(s, h)
