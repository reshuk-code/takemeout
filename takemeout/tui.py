"""Curses dashboard and log plumbing."""

import collections
import curses
import logging
import time

log = logging.getLogger("takemeout")


class BufferHandler(logging.Handler):
    def __init__(self, maxlen=500):
        super().__init__()
        self.lines = collections.deque(maxlen=maxlen)
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)-5s %(message)s", "%H:%M:%S"))

    def emit(self, record):
        self.lines.append((record.levelno, self.format(record)))


def setup_logging(tui: bool, verbose: bool):
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    log.handlers.clear()
    if tui:
        buf = BufferHandler()
        log.addHandler(buf)
        return buf
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)-5s %(message)s", "%H:%M:%S"))
    log.addHandler(h)
    return None


def human_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def ago(t) -> str:
    if t is None:
        return "never"
    s = int(time.monotonic() - t)
    return f"{s}s ago" if s < 120 else f"{s // 60}m ago"


class RateMeter:
    def __init__(self):
        self._last = {}

    def rate(self, key, total):
        now = time.monotonic()
        prev = self._last.get(key)
        self._last[key] = (now, total, prev[2] if prev else 0.0)
        if not prev or now - prev[0] < 0.2:
            return self._last[key][2] if prev else 0.0
        r = (total - prev[1]) / (now - prev[0])
        self._last[key] = (now, total, r)
        return r


class Dashboard:
    """`provider()` returns dict(title, state, status=[(k, v)], header=[...], rows=[[...]])."""

    def __init__(self, provider, logbuf: BufferHandler):
        self.provider = provider
        self.logbuf = logbuf
        self.scr = None
        self._last_draw = 0.0

    def start(self):
        self.scr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        self.scr.keypad(True)
        self.scr.nodelay(True)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            for i, c in enumerate((curses.COLOR_GREEN, curses.COLOR_YELLOW, curses.COLOR_RED, curses.COLOR_CYAN), 1):
                curses.init_pair(i, c, -1)
            curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_CYAN)

    def stop(self):
        if self.scr:
            self.scr.keypad(False)
            curses.nocbreak()
            curses.echo()
            curses.endwin()
            self.scr = None

    def tick(self) -> bool:
        """Handle input and redraw if due. Returns True when the user asked to quit."""
        while True:
            ch = self.scr.getch()
            if ch == -1:
                break
            if ch in (ord("q"), ord("Q")):
                return True
            if ch == curses.KEY_RESIZE:
                self.scr.clear()
                self._last_draw = 0
        if time.monotonic() - self._last_draw >= 0.5:
            self._draw()
            self._last_draw = time.monotonic()
        return False

    def _put(self, y, x, text, attr=0):
        h, w = self.scr.getmaxyx()
        if 0 <= y < h and x < w:
            try:
                self.scr.addnstr(y, x, text, w - x - (1 if y == h - 1 else 0), attr)
            except curses.error:
                pass

    def _draw(self):
        st = self.provider()
        scr = self.scr
        scr.erase()
        h, w = scr.getmaxyx()
        color = curses.has_colors()
        cp = (lambda n: curses.color_pair(n)) if color else (lambda n: 0)

        self._put(0, 0, f" takemeout · {st['title']} ".ljust(w), cp(5) | curses.A_BOLD)
        state = st["state"]
        state_color = {"connected": 1, "listening": 1, "connecting": 2}.get(state, 3)
        self._put(2, 2, "state", curses.A_DIM)
        self._put(2, 14, f"● {state}", cp(state_color) | curses.A_BOLD)
        y = 3
        for k, v in st["status"]:
            self._put(y, 2, k, curses.A_DIM)
            self._put(y, 14, str(v))
            y += 1

        if st.get("header"):
            y += 1
            widths = st.get("widths") or [16] * len(st["header"])
            line = "".join(c.ljust(wd) for c, wd in zip(st["header"], widths))
            self._put(y, 2, line, curses.A_BOLD | curses.A_UNDERLINE)
            y += 1
            if not st["rows"]:
                self._put(y, 2, st.get("empty", "(none)"), curses.A_DIM)
                y += 1
            for row in st["rows"]:
                self._put(y, 2, "".join(str(c)[: wd - 1].ljust(wd) for c, wd in zip(row, widths)))
                y += 1

        y += 1
        self._put(y, 0, "─" * w, curses.A_DIM)
        self._put(y, 2, " log ", curses.A_DIM)
        y += 1
        room = h - 1 - y
        if room > 0:
            lvl_color = {logging.WARNING: 2, logging.ERROR: 3, logging.CRITICAL: 3}
            for lvl, text in list(self.logbuf.lines)[-room:]:
                self._put(y, 2, text, cp(lvl_color.get(lvl, 0)) if lvl in lvl_color else 0)
                y += 1
        self._put(h - 1, 0, " q quit ".ljust(w), curses.A_REVERSE)
        scr.refresh()
