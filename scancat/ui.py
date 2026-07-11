"""Live terminal display for recon: a tmux-like two-pane layout with
module statuses pinned on the left and a rolling combined output log on
the right, filling the rest of the terminal down to the bottom.

Each task is a (subfolder, module) pair. Output lines are shown as
"[subfolder][module] output".

Rendering model: this object is itself the Live renderable (via __rich__),
and Rich's own refresh thread is the single source of redraws. We never
hand-drive refreshes during the run, so there's no second timer to race
(which is what caused flicker), and every frame is a fixed height so the
terminal never scroll-jumps.
"""
import time
from collections import deque

from rich import box
from rich.console import Console, Group
from rich.table import Table
from rich.text import Text

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class LiveDisplay:
    def __init__(self, scope_label):
        self.scope_label = scope_label
        self.console = Console()
        self.tasks = {}          # key -> state dict
        self.order = []          # keys in insertion order
        self.logs = deque(maxlen=1000)
        self.cancelling = False
        self.finished = False    # work is over; pane held open for review
        self.scroll = 0          # output lines scrolled back from the tail
        self.view_height = 20    # visible output rows; set each render

    # task lifecycle ------------------------------------------------------
    def add(self, sub, module):
        key = (sub, module)
        self.tasks[key] = {"state": "pending", "start": None, "end": None,
                           "label": f"[{sub}][{module}]"}
        self.order.append(key)
        return key

    def start(self, key):
        self.tasks[key]["state"] = "running"
        self.tasks[key]["start"] = time.monotonic()

    def done(self, key):
        self.tasks[key]["state"] = "done"
        self.tasks[key]["end"] = time.monotonic()

    def missing(self, key):
        self.tasks[key]["state"] = "missing"

    def stub(self, key):
        self.tasks[key]["state"] = "stub"

    def cancelled(self, key):
        self.tasks[key]["state"] = "cancelled"
        self.tasks[key]["end"] = time.monotonic()

    def begin_cancel(self):
        self.cancelling = True

    def finish(self):
        self.finished = True

    def log(self, key, line):
        sub, module = key
        self.logs.append((sub, module, line))
        # If the user has scrolled back, keep the viewport pinned to the same
        # lines instead of letting new output shove it around (like less/htop).
        if self.scroll > 0:
            self.scroll += 1

    # scrolling -----------------------------------------------------------
    def scroll_up(self, n=1):
        self.scroll += n

    def scroll_down(self, n=1):
        self.scroll = max(0, self.scroll - n)

    def page_up(self):
        self.scroll_up(max(1, self.view_height - 1))

    def page_down(self):
        self.scroll_down(max(1, self.view_height - 1))

    def scroll_home(self):
        self.scroll = len(self.logs)   # clamped to oldest line in _output_pane

    def scroll_end(self):
        self.scroll = 0                # back to the live tail

    # rendering -----------------------------------------------------------
    def _runtime(self, t):
        if t["start"] is None:
            return "--:--"
        end = t["end"] if t["end"] is not None else time.monotonic()
        secs = int(end - t["start"])
        return f"{secs // 60:02d}:{secs % 60:02d}"

    def _statuses_pane(self):
        frame = SPINNER[int(time.time() * 12) % len(SPINNER)]
        rows = []
        for key in self.order:
            t = self.tasks[key]
            state = t["state"]
            if state == "running":
                status = Text(frame, style="cyan")
                info = Text(f"[{self._runtime(t)}]", style="cyan")
            elif state == "done":
                status = Text("✓", style="green")
                info = Text(f"[{self._runtime(t)}] DONE!", style="bold green")
            elif state == "missing":
                status = Text("[!]", style="yellow")
                info = Text("missing", style="yellow")
            elif state == "stub":
                status = Text("·", style="grey50")
                info = Text("stub", style="grey50")
            elif state == "cancelled":
                status = Text("✗", style="red")
                info = Text(f"[{self._runtime(t)}] CANCELLED", style="bold red")
            else:  # pending
                status = Text("·", style="grey50")
                info = Text("[--:--]", style="grey50")
            line = Text()
            line.append_text(status)
            line.append(" ")
            line.append(t["label"], style="bold")
            line.append(" ")
            line.append_text(info)
            rows.append(line)
        return Text("\n").join(rows) if rows else Text()

    def _output_pane(self, height):
        """A `height`-tall window into the log. Normally shows the tail
        (bottom-anchored, top-padded with blanks); when scrolled back it
        shows an older slice. self.scroll is clamped to the valid range."""
        total = len(self.logs)
        self.scroll = max(0, min(self.scroll, max(0, total - height)))
        end = total - self.scroll
        start = max(0, end - height)
        recent = list(self.logs)[start:end]
        rows = [Text() for _ in range(height - len(recent))]
        for sub, module, line in recent:
            t = Text()
            t.append(f"[{sub}]", style="cyan")
            t.append(f"[{module}] ", style="magenta")
            t.append(line)
            rows.append(t)
        return Text("\n").join(rows)

    def _hint(self):
        # Mid-cancel (tasks still winding down): a prominent single message.
        if self.cancelling and not self.finished:
            return Text("Stopping early... press Ctrl+C to exit now",
                       style="bold yellow")

        hint = Text(no_wrap=True, overflow="ellipsis")
        hint.append("↑/↓", style="bold")
        hint.append(" line  ", style="grey50")
        hint.append("PgUp/PgDn", style="bold")
        hint.append(" page  ", style="grey50")
        hint.append("Ctrl+C", style="bold")
        hint.append(" exit", style="grey50")
        if not self.finished:
            hint.append("  ", style="grey50")
            hint.append("q", style="bold")
            hint.append(" stop early", style="grey50")
        elif self.cancelling:
            hint.append("   ■ stopped early - reviewing output",
                       style="bold red")
        else:
            hint.append("   ✓ all modules finished - reviewing output",
                       style="bold green")
        if self.scroll > 0:
            hint.append(f"   ▲ SCROLLBACK +{self.scroll} (PgDn/End to resume)",
                       style="bold yellow")
        return hint

    def _render(self):
        header = Text(f"scancat recon  scope [{self.scope_label}]", style="bold")
        hint = self._hint()

        # header(1) + table header(1) + table rule(1) + hint(1) + 1 safety
        # line so the frame never fills the last row and scrolls the terminal.
        fixed_lines = 5
        height = max(len(self.order), self.console.size.height - fixed_lines)
        self.view_height = height

        panes = Table(show_header=True, header_style="bold", box=box.MINIMAL,
                     expand=True, padding=0, show_edge=False)
        # no_wrap keeps every entry to a single row so the output stays
        # bottom-anchored and the frame height stays constant; long lines
        # are truncated with an ellipsis rather than wrapping.
        panes.add_column("MODULES", ratio=1, vertical="top",
                        no_wrap=True, overflow="ellipsis")
        panes.add_column("OUTPUT", ratio=3, vertical="top",
                        no_wrap=True, overflow="ellipsis")
        panes.add_row(self._statuses_pane(), self._output_pane(height))

        return Group(header, panes, hint)

    def __rich__(self):
        return self._render()

    # post-run summary ----------------------------------------------------
    # Printed to the normal terminal after the pane closes, so the final
    # module states and a tally persist in the user's scrollback.
    _SUMMARY = {
        "done":      ("✓", "done",        "green"),
        "cancelled": ("✗", "stopped",     "red"),
        "running":   ("…", "interrupted", "yellow"),
        "missing":   ("[!]", "missing",   "yellow"),
        "stub":      ("·", "stub",        "grey50"),
        "pending":   ("·", "not run",     "grey50"),
    }

    def summary(self):
        counts = {}
        rows = []
        for key in self.order:
            t = self.tasks[key]
            glyph, label, style = self._SUMMARY.get(
                t["state"], ("?", t["state"], "white"))
            counts[label] = counts.get(label, 0) + 1
            line = Text()
            line.append(f"  {glyph} ", style=style)
            line.append(t["label"], style="bold")
            line.append(f"  {label}", style=style)
            if t["start"] is not None:
                line.append(f"  ({self._runtime(t)})", style="grey50")
            rows.append(line)

        header = Text(f"recon summary  scope [{self.scope_label}]", style="bold")
        tally = Text("  ".join(f"{n} {label}" for label, n in counts.items()),
                    style="grey50")
        return Group(header, *rows, tally)
