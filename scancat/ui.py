"""Live terminal display for recon: a pinned table of per-task spinners with
runtimes at the top, and a rolling combined log of module output below it.

Each task is a (subfolder, module) pair. Output lines are shown as
"[subfolder][module] output".
"""
import time
from collections import deque

from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.text import Text

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class LiveDisplay:
    def __init__(self, scope_label, log_lines=15):
        self.scope_label = scope_label
        self.log_lines = log_lines
        self.console = Console()
        self.tasks = {}          # key -> state dict
        self.order = []          # keys in insertion order
        self.logs = deque(maxlen=500)
        self.cancelling = False
        self.live = Live(self._render(), console=self.console,
                         refresh_per_second=12, transient=False)

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

    def log(self, key, line):
        sub, module = key
        self.logs.append((sub, module, line))

    # rendering -----------------------------------------------------------
    def _runtime(self, t):
        if t["start"] is None:
            return "--:--"
        end = t["end"] if t["end"] is not None else time.monotonic()
        secs = int(end - t["start"])
        return f"{secs // 60:02d}:{secs % 60:02d}"

    def _render(self):
        frame = SPINNER[int(time.time() * 12) % len(SPINNER)]

        table = Table.grid(padding=(0, 1))
        table.add_column()   # status glyph
        table.add_column()   # label
        table.add_column()   # runtime / message
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
                info = Text("missing - not installed", style="yellow")
            elif state == "stub":
                status = Text("·", style="grey50")
                info = Text("stub - not implemented", style="grey50")
            elif state == "cancelled":
                status = Text("✗", style="red")
                info = Text(f"[{self._runtime(t)}] CANCELLED", style="bold red")
            else:  # pending
                status = Text("·", style="grey50")
                info = Text("[--:--]", style="grey50")
            table.add_row(status, Text(t["label"], style="bold"), info)

        log_text = Text()
        for sub, module, line in list(self.logs)[-self.log_lines:]:
            log_text.append(f"[{sub}]", style="cyan")
            log_text.append(f"[{module}] ", style="magenta")
            log_text.append(line + "\n")

        header = Text(f"scancat recon  scope [{self.scope_label}]", style="bold")
        if self.cancelling:
            hint = Text("Stopping early... press Ctrl+C again to force quit",
                       style="bold yellow")
        else:
            hint = Text("Ctrl+C to stop early, Ctrl+C again to force quit",
                       style="grey50")
        rule = Text("─" * 60, style="grey37")
        return Group(header, table, hint, rule, log_text)

    def refresh(self):
        self.live.update(self._render())

    def __enter__(self):
        self.live.__enter__()
        return self

    def __exit__(self, *exc):
        self.refresh()
        self.live.__exit__(*exc)
