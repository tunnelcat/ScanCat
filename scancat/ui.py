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

from .notify import NOTIFY_COLORS as NOTIFY   # token -> colour (shared source)

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class LiveDisplay:
    def __init__(self, scope_label, phase="recon"):
        self.scope_label = scope_label
        self.phase = phase       # "recon" | "scan" | "vuln"; shown in the header
        self.console = Console()
        self.tasks = {}          # key -> state dict
        self.order = []          # keys in insertion order
        self.procs = {}          # key -> live subprocess (kill/pause target)
        self.paused = set()      # keys whose process is stopped (SIGSTOP)
        self.logs = deque(maxlen=1000)
        self.cancelling = False
        self.finished = False    # work is over; pane held open for review
        # pending confirmation: None | "stop" | "quit" | "restart" | "cancel"
        self.confirm = None
        self.control = False     # module control mode (navigate/select modules)
        self.cursor = 0          # highlighted module index in control mode
        self.selected = set()    # keys checkbox-selected in control mode
        self.output_only = False # hide statuses so output fills the width
        self.copied_at = 0.0     # monotonic time of last clipboard copy
        self.copied_count = 0    # lines in that copy (for the confirmation)
        self.selecting = False   # in visual copy-selection mode
        self.sel_top = 0         # selection bounds (absolute log indices)
        self.sel_bot = 0
        self.scroll = 0          # output lines scrolled back from the tail
        self.view_height = 20    # visible output rows; set each render

    # task lifecycle ------------------------------------------------------
    def add(self, sub, module):
        key = (sub, module)
        self.tasks[key] = {"state": "pending", "start": None, "end": None,
                           "label": f"[{sub}][{module}]",
                           "paused_at": None, "paused_accum": 0.0}
        self.order.append(key)
        return key

    def waiting(self, key):
        """Queued behind a dependency; not yet started."""
        self.tasks[key]["state"] = "waiting"

    def start(self, key):
        self.tasks[key]["state"] = "running"
        self.tasks[key]["start"] = time.monotonic()

    def done(self, key):
        self._finalize_pause(key)
        self.tasks[key]["state"] = "done"
        self.tasks[key]["end"] = time.monotonic()
        self.paused.discard(key)

    def missing(self, key):
        self.tasks[key]["state"] = "missing"
        self.paused.discard(key)

    def stub(self, key):
        self.tasks[key]["state"] = "stub"

    def cancelled(self, key):
        self._finalize_pause(key)
        self.tasks[key]["state"] = "cancelled"
        self.tasks[key]["end"] = time.monotonic()
        self.paused.discard(key)

    def begin_cancel(self):
        self.cancelling = True

    # pause bookkeeping: freeze a module's runtime clock while it's stopped,
    # so the displayed mm:ss counts active time only, not time spent paused.
    def _finalize_pause(self, key):
        t = self.tasks[key]
        if t["paused_at"] is not None:
            t["paused_accum"] += time.monotonic() - t["paused_at"]
            t["paused_at"] = None

    def pause_task(self, key):
        self.paused.add(key)
        if self.tasks[key]["paused_at"] is None:
            self.tasks[key]["paused_at"] = time.monotonic()

    def resume_task(self, key):
        self._finalize_pause(key)
        self.paused.discard(key)

    def reset(self, key):
        """Return a module to the pending state so it can be re-run."""
        self.tasks[key].update(state="pending", start=None, end=None,
                              paused_at=None, paused_accum=0.0)
        self.paused.discard(key)

    # module control mode -------------------------------------------------
    def enter_control(self):
        if (self.order and not self.selecting and not self.output_only
                and self.confirm is None):
            self.control = True
            self.cursor = min(self.cursor, len(self.order) - 1)
            self.selected = set()

    def exit_control(self):
        self.control = False
        self.selected = set()

    def cursor_up(self, n=1):
        if self.control:
            self.cursor = max(0, self.cursor - n)

    def cursor_down(self, n=1):
        if self.control:
            self.cursor = min(len(self.order) - 1, self.cursor + n)

    def toggle_selected(self):
        if self.control and self.order:
            self.selected.symmetric_difference_update({self.order[self.cursor]})

    def invert_selection(self):
        if self.control:
            self.selected = set(self.order) - self.selected

    def control_targets(self):
        """Keys the control-mode action applies to: the checkbox selection,
        or the highlighted module when nothing is checked."""
        if self.selected:
            return set(self.selected)
        if self.control and self.order:
            return {self.order[self.cursor]}
        return set()

    def log(self, key, line):
        sub, module = key
        self.logs.append((sub, module, line))
        # If the user has scrolled back, keep the viewport pinned to the same
        # lines instead of letting new output shove it around (like less/htop).
        if self.scroll > 0:
            self.scroll += 1

    # scrolling / selection ----------------------------------------------
    # The nav keys do double duty: normally they scroll the output; in
    # selection mode they extend the highlighted range instead. page_up/
    # page_down delegate here, so they inherit the mode-awareness too.
    def scroll_up(self, n=1):
        if self.control:
            self.cursor_up(n)
        elif self.selecting:
            self._grow_top(n)
        else:
            self.scroll += n

    def scroll_down(self, n=1):
        if self.control:
            self.cursor_down(n)
        elif self.selecting:
            self._grow_bottom(n)
        else:
            self.scroll = max(0, self.scroll - n)

    def page_up(self):
        self.scroll_up(max(1, self.view_height - 1))

    def page_down(self):
        self.scroll_down(max(1, self.view_height - 1))

    def scroll_home(self):
        if self.control:
            self.cursor = 0
        elif self.selecting:
            self._grow_top(len(self.logs))     # extend to the oldest line
        else:
            self.scroll = len(self.logs)       # clamped in _output_pane

    def scroll_end(self):
        if self.control:
            self.cursor = max(0, len(self.order) - 1)
        elif self.selecting:
            self._grow_bottom(len(self.logs))  # extend to the newest line
        else:
            self.scroll = 0                    # back to the live tail

    def _grow_top(self, n):
        self.sel_top = max(0, self.sel_top - n)
        self._scroll_to_show(self.sel_top, at_bottom=False)

    def _grow_bottom(self, n):
        self.sel_bot = min(len(self.logs) - 1, self.sel_bot + n)
        self._scroll_to_show(self.sel_bot, at_bottom=True)

    def _scroll_to_show(self, idx, at_bottom):
        """Scroll so absolute log index `idx` sits at the bottom (or top) of
        the visible window, keeping the moving selection edge on screen."""
        n, h = len(self.logs), self.view_height
        target = (n - 1 - idx) if at_bottom else (n - h - idx)
        self.scroll = max(0, min(target, max(0, n - h)))

    def begin_selection(self):
        """Enter copy-selection mode with the current visible window selected."""
        n = len(self.logs)
        if n == 0:
            self.copied_at = time.monotonic()   # flash "nothing to copy"
            self.copied_count = 0
            return
        h = self.view_height
        self.scroll = max(0, min(self.scroll, max(0, n - h)))
        end = n - self.scroll
        self.sel_top = max(0, end - h)
        self.sel_bot = end - 1
        self.selecting = True

    def take_selection(self):
        """Exit selection mode and return the selected lines as text."""
        items = list(self.logs)
        chosen = items[self.sel_top:self.sel_bot + 1]
        self.selecting = False
        self.copied_at = time.monotonic()
        self.copied_count = len(chosen)
        return "\n".join(f"[{sub}][{module}] {line}"
                        for sub, module, line in chosen)

    def cancel_selection(self):
        """Leave selection mode without copying (Esc)."""
        self.selecting = False

    def toggle_output_only(self):
        # Collapse the statuses pane so output spans the full width; then a
        # normal terminal drag-select grabs only output text, not the left
        # pane. Toggle back to restore the split view. Disabled in control
        # mode, which needs the statuses pane visible.
        if not self.control:
            self.output_only = not self.output_only

    # rendering -----------------------------------------------------------
    def _runtime(self, t):
        if t["start"] is None:
            return "--:--"
        end = t["end"] if t["end"] is not None else time.monotonic()
        paused = t["paused_accum"]
        if t["paused_at"] is not None:      # currently paused: freeze the clock
            paused += end - t["paused_at"]
        secs = max(0, int(end - t["start"] - paused))
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        if h:                               # only widen to H:MM:SS past an hour
            return f"{h}:{m:02d}:{s:02d}"
        return f"{m:02d}:{s:02d}"

    def _statuses_pane(self):
        frame = SPINNER[int(time.time() * 12) % len(SPINNER)]
        rows = []
        for i, key in enumerate(self.order):
            t = self.tasks[key]
            state = t["state"]
            if state == "running" and key in self.paused:
                status = Text("‖", style="bold yellow")
                info = Text(f"[{self._runtime(t)}] PAUSED", style="bold yellow")
            elif state == "running":
                status = Text(frame, style="cyan")
                info = Text(f"[{self._runtime(t)}]", style="cyan")
            elif state == "done":
                status = Text("✓", style="green")
                info = Text(f"[{self._runtime(t)}] DONE!", style="bold green")
            elif state == "missing":
                status = Text("[!]", style="yellow")
                info = Text("missing", style="yellow")
            elif state == "waiting":
                status = Text("·", style="grey50")
                info = Text("waiting", style="blue")
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
            if self.control:
                # cursor marker + checkbox for navigation/selection
                line.append("❯ " if i == self.cursor else "  ",
                           style="bold cyan")
                checked = key in self.selected
                line.append("[x] " if checked else "[ ] ",
                           style="bold cyan" if checked else "grey50")
            line.append_text(status)
            line.append(" ")
            line.append(t["label"], style="bold")
            line.append(" ")
            line.append_text(info)
            if self.control and i == self.cursor:
                line.stylize("on grey30")   # highlight the current row
            rows.append(line)
        return Text("\n").join(rows) if rows else Text()

    def _output_pane(self, height):
        """A `height`-tall window into the log. Shows the tail
        (top-anchored: lines fill from the top down, bottom-padded with
        blanks); when scrolled back it shows an older slice. self.scroll is
        clamped to the valid range."""
        total = len(self.logs)
        self.scroll = max(0, min(self.scroll, max(0, total - height)))
        end = total - self.scroll
        start = max(0, end - height)
        recent = list(self.logs)[start:end]
        rows = []
        for offset, (sub, module, line) in enumerate(recent):
            idx = start + offset
            if self.selecting and self.sel_top <= idx <= self.sel_bot:
                # Selected lines render as a solid highlight bar (reverse
                # video) so the range is unmistakable across themes.
                rows.append(Text(f"[{sub}][{module}] {line}", style="reverse"))
            else:
                t = Text()
                t.append(f"[{sub}]", style="cyan")
                t.append(f"[{module}] ", style="magenta")
                color = NOTIFY.get(line[:3])
                if color:
                    t.append(line[:3], style=f"bold {color}")
                    t.append(line[3:])
                else:
                    t.append(line)
                rows.append(t)
        rows += [Text() for _ in range(height - len(recent))]   # pad below
        return Text("\n").join(rows)

    def _hint(self):
        # A confirmation prompt takes over the hint line until resolved.
        if self.confirm == "quit":
            return Text("Exit scancat?   Ctrl+C again = exit    Esc/n = cancel",
                       style="bold red")
        if self.confirm == "stop":
            return Text("Stop all modules early?   y = stop    Esc/n = cancel",
                       style="bold yellow")
        if self.confirm == "restart":
            n = len(self.control_targets())
            return Text(f"Restart {n} module(s)?   y = confirm    Esc/n = back",
                       style="bold yellow")
        if self.confirm == "cancel":
            n = len(self.control_targets())
            return Text(f"Cancel {n} module(s)?   y = confirm    Esc/n = back",
                       style="bold red")

        # Module control mode: navigate/select modules and act on them.
        if self.control:
            m = Text(no_wrap=True, overflow="ellipsis")
            m.append("MODULES  ", style="bold reverse")
            m.append("↑/↓ j/k PgUp/PgDn Home/End", style="bold")
            m.append(" move   ", style="grey50")
            m.append("Space", style="bold")
            m.append(" select   ", style="grey50")
            m.append("i", style="bold")
            m.append(" invert   ", style="grey50")
            m.append("r", style="bold")
            m.append(" restart   ", style="grey50")
            m.append("c", style="bold")
            m.append(" cancel   ", style="grey50")
            m.append("p", style="bold")
            m.append(" pause   ", style="grey50")
            m.append("Esc/m", style="bold")
            m.append(" cancel   ", style="grey50")
            m.append(f"({len(self.selected)} selected)", style="cyan")
            return m

        # Selection mode takes priority: show its own control set.
        if self.selecting:
            sel = Text(no_wrap=True, overflow="ellipsis")
            sel.append("SELECT  ", style="bold reverse")
            sel.append("↑/↓ j/k PgUp/PgDn Home/End", style="bold")
            sel.append(" extend   ", style="grey50")
            sel.append("Space", style="bold")
            sel.append(" copy   ", style="grey50")
            sel.append("Esc", style="bold")
            sel.append(" cancel   ", style="grey50")
            sel.append(f"({self.sel_bot - self.sel_top + 1} lines)",
                      style="cyan")
            return sel

        # Mid-cancel (tasks still winding down): a prominent single message.
        if self.cancelling and not self.finished:
            return Text("Stopping early... press Ctrl+C to exit now",
                       style="bold yellow")

        # A copy just happened: flash a confirmation for ~2s (auto-refresh
        # clears it). copied_count == 0 means there was nothing to copy.
        if self.copied_at and time.monotonic() - self.copied_at < 2.0:
            if self.copied_count:
                return Text(f"✓ copied {self.copied_count} lines to clipboard",
                           style="bold green")
            return Text("nothing to copy yet", style="bold yellow")

        hint = Text(no_wrap=True, overflow="ellipsis")
        hint.append("↑/↓ j/k PgUp/PgDn Home/End", style="bold")
        hint.append(" move  ", style="grey50")
        hint.append("Space", style="bold")
        hint.append(" select/copy  ", style="grey50")
        hint.append("Tab", style="bold")
        hint.append(" show statuses  " if self.output_only
                   else " output-only  ", style="grey50")
        if not self.output_only:
            hint.append("m", style="bold")
            hint.append(" modules  ", style="grey50")
        if not self.finished:
            hint.append("q", style="bold")
            hint.append(" stop all  ", style="grey50")
        hint.append("Ctrl+C", style="bold")
        hint.append(" exit", style="grey50")
        if self.finished and self.cancelling:
            hint.append("   ■ stopped early - reviewing output",
                       style="bold red")
        elif self.finished:
            hint.append("   ✓ all modules finished - reviewing output",
                       style="bold green")
        if self.scroll > 0:
            hint.append(f"   ▲ SCROLLBACK +{self.scroll} (PgDn/End to resume)",
                       style="bold yellow")
        return hint

    def _render(self):
        header = Text(f"scancat {self.phase}  scope [{self.scope_label}]", style="bold")
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
        output = self._output_pane(height)
        if self.output_only:
            # Single full-width column: a plain line-select copies only output.
            panes.add_column("OUTPUT", ratio=1, vertical="top",
                            no_wrap=True, overflow="ellipsis")
            panes.add_row(output)
        else:
            panes.add_column("MODULES", ratio=1, vertical="top",
                            no_wrap=True, overflow="ellipsis")
            panes.add_column("OUTPUT", ratio=3, vertical="top",
                            no_wrap=True, overflow="ellipsis")
            panes.add_row(self._statuses_pane(), output)

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
        "waiting":   ("·", "not run",     "grey50"),
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

        header = Text(f"{self.phase} summary  scope [{self.scope_label}]", style="bold")
        tally = Text("  ".join(f"{n} {label}" for label, n in counts.items()),
                    style="grey50")
        return Group(header, *rows, tally)
