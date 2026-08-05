"""Module orchestration engine for every phase: run a set of modules against
every in-scope subfolder concurrently, driving a single live display and its
keyboard controls. run_modules() is called by all three modes; each phase's
module list lives in its own file (recon.py, scan.py, vuln.py).
"""
import asyncio
import base64
import os
import shutil
import signal
import subprocess
import sys

try:
    import termios
    import tty
except ImportError:
    termios = None   # non-POSIX platform; terminal restore becomes a no-op
    tty = None

from rich.live import Live

from .store import SubfolderStore
from .ui import LiveDisplay


def _term_snapshot():
    """Capture stdin's termios state so it can be restored on exit, even if
    Rich/asyncio cleanup gets skipped (e.g. os._exit on a forced quit)."""
    if termios and sys.stdin.isatty():
        try:
            return termios.tcgetattr(sys.stdin.fileno())
        except Exception:
            return None
    return None


def _term_restore(attrs):
    if attrs is None:
        return
    try:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, attrs)
    except Exception:
        pass


def _osc52_copy(text):
    """Set the terminal clipboard via the OSC 52 escape sequence. Works over
    SSH without any external tool; a terminal that doesn't support it (or has
    it disabled) just ignores the sequence. When running inside tmux the
    sequence is wrapped in tmux's passthrough so it reaches the outer
    terminal (needs `set-clipboard on` / `allow-passthrough on`, the tmux
    3.3+ defaults)."""
    payload = base64.b64encode(text.encode("utf-8", "replace")).decode("ascii")
    seq = f"\x1b]52;c;{payload}\x07"
    if os.environ.get("TMUX"):
        seq = "\x1bPtmux;" + seq.replace("\x1b", "\x1b\x1b") + "\x1b\\"
    sys.stdout.write(seq)
    sys.stdout.flush()


# Native clipboard tools tried in order; clip.exe covers WSL, the rest cover
# Wayland/X11/macOS. First one present wins.
_CLIP_TOOLS = (
    ["clip.exe"],
    ["wl-copy"],
    ["xclip", "-selection", "clipboard"],
    ["xsel", "-ib"],
    ["pbcopy"],
)


def _copy_to_clipboard(text):
    """Copy via the first available native clipboard tool; fall back to the
    OSC 52 terminal escape when none is present (e.g. an SSH session)."""
    data = text.encode("utf-8", "replace")
    for tool in _CLIP_TOOLS:
        if shutil.which(tool[0]):
            try:
                subprocess.run(tool, input=data, check=False)
                return
            except Exception:
                continue
    _osc52_copy(text)


def _install_key_reader(loop, display, handlers):
    """Put stdin in cbreak mode and dispatch keys via `handlers` (a dict with
    'stop', 'copy', 'escape', 'yes', 'no' callbacks); scroll keys drive the
    display directly. A bare Esc calls handlers['escape'].

    Returns a cleanup callable that unregisters the reader (terminal attrs
    are restored separately by _term_restore). No-op without a POSIX TTY.
    """
    if tty is None or not sys.stdin.isatty():
        return lambda: None
    fd = sys.stdin.fileno()
    tty.setcbreak(fd)   # raw-ish: no echo/line-buffering, but Ctrl+C still signals

    # Byte sequence -> action. Several terminals encode Home/End two ways.
    # Esc (\x1b) is NOT here: it prefixes every arrow/page sequence, so it's
    # disambiguated by a short timeout below.
    seqs = [
        (b"q", handlers["stop"]),
        (b"Q", handlers["stop"]),
        (b"y", handlers["yes"]),
        (b"Y", handlers["yes"]),
        (b"n", handlers["no"]),
        (b"N", handlers["no"]),
        (b"m", handlers["control"]),
        (b"r", handlers["restart"]),
        (b"c", handlers["cancel_modules"]),
        (b"p", handlers["pause"]),
        (b"i", handlers["invert"]),
        # j/k mirror the down/up arrows: scroll output, extend a copy
        # selection, or move the module cursor depending on the active mode.
        (b"j", display.scroll_down),
        (b"k", display.scroll_up),
        (b" ", handlers["copy"]),
        (b"\t", display.toggle_output_only),
        (b"\x1b[5~", display.page_up),
        (b"\x1b[6~", display.page_down),
        (b"\x1b[A", display.scroll_up),
        (b"\x1b[B", display.scroll_down),
        (b"\x1b[H", display.scroll_home),
        (b"\x1b[1~", display.scroll_home),
        (b"\x1b[7~", display.scroll_home),
        (b"\x1b[F", display.scroll_end),
        (b"\x1b[4~", display.scroll_end),
        (b"\x1b[8~", display.scroll_end),
    ]
    on_escape = handlers["escape"]
    buf = bytearray()
    esc_timer = None

    def flush_escape():
        # Fired ~60ms after a lone Esc with no follow-up bytes: it was the
        # Esc key, not the start of an arrow/page sequence.
        nonlocal esc_timer
        esc_timer = None
        if bytes(buf) == b"\x1b":
            del buf[:]
            on_escape()

    def on_input():
        nonlocal esc_timer
        try:
            data = os.read(fd, 1024)
        except (BlockingIOError, InterruptedError):
            return
        if not data:
            return
        if esc_timer is not None:      # new bytes may complete the sequence
            esc_timer.cancel()
            esc_timer = None
        buf.extend(data)
        while buf:
            for seq, action in seqs:
                if buf.startswith(seq):
                    action()
                    del buf[:len(seq)]
                    break
            else:
                # Keep a trailing partial escape (more bytes may arrive);
                # otherwise drop one unrecognized byte and re-scan.
                if any(s.startswith(bytes(buf)) for s, _ in seqs):
                    break
                del buf[:1]
        # A lone Esc is ambiguous with a sequence start: wait briefly, then
        # treat it as the Esc key if nothing else arrives.
        if bytes(buf) == b"\x1b":
            esc_timer = loop.call_later(0.06, flush_escape)

    loop.add_reader(fd, on_input)

    def cleanup():
        if esc_timer is not None:
            esc_timer.cancel()
        try:
            loop.remove_reader(fd)
        except Exception:
            pass

    return cleanup


async def run_modules(proj, scope, modules, enabled_modules=None):
    # Modules in a run share a phase (recon/scan/vuln); label the TUI with it.
    phase = modules[0].module_class if modules else "recon"
    display = LiveDisplay(",".join(scope), phase=phase)
    # Rich owns the single refresh timer (auto_refresh); the display object
    # is itself the renderable, so there's no second timer to race -> no
    # flicker, and the frame paints immediately instead of only on exit.
    # screen=True runs the UI in the terminal's alternate screen buffer
    # (like htop/vim): a self-contained pane that never touches scrollback
    # and restores the terminal's prior contents on exit.
    live = Live(display, console=display.console, auto_refresh=True,
                refresh_per_second=12, transient=False, screen=True)
    locks = {sub: asyncio.Lock() for sub in scope}   # serializes each scancat.db
    term_attrs = _term_snapshot()

    # Make sure each subfolder's datastore exists before modules read/write it.
    for sub in scope:
        SubfolderStore(proj.subfolder_path(sub) / "scancat.db").init()

    active_modules = modules if enabled_modules is None else \
        [m for m in modules if m.name in enabled_modules]

    # key -> (module class, subfolder); lets us (re)spawn any module on demand.
    module_by_key = {}
    for sub in scope:
        for module_cls in active_modules:
            key = display.add(sub, module_cls.name)
            module_by_key[key] = (module_cls, sub)

    tasks = {}   # key -> current asyncio task

    def start_module(key):
        module_cls, sub = module_by_key[key]
        tasks[key] = asyncio.create_task(
            module_cls().run(key, display, proj, sub, locks[sub]))

    def _deps_ready(key):
        # A deferred module is ready once every module of its awaited class(es)
        # in the SAME subfolder has settled (its task is done, whether it
        # completed, was cancelled, or was missing).
        module_cls, sub = module_by_key[key]
        need = set(module_cls.depends_on)
        if not need:
            return True
        for okey, (ocls, osub) in module_by_key.items():
            if osub == sub and need.intersection(ocls.out_datatypes):
                t = tasks.get(okey)
                if t is None or not t.done():
                    return False
        return True

    def _settled(key):
        # Terminal for the 'finished' review state: a reached end-state, or a
        # started task that is done (covers a crash that left no end-state).
        if display.tasks[key]["state"] in ("done", "cancelled", "missing",
                                           "stub", "failed", "skipped"):
            return True
        t = tasks.get(key)
        return t is not None and t.done()

    try:
        with live:
            loop = asyncio.get_running_loop()
            for key, (module_cls, sub) in module_by_key.items():
                if module_cls.depends_on:
                    display.waiting(key)     # queued behind its dependencies
                else:
                    start_module(key)

            def request_cancel():
                # 'q': graceful stop-early. Cancel running tasks (they wind
                # down their subprocesses) and let the run finish on its own.
                if display.cancelling:
                    return
                display.begin_cancel()
                for key in module_by_key:
                    t = tasks.get(key)
                    if t is None:
                        display.cancelled(key)   # queued module, never started
                    else:
                        if display.tasks[key]["state"] == "pending":
                            display.cancelled(key)
                        t.cancel()

            def cancel_modules(keys):
                # Module control 'c': cancel just these modules.
                for key in keys:
                    t = tasks.get(key)
                    if t and not t.done():
                        t.cancel()
                    elif t is None and display.tasks[key]["state"] == "waiting":
                        display.cancelled(key)   # cancel a still-queued module

            def pause_modules(keys):
                # Module control 'p': toggle pause (SIGSTOP) / resume (SIGCONT)
                # on each module's process group. No-op if it isn't running.
                for key in keys:
                    proc = display.procs.get(key)
                    if proc is None:
                        continue
                    pause = key not in display.paused
                    try:
                        pgid = os.getpgid(proc.pid)
                        os.killpg(pgid, signal.SIGSTOP if pause else signal.SIGCONT)
                    except (ProcessLookupError, OSError):
                        display.resume_task(key)   # clear stale paused state
                        continue
                    (display.pause_task if pause else display.resume_task)(key)

            async def _restart_keys(keys):
                # Cancel the selected modules, wait for them to actually stop,
                # then spawn fresh tasks for each.
                waiting = [tasks[k] for k in keys
                          if tasks.get(k) and not tasks[k].done()]
                for t in waiting:
                    t.cancel()
                if waiting:
                    await asyncio.gather(*waiting, return_exceptions=True)
                display.cancelling = False
                for key in keys:
                    display.reset(key)
                    start_module(key)

            def restart_modules(keys):
                # Module control 'r': re-run these modules from scratch.
                asyncio.create_task(_restart_keys(keys))

            def force_exit():
                # Ctrl+C confirmed: leave immediately. The module tools run in
                # their own process groups (they survive the terminal's
                # Ctrl+C), so kill them here to avoid orphans before we go.
                for proc in list(display.procs.values()):
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except (ProcessLookupError, PermissionError, OSError):
                        pass
                # os._exit skips all Python cleanup, so restore the terminal.
                try:
                    live.stop()   # tears down the alt-screen, back to normal
                except Exception:
                    pass
                _term_restore(term_attrs)
                sys.stdout.write("\x1b[?25h")   # show cursor, in case Live didn't
                # Print the final module states + tally into normal scrollback.
                try:
                    display.console.print(display.summary())
                except Exception:
                    pass
                sys.stdout.flush()
                os._exit(130)

            def do_copy():
                # Space: toggle a module in control mode; otherwise drive the
                # copy-selection (enter, then copy on the second press).
                if display.confirm:
                    return
                if display.control:
                    display.toggle_selected()
                elif display.selecting:
                    _copy_to_clipboard(display.take_selection())
                else:
                    display.begin_selection()

            # Confirmation dialogs: the triggering key asks first; y confirms
            # (Ctrl+C again for exit), Esc/n cancels. A second Ctrl+C while the
            # exit prompt is up forces the exit (escape hatch if UI is wedged).
            def ask_stop():
                if (display.confirm is None and not display.control
                        and not display.selecting and not display.finished):
                    display.confirm = "stop"

            def ask_quit():
                if display.confirm == "quit":
                    force_exit()
                else:
                    display.confirm = "quit"

            def ask_restart():
                if display.control and display.confirm is None \
                        and display.control_targets():
                    display.confirm = "restart"

            def ask_cancel_modules():
                if display.control and display.confirm is None \
                        and display.control_targets():
                    display.confirm = "cancel"

            def confirm_yes():
                # 'y' confirms stop / restart / cancel prompts; the exit prompt
                # is confirmed by a second Ctrl+C (handled in ask_quit).
                mode = display.confirm
                if mode == "stop":
                    display.confirm = None
                    request_cancel()
                elif mode in ("restart", "cancel"):
                    targets = display.control_targets()
                    display.confirm = None
                    display.exit_control()
                    (restart_modules if mode == "restart"
                     else cancel_modules)(targets)

            def confirm_no():
                display.confirm = None

            def on_escape():
                # Esc backs out of the innermost thing: confirm, then control
                # mode, then a copy selection.
                if display.confirm:
                    display.confirm = None
                elif display.control:
                    display.exit_control()
                elif display.selecting:
                    display.cancel_selection()

            def toggle_control():
                if display.control:
                    display.exit_control()
                else:
                    display.enter_control()

            def do_pause():
                # 'p': pause/resume the targeted modules (immediate, no prompt).
                if display.control and display.confirm is None:
                    pause_modules(display.control_targets())

            handlers = {
                "stop": ask_stop,
                "copy": do_copy,
                "escape": on_escape,
                "yes": confirm_yes,
                "no": confirm_no,
                "control": toggle_control,
                "restart": ask_restart,
                "cancel_modules": ask_cancel_modules,
                "pause": do_pause,
                "invert": display.invert_selection,
            }
            loop.add_signal_handler(signal.SIGINT, ask_quit)
            key_cleanup = _install_key_reader(loop, display, handlers)
            try:
                # Supervisor: start deferred modules once their dependencies
                # settle, keep the pane alive until Ctrl+C, and derive the
                # 'finished' review state so restart/cancel flip it live.
                while True:
                    await asyncio.sleep(0.15)
                    if not display.cancelling:
                        for key in module_by_key:
                            if (key not in tasks
                                    and display.tasks[key]["state"] == "waiting"
                                    and _deps_ready(key)):
                                start_module(key)
                    for t in list(tasks.values()):
                        if t.done():
                            try:
                                t.exception()   # retrieve, avoid warnings
                            except (asyncio.CancelledError, Exception):
                                pass
                    display.finished = all(_settled(k) for k in module_by_key)
            finally:
                key_cleanup()
                loop.remove_signal_handler(signal.SIGINT)
    finally:
        _term_restore(term_attrs)
