"""Recon orchestration: run every module against every in-scope subfolder
concurrently, driving a single live display.
"""
import asyncio
import os
import signal
import sys

try:
    import termios
    import tty
except ImportError:
    termios = None   # non-POSIX platform; terminal restore becomes a no-op
    tty = None

from rich.live import Live

from .ui import LiveDisplay
from .plugins.subfinder import SubfinderModule
from .plugins.theharvester import TheHarvesterModule
from .plugins.massdns import MassdnsModule

MODULES = [SubfinderModule, TheHarvesterModule, MassdnsModule]


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


def _install_key_reader(loop, display, on_cancel):
    """Put stdin in cbreak mode and dispatch keys: scroll keys drive the
    display, 'q' requests a graceful stop-early via on_cancel.

    Returns a cleanup callable that unregisters the reader (terminal attrs
    are restored separately by _term_restore). No-op without a POSIX TTY.
    """
    if tty is None or not sys.stdin.isatty():
        return lambda: None
    fd = sys.stdin.fileno()
    tty.setcbreak(fd)   # raw-ish: no echo/line-buffering, but Ctrl+C still signals

    # Byte sequence -> action. Several terminals encode Home/End two ways.
    seqs = [
        (b"q", on_cancel),
        (b"Q", on_cancel),
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
    buf = bytearray()

    def on_input():
        try:
            data = os.read(fd, 1024)
        except (BlockingIOError, InterruptedError):
            return
        if not data:
            return
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

    loop.add_reader(fd, on_input)

    def cleanup():
        try:
            loop.remove_reader(fd)
        except Exception:
            pass

    return cleanup


async def run_recon(proj, scope, enabled_modules=None):
    display = LiveDisplay(",".join(scope))
    # Rich owns the single refresh timer (auto_refresh); the display object
    # is itself the renderable, so there's no second timer to race -> no
    # flicker, and the frame paints immediately instead of only on exit.
    # screen=True runs the UI in the terminal's alternate screen buffer
    # (like htop/vim): a self-contained pane that never touches scrollback
    # and restores the terminal's prior contents on exit.
    live = Live(display, console=display.console, auto_refresh=True,
                refresh_per_second=12, transient=False, screen=True)
    locks = {sub: asyncio.Lock() for sub in scope}   # guards each fqdns-all.txt
    term_attrs = _term_snapshot()

    active_modules = MODULES if enabled_modules is None else \
        [m for m in MODULES if m.name in enabled_modules]

    module_specs = []
    for sub in scope:
        for module_cls in active_modules:
            module = module_cls()
            key = display.add(sub, module.name)
            module_specs.append((module, key, sub))

    try:
        with live:
            tasks = [asyncio.create_task(module.run(key, display, proj, sub, locks[sub]))
                     for module, key, sub in module_specs]

            loop = asyncio.get_running_loop()

            def request_cancel():
                # 'q': graceful stop-early. Cancel running tasks (they wind
                # down their subprocesses) and let the run finish on its own.
                if display.cancelling:
                    return
                display.begin_cancel()
                for (_, key, _), t in zip(module_specs, tasks):
                    if display.tasks[key]["state"] == "pending":
                        display.cancelled(key)
                    t.cancel()

            def force_exit():
                # Ctrl+C: leave the pane immediately. os._exit skips all
                # Python cleanup, so restore the terminal by hand first.
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

            loop.add_signal_handler(signal.SIGINT, force_exit)
            key_cleanup = _install_key_reader(loop, display, request_cancel)
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
                # Work is over (finished or stopped via 'q'). Hold the pane
                # open so the user can scroll the output for review; only
                # Ctrl+C (force_exit) leaves.
                display.finish()
                await asyncio.Event().wait()
            finally:
                key_cleanup()
                loop.remove_signal_handler(signal.SIGINT)
    finally:
        _term_restore(term_attrs)
