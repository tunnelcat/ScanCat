"""Recon orchestration: run every module against every in-scope subfolder
concurrently, driving a single live display.
"""
import asyncio
import os
import signal
import sys

try:
    import termios
except ImportError:
    termios = None   # non-POSIX platform; terminal restore becomes a no-op

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


async def _refresh_loop(display):
    try:
        while True:
            display.refresh()
            await asyncio.sleep(0.08)
    except asyncio.CancelledError:
        pass


async def run_recon(proj, scope, enabled_modules=None):
    display = LiveDisplay(",".join(scope))
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
        with display:
            refresher = asyncio.create_task(_refresh_loop(display))
            tasks = [asyncio.create_task(module.run(key, display, proj, sub))
                     for module, key, sub in module_specs]

            loop = asyncio.get_running_loop()
            sigint_count = 0

            def handle_sigint():
                nonlocal sigint_count
                sigint_count += 1
                if sigint_count == 1:
                    display.begin_cancel()
                    for (_, key, _), t in zip(module_specs, tasks):
                        if display.tasks[key]["state"] == "pending":
                            display.cancelled(key)
                        t.cancel()
                else:
                    # os._exit skips all Python cleanup, so restore the
                    # terminal by hand before it fires.
                    try:
                        display.live.stop()
                    except Exception:
                        pass
                    _term_restore(term_attrs)
                    sys.stdout.write("\x1b[?25h")   # show cursor, in case Live didn't
                    sys.stdout.flush()
                    os._exit(130)   # second Ctrl+C: quit immediately

            loop.add_signal_handler(signal.SIGINT, handle_sigint)
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            finally:
                loop.remove_signal_handler(signal.SIGINT)
                refresher.cancel()
                await asyncio.gather(refresher, return_exceptions=True)
    finally:
        _term_restore(term_attrs)
