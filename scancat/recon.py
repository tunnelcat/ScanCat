"""Recon orchestration: run every module against every in-scope subfolder
concurrently, driving a single live display.
"""
import asyncio

from .ui import LiveDisplay
from .plugins.amass import AmassModule
from .plugins.subfinder import SubfinderModule
from .plugins.theharvester import TheHarvesterModule
from .plugins.massdns import MassdnsModule

MODULES = [AmassModule, SubfinderModule, TheHarvesterModule, MassdnsModule]


async def _refresh_loop(display):
    try:
        while True:
            display.refresh()
            await asyncio.sleep(0.08)
    except asyncio.CancelledError:
        pass


async def run_recon(proj, scope):
    display = LiveDisplay(",".join(scope))
    locks = {sub: asyncio.Lock() for sub in scope}   # guards each fqdns-all.txt

    coros = []
    for sub in scope:
        for module_cls in MODULES:
            module = module_cls()
            key = display.add(sub, module.name)
            coros.append(module.run(key, display, proj, sub, locks[sub]))

    with display:
        refresher = asyncio.create_task(_refresh_loop(display))
        try:
            await asyncio.gather(*coros)
        finally:
            refresher.cancel()
            await asyncio.gather(refresher, return_exceptions=True)
