"""massdns resolution - stub for now."""
from .base import ReconModule


class MassdnsModule(ReconModule):
    name = "massdns"
    binary = None  # not wired up yet

    async def run(self, key, display, proj, sub):
        display.stub(key)
        display.log(key, "massdns module is a stub (not implemented yet)")
