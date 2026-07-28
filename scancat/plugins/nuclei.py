"""nuclei vuln-scan modules (vuln phase).

Two modes share the nuclei binary, like the nmap modes share theirs: nuclei-web
runs against httpx's discovered URLs, nuclei-net against host/port services.
Stubs for now - each marks itself 'stub' instead of running. To make one real,
give it build()/adapt() and drop the run() override so it uses the BaseModule
pipeline.
"""
from .base import BaseModule


class NucleiBase(BaseModule):
    """Shared base for the nuclei modes. Stub for now: marks itself 'stub' in
    the display instead of launching the tool."""
    binary = "nuclei"
    module_class = "vuln"

    async def run(self, key, display, proj, sub, lock):
        display.stub(key)


class NucleiWebModule(NucleiBase):
    name = "nuclei-web"
    depends_on = ["url"]   # runs on httpx's urlTargets-out


class NucleiNetModule(NucleiBase):
    name = "nuclei-net"
