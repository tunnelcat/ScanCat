"""Phase module pipelines.

The ordered module list for each phase (recon, scan, vuln). Each tool is its own
plugin in scancat.plugins; this file just maps them into phases and sets the run
order. runner.run_modules() executes a given list; main.py picks it per mode.
"""
from .plugins.subfinder import SubfinderModule
from .plugins.theharvester import TheHarvesterModule
from .plugins.dnsx import DnsxModule
from .plugins.nmap import (
    NmapPingModule, NmapFastModule, NmapTcp1000Module, NmapTcpAllModule,
    NmapUdp200Module, NmapUdpSelectModule, NmapCustomModule)
from .plugins.httpx import HttpxModule
from .plugins.nuclei import NucleiWebModule, NucleiNetModule

# Recon: host discovery + DNS resolution (dnsx depends_on host).
RECON_MODULES = [SubfinderModule, TheHarvesterModule, DnsxModule]

# Scan: the nmap modes.
SCAN_MODULES = [
    NmapPingModule,
    NmapFastModule,
    NmapTcp1000Module,
    NmapTcpAllModule,
    NmapUdp200Module,
    NmapUdpSelectModule,
    NmapCustomModule,
]

# Vuln: httpx discovers live web URLs, then the nuclei scans run.
VULN_MODULES = [HttpxModule, NucleiWebModule, NucleiNetModule]
