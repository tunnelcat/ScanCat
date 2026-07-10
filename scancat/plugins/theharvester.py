"""theHarvester OSINT recon, run once per domain."""
from .base import ReconModule, Command

SOURCES = ("crtsh,dnsdumpster,duckduckgo,rapiddns,"
           "subdomaincenter,subdomainfinderc99")


class TheHarvesterModule(ReconModule):
    name = "theharvester"
    binary = "theHarvester"

    def build(self, domains_file, module_dir, domains):
        commands = []
        for domain in domains:
            tee = module_dir / f"theharvester-{domain}.txt"
            argv = ["theHarvester", "-d", domain, "-b", SOURCES]
            commands.append(Command(argv, tee=tee, reads=[tee]))
        return commands
