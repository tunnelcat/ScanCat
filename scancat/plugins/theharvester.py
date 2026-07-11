"""theHarvester OSINT recon, run once per domain."""
from .base import ReconModule, Command

SOURCES = ("crtsh,duckduckgo,rapiddns,"
           "subdomaincenter,subdomainfinderc99")


class TheHarvesterModule(ReconModule):
    name = "theharvester"
    binary = "theHarvester"
    modular_outputs = ["fqdns"]

    def build(self, domains_file, module_dir, domains):
        commands = []
        for domain in domains:
            argv = ["theHarvester", "-d", domain, "-b", SOURCES]
            commands.append(Command(argv))
        return commands
