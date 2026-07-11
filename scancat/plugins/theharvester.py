"""theHarvester OSINT recon, run once per domain."""
from .base import ReconModule, Command

SOURCES = ("all")


class TheHarvesterModule(ReconModule):
    name = "theharvester"
    binary = "theHarvester"

    def build(self, domains_file, module_dir, domains):
        commands = []
        for domain in domains:
            filename = f"theHarvester-{domain.replace('.', '-')}"
            argv = ["theHarvester", "-q", "-d", domain, "-b", SOURCES,
                    "-f", str(module_dir / filename)]
            commands.append(Command(argv))
        return commands
