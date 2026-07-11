"""theHarvester OSINT recon, run once per domain."""
import json

from .base import ReconModule, Command, merge_fqdns

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

    def parse_output(self, module_dir):
        hosts = set()
        for out_file in module_dir.glob("theHarvester-*.json"):
            try:
                data = json.loads(out_file.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            for entry in data.get("hosts", []):
                # entries may be "host" or "host:ip"/"host:ipv6" - keep the hostname
                host = entry.split(":", 1)[0]
                if host:
                    hosts.add(host)

        return merge_fqdns(module_dir / "fqdns-theHarvester.txt", hosts)
