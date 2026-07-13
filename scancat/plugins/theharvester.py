"""theHarvester OSINT recon, run once per domain."""
import json

from .base import ReconModule, Command, normalize_host, ip_version

SOURCES = ("all")


class TheHarvesterModule(ReconModule):
    name = "theharvester"
    binary = "theHarvester"
    out_datatypes = ["host"]

    def build(self, domains_file, module_dir, domains):
        commands = []
        for domain in domains:
            filename = f"theHarvester-{domain.replace('.', '-')}"
            argv = ["theHarvester", "-q", "-d", domain, "-b", SOURCES,
                    "-f", str(module_dir / filename)]
            commands.append(Command(argv))
        return commands

    def adapt(self, module_dir):
        # Deduplication is the datastore's job (unique keys + upsert), so this
        # just emits every valid record it sees.
        hosts, ips, dns, emails = [], [], [], []

        def add_ip(addr):
            ver = ip_version(addr)
            if ver:
                ips.append({"address": addr, "version": ver})
            return ver

        for out_file in module_dir.glob("theHarvester-*.json"):
            try:
                data = json.loads(out_file.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            for entry in data.get("hosts", []):
                # entries may be "host", "host:ip", or "host:ipv6"
                host_part, _, ip_part = entry.partition(":")
                host = normalize_host(host_part)
                if not host:
                    continue
                hosts.append({"name": host})
                ip = ip_part.strip()
                if ip:
                    ver = add_ip(ip)
                    if ver:
                        rtype = "A" if ver == 4 else "AAAA"
                        dns.append({"host": host, "type": rtype, "value": ip})
            for addr in data.get("ips", []):
                add_ip(addr.strip())
            for em in data.get("emails", []):
                em = em.strip().lower()
                if em and "@" in em:
                    emails.append({"address": em})

        return {"hosts": hosts, "ips": ips, "dns": dns, "emails": emails}
