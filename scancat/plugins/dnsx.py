"""dnsx DNS resolution.

Runs after the subdomain modules for a subfolder finish (see depends_on),
resolving the union of the in-scope domains and every domain already collected
in the subfolder datastore. Its adapter records each host's resolvability
(NOERROR) and its A/AAAA/CNAME records back into that same datastore.
"""
import json

from .base import ReconModule, Command, normalize_host, ip_version
from ..store import SubfolderStore


class DnsxModule(ReconModule):
    name = "dnsx"
    binary = "dnsx"
    out_datatypes = ["dns"]
    depends_on = ["host"]   # wait for subfinder/theHarvester to settle

    def build(self, module_dir, domains):
        # Input list = in-scope domains + every host gathered so far in the
        # subfolder datastore (scancat.db one level up), deduped and sorted.
        list_file = module_dir / "dnsx-in.txt"
        entries = set(domains)
        store = SubfolderStore(module_dir.parent / "scancat.db")
        entries.update(store.host_names())
        list_file.write_text("\n".join(sorted(entries))
                            + ("\n" if entries else ""))

        argv = ["dnsx", "-l", str(list_file), "-silent", "-resp", "-nc",
                "-json", "-or", "-o", str(module_dir / "dnsx-out.json")]
        return [Command(argv)]

    def adapt(self, module_dir):
        out_file = module_dir / "dnsx-out.json"
        if not out_file.exists():
            return {}

        # Deduplication is the datastore's job (unique keys + upsert), so this
        # just emits every valid record it sees. A/AAAA go out as dns rows; the
        # store turns them into ips + resolutions, so no separate ips list.
        hosts, dns = [], []
        for line in out_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = normalize_host(data.get("host"))
            if not host:
                continue
            status = data.get("status_code")
            hosts.append({"name": host, "status_code": status,
                          "resolvable": status == "NOERROR"})
            for rtype, want in (("a", 4), ("aaaa", 6)):
                for ip in (data.get(rtype) or []):
                    ip = ip.strip()
                    if ip and ip_version(ip) == want:
                        dns.append({"host": host, "type": rtype.upper(),
                                    "value": ip})
            for cname in (data.get("cname") or []):
                target = cname.strip().lower().rstrip(".")
                if target:
                    dns.append({"host": host, "type": "CNAME", "value": target})

        return {"hosts": hosts, "dns": dns}
