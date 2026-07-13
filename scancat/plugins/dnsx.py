"""dnsx DNS resolution.

Runs after the subdomain modules for a subfolder finish (see depends_on),
resolving the union of domains.txt and the collected fqdns-all.txt. Into the
subfolder it accumulates: fqdns-live.txt (hosts that resolved NOERROR),
fqdns-a.txt (host -> A records), and fqdns-cname.txt (host -> CNAME records).
"""
import json

from .base import ReconModule, Command, FQDN_RE, merge_fqdns, merge_resp


class DnsxModule(ReconModule):
    name = "dnsx"
    binary = "dnsx"
    module_class = ["dns"]
    depends_on = ["subdomains"]   # wait for subfinder/theHarvester to settle

    def build(self, domains_file, module_dir, domains):
        # Input list = domains.txt + the subdomains gathered into fqdns-all.txt
        # (one level up), deduplicated and sorted.
        list_file = module_dir / "dnsx-in.txt"
        entries = set()
        for src in (domains_file, module_dir.parent / "fqdns-all.txt"):
            if src.exists():
                entries.update(ln.strip() for ln in src.read_text().splitlines()
                              if ln.strip())
        list_file.write_text("\n".join(sorted(entries))
                            + ("\n" if entries else ""))

        argv = ["dnsx", "-l", str(list_file), "-silent", "-resp", "-nc",
                "-json", "-or", "-o", str(module_dir / "dnsx-out.json")]
        return [Command(argv)]

    def parse_output(self, module_dir):
        out_file = module_dir / "dnsx-out.json"
        if not out_file.exists():
            return None

        live = set()        # hosts that resolved with status NOERROR
        a_map = {}          # host -> set of A-record IPs
        cname_map = {}      # host -> set of CNAME targets
        for line in out_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = data.get("host", "").strip().lower().rstrip(".")
            if not host or not FQDN_RE.match(host):
                continue
            if data.get("status_code") == "NOERROR":
                live.add(host)
            # Only record a host under a type when it actually has a non-empty
            # value there; an empty/whitespace list must not create an entry.
            a_records = {ip.strip() for ip in (data.get("a") or []) if ip.strip()}
            if a_records:
                a_map.setdefault(host, set()).update(a_records)
            cnames = {c.strip().lower().rstrip(".")
                     for c in (data.get("cname") or []) if c.strip().rstrip(".")}
            if cnames:
                cname_map.setdefault(host, set()).update(cnames)

        # Accumulate into the base subfolder (one level up), sorted + unique.
        base = module_dir.parent
        merge_fqdns(base / "fqdns-live.txt", live)
        merge_resp(base / "fqdns-a.txt", a_map)
        merge_resp(base / "fqdns-cname.txt", cname_map)
        return None   # dnsx doesn't add to fqdns-all (its input came from it)
