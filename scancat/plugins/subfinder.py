"""subfinder passive subdomain enumeration."""
import json

from .base import BaseModule, Command, normalize_host, notify_failure


class SubfinderModule(BaseModule):
    name = "subfinder"
    binary = "subfinder"
    out_datatypes = ["host"]

    def build(self, module_dir, domains):
        # Seed subfinder from the subfolder's in-scope domains.
        if not domains:
            self.notice("[!] no in-scope domains in the recon scope")
            return []
        list_file = module_dir / "subfinder-in.txt"
        list_file.write_text("\n".join(domains) + ("\n" if domains else ""))
        argv = ["subfinder", "-silent", "-nc", "-all", "-dL", str(list_file),
                "-oJ", "-o", str(module_dir / "subfinder-out.json")]
        return [Command(argv)]

    def emit(self, line):
        # subfinder streams one JSON object per discovered subdomain; surface
        # just the host. A line that isn't JSON is the tool's own output (e.g.
        # an error), so error-check only then - a valid host named
        # "error.example.com" must stay a finding, not get tagged as an error.
        try:
            data = json.loads(line.strip())
        except json.JSONDecodeError:
            return notify_failure(line)
        host = normalize_host(data.get("host"))
        return f"[+] {host}" if host else None

    def adapt(self, module_dir):
        out_file = module_dir / "subfinder-out.json"
        if not out_file.exists():
            return {}

        hosts = []
        for line in out_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = normalize_host(data.get("host"))
            if host:
                hosts.append({"name": host})
        return {"hosts": hosts}
