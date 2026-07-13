"""subfinder passive subdomain enumeration."""
import json

from .base import ReconModule, Command, normalize_host


class SubfinderModule(ReconModule):
    name = "subfinder"
    binary = "subfinder"
    out_datatypes = ["host"]

    def build(self, domains_file, module_dir, domains):
        argv = ["subfinder", "-silent", "-nc", "-all", "-dL", str(domains_file),
                "-oJ", "-o", str(module_dir / "subfinder-out.json")]
        return [Command(argv)]

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
