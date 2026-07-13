"""subfinder passive subdomain enumeration."""
import json

from .base import ReconModule, Command, merge_fqdns


class SubfinderModule(ReconModule):
    name = "subfinder"
    binary = "subfinder"
    module_class = ["subdomains"]

    def build(self, domains_file, module_dir, domains):
        argv = ["subfinder", "-silent", "-nc", "-all", "-dL", str(domains_file),
                "-oJ", "-o", str(module_dir / "subfinder-out.json")]
        return [Command(argv)]

    def parse_output(self, module_dir):
        out_file = module_dir / "subfinder-out.json"
        if not out_file.exists():
            return None

        hosts = set()
        for line in out_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = data.get("host")
            if host:
                hosts.add(host)

        return merge_fqdns(module_dir / "fqdns-subfinder.txt", hosts)
