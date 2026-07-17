"""subfinder passive subdomain enumeration."""
import json

from .base import ReconModule, Command, normalize_host, notify_failure


class SubfinderModule(ReconModule):
    name = "subfinder"
    binary = "subfinder"
    out_datatypes = ["host"]

    def build(self, module_dir, domains):
        # Seed subfinder from the subfolder's in-scope domains.
        list_file = module_dir / "subfinder-in.txt"
        list_file.write_text("\n".join(domains) + ("\n" if domains else ""))
        argv = ["subfinder", "-silent", "-nc", "-all", "-dL", str(list_file),
                "-oJ", "-o", str(module_dir / "subfinder-out.json")]
        return [Command(argv)]

    def display_line(self, line):
        # subfinder streams one JSON object per discovered subdomain; surface
        # just the host so the TUI reads as a clean list of finds.
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return notify_failure(line)   # non-JSON => possibly an error/warning
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
