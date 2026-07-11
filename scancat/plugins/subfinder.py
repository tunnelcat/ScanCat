"""subfinder passive subdomain enumeration."""
from .base import ReconModule, Command


class SubfinderModule(ReconModule):
    name = "subfinder"
    binary = "subfinder"

    def build(self, domains_file, module_dir, domains):
        argv = ["subfinder", "-nc", "-all", "-dL", str(domains_file),
                "-oJ", "-o", str(module_dir / "subfinder-out.json")]
        return [Command(argv)]
