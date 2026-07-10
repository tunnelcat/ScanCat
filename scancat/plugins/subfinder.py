"""subfinder passive subdomain enumeration."""
from .base import ReconModule, Command


class SubfinderModule(ReconModule):
    name = "subfinder"
    binary = "subfinder"

    def build(self, domains_file, module_dir, domains):
        out = module_dir / "subfinder-out.txt"
        argv = ["subfinder", "-all", "-dL", str(domains_file), "-o", str(out)]
        return [Command(argv, reads=[out])]
