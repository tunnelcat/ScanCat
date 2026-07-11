"""subfinder passive subdomain enumeration."""
from .base import ReconModule, Command


class SubfinderModule(ReconModule):
    name = "subfinder"
    binary = "subfinder"
    modular_outputs = ["fqdns"]

    def build(self, domains_file, module_dir, domains):
        argv = ["subfinder", "-all", "-dL", str(domains_file)]
        return [Command(argv)]
