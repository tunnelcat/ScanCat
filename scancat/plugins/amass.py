"""amass subdomain enumeration."""
from .base import ReconModule, Command


class AmassModule(ReconModule):
    name = "amass"
    binary = "amass"
    modular_outputs = ["fqdns"]

    def build(self, domains_file, module_dir, domains):
        argv = ["amass", "enum", "-v", "-active", "-brute",
                "-min-for-recursive", "1", "-nocolor",
                "-timeout", "60",  # TODO - variable timeout
                "-df", str(domains_file)]
        return [Command(argv)]
