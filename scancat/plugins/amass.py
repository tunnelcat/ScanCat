"""amass subdomain enumeration."""
from .base import ReconModule, Command


class AmassModule(ReconModule):
    name = "amass"
    binary = "amass"

    def build(self, domains_file, module_dir, domains):
        out = module_dir / "amass-out-recursive.txt"
        argv = ["amass", "enum", "-active", "-brute",
                "-min-for-recursive", "2",
                "-df", str(domains_file), "-o", str(out)]
        return [Command(argv, reads=[out])]
