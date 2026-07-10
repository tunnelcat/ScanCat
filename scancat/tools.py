"""External tools scancat relies on, and a startup availability check."""
import shutil

from termcolor import colored

# command that must be on PATH -> package name to install
REQUIRED_TOOLS = {
    "nmap": "nmap",
    "massdns": "massdns",
    "theHarvester": "theharvester",
    "amass": "amass",
    "subfinder": "subfinder",
    "nuclei": "nuclei",
    "onesixtyone": "onesixtyone",
    "snmp-check": "snmp-check",
    "hydra": "hydra",
}


def missing_tools():
    """Install names of required tools not found on PATH."""
    return [pkg for cmd, pkg in REQUIRED_TOOLS.items() if shutil.which(cmd) is None]


def warn_missing_tools():
    """Warn once, at startup, about any tools that need installing."""
    missing = missing_tools()
    if missing:
        print(colored("[!] Missing tools: " + " ".join(missing), "yellow"))
        print(colored("[!] Install them to enable all modules.", "yellow"))
    return missing
