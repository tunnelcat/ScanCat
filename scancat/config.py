"""Global scancat.yml: user-editable defaults shared by every project.

Lives next to scancat.py (the repo root), and is separate from a project's own
.scancat.yml (which remembers that one project's saved picks). Right now it just
lists the modules left unchecked in the picker on a project's first run - edit
scancat.yml to change those defaults for new projects.

Everything is enabled by default; a module is only unchecked if scancat.yml
lists it under disabled_modules. A missing or unreadable file means nothing is
disabled (all modules checked).
"""
from pathlib import Path

import yaml

# Repo root = one level up from this package, where scancat.py lives.
CONFIG_PATH = Path(__file__).resolve().parent.parent / "scancat.yml"


def load_config():
    """Parse scancat.yml into a dict, or {} if it's missing or unreadable."""
    try:
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        return {}


def disabled_modules():
    """Module names left unchecked in the picker on a project's first run, from
    scancat.yml's disabled_modules list (empty if unset). One flat set matched
    by name, so it applies to any module in any phase (recon, scan, vuln) that
    goes through select_modules - module names are unique across phases."""
    value = load_config().get("disabled_modules")
    return set(value) if isinstance(value, list) else set()
