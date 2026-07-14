"""Scancat project model: the .scancat.yml config and path helpers.

A "project" is a CLIENT folder containing a .scancat.yml file. The yml stores
the client name, the year/month it was created, the subfolders that exist,
the subfolders currently in scope, and the recon modules currently enabled
(all memorized between runs).
"""
import datetime
from dataclasses import dataclass, field
from pathlib import Path

import yaml

PROJECT_FILE = ".scancat.yml"
DEFAULT_SUBFOLDERS = ["ext", "int", "wapt"]

# Hostname globs skipped by `scancat scope expand` - infrastructure endpoints
# (mostly Microsoft 365) that are noise for a pentest. Editable per project.
DEFAULT_SCAN_NOISE = [
    "autodiscover.*",
    "lyncdiscover.*",
    "sip.*",
    "enterpriseregistration.*",
    "enterpriseenrollment.*",
    "msoid.*",
    "*._domainkey.*",
    "_dmarc.*",
]


@dataclass
class Project:
    root: Path            # the CLIENT folder
    client: str
    year: str             # xxxx
    month: str            # xx
    subfolders: list = field(default_factory=list)
    scope: list = field(default_factory=list)
    enabled_modules: list = field(default_factory=list)
    scan_noise: list = field(
        default_factory=lambda: list(DEFAULT_SCAN_NOISE))

    @property
    def config_path(self):
        return self.root / PROJECT_FILE

    def subfolder_path(self, name):
        return self.root / name

    def existing_subfolders(self):
        """Top-level folders inside the project (skips hidden ones)."""
        return [d.name for d in sorted(self.root.iterdir())
                if d.is_dir() and not d.name.startswith(".")]

    def save(self):
        data = {
            "client": self.client,
            "year": self.year,
            "month": self.month,
            "subfolders": self.subfolders,
            "scope": self.scope,
            "enabled_modules": self.enabled_modules,
            "scan_noise": self.scan_noise,
        }
        with open(self.config_path, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


def load_project(root):
    root = Path(root)
    with open(root / PROJECT_FILE) as f:
        data = yaml.safe_load(f) or {}
    return Project(
        root=root,
        client=data.get("client", root.name),
        year=str(data.get("year", "")),
        month=str(data.get("month", "")),
        subfolders=data.get("subfolders", []) or [],
        scope=data.get("scope", []) or [],
        enabled_modules=data.get("enabled_modules", []) or [],
        scan_noise=(data.get("scan_noise") or list(DEFAULT_SCAN_NOISE)),
    )


def new_project(root, client):
    now = datetime.datetime.now()
    return Project(
        root=Path(root),
        client=client,
        year=now.strftime("%Y"),
        month=now.strftime("%m"),
    )
