"""Scancat project model: the .scancat.yml config and path helpers.

A "project" is a CLIENT folder containing a .scancat.yml file. The yml stores
the client name, the year/month it was created, the subfolders that exist and
the subfolders currently in scope (memorized between runs).
"""
import datetime
from dataclasses import dataclass, field
from pathlib import Path

import yaml

PROJECT_FILE = ".scancat.yml"
DEFAULT_SUBFOLDERS = ["int", "ext", "wapt"]


@dataclass
class Project:
    root: Path            # the CLIENT folder
    client: str
    year: str             # xxxx
    month: str            # xx
    subfolders: list = field(default_factory=list)
    scope: list = field(default_factory=list)

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
    )


def new_project(root, client):
    now = datetime.datetime.now()
    return Project(
        root=Path(root),
        client=client,
        year=now.strftime("%Y"),
        month=now.strftime("%m"),
    )
