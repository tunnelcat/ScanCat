"""Interactive project setup: detect or create a project, pick the subfolders
in scope, and pick which recon modules to run.

Uses questionary for arrow/spacebar checkbox menus. Per-subfolder target scope
(domains/IPs/CIDRs) lives in the datastore and is managed via `scancat scope`.
"""
from pathlib import Path

import questionary
from termcolor import colored

from .menu import checkbox
from .project import (PROJECT_FILE, DEFAULT_SUBFOLDERS,
                      load_project, new_project)
from .recon import MODULES


def find_project(start_dir="."):
    """Return the CLIENT folder holding a .scancat.yml, or None.

    Checks the current directory first (you are inside a project), then one
    level of subfolders (the current directory is a workspace of projects).
    """
    start = Path(start_dir).resolve()
    if (start / PROJECT_FILE).exists():
        return start
    candidates = [d for d in sorted(start.iterdir())
                  if d.is_dir() and (d / PROJECT_FILE).exists()]
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        choice = questionary.select(
            "Multiple scancat projects found. Select one:",
            choices=[d.name for d in candidates],
        ).ask()
        return (start / choice) if choice else None
    return None


def ensure_project(start_dir="."):
    """Detect a project or offer to create one. Returns a loaded Project."""
    root = find_project(start_dir)
    if root:
        proj = load_project(root)
        print(colored(f"[+] Loaded project: {proj.client}", "green"))
        return proj

    print(colored("[!] No scancat project found in this directory.", "yellow"))
    if not questionary.confirm("Create a new project here?", default=True).ask():
        print("No project. Exiting.")
        raise SystemExit(1)
    return create_project(start_dir)


def create_project(start_dir="."):
    client = questionary.text("Client name:").ask()
    if not client or not client.strip():
        print("No client name given. Exiting.")
        raise SystemExit(1)
    client = client.strip()

    root = Path(start_dir).resolve() / client
    root.mkdir(parents=True, exist_ok=True)
    proj = new_project(root, client)

    picked = checkbox(
        "Select standard subfolders to create:",
        [questionary.Choice(s, checked=True) for s in DEFAULT_SUBFOLDERS],
    ) or []

    extra = questionary.text(
        "Additional folder names (comma separated, blank to skip):"
    ).ask() or ""
    manual = [name.strip() for name in extra.split(",") if name.strip()]

    subfolders = []
    for name in picked + manual:
        if name not in subfolders:
            subfolders.append(name)
    for name in subfolders:
        (root / name).mkdir(exist_ok=True)

    proj.subfolders = subfolders
    proj.scope = list(subfolders)
    proj.save()
    print(colored(f"[+] Created project '{client}' with: "
                  f"{', '.join(subfolders) or '(no subfolders)'}", "green"))
    return proj


def select_scope(proj):
    """Interactive scope picker. Defaults to the memorized scope (or all)."""
    available = proj.existing_subfolders()
    if not available:
        print(colored("[!] No subfolders in project. Nothing to scope.", "yellow"))
        return []

    default_scope = proj.scope or available
    choices = [questionary.Choice(name, checked=(name in default_scope))
               for name in available]
    scope = checkbox("Select subfolders in scope:", choices) or []

    proj.scope = scope
    proj.save()
    print(colored(f"[+] Scope: [{','.join(scope)}]", "cyan"))
    return scope


def select_modules(proj):
    """Interactive module picker. Defaults to the memorized selection (or
    all modules enabled)."""
    available = [m.name for m in MODULES]
    default_enabled = proj.enabled_modules or available
    choices = [questionary.Choice(name, checked=(name in default_enabled))
               for name in available]
    enabled = checkbox("Select modules to run:", choices) or []

    proj.enabled_modules = enabled
    proj.save()
    print(colored(f"[+] Modules: [{','.join(enabled)}]", "cyan"))
    return enabled
