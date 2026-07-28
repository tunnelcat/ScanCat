"""Interactive project setup: detect or create a project, pick the subfolders
in scope, and pick which recon modules to run.

Uses questionary for arrow/spacebar checkbox menus. Per-subfolder target scope
(domains/IPs/CIDRs) lives in the datastore and is managed via `scancat scope`.
"""
from pathlib import Path

import questionary
from termcolor import colored

from .config import disabled_modules
from .menu import checkbox
from .project import (PROJECT_FILE, DEFAULT_SUBFOLDERS,
                      load_project, new_project)
from .phases import RECON_MODULES


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


def select_modules(proj, modules=None, attr="enabled_modules"):
    """Interactive module picker, shared by every phase (recon, scan, vuln).
    Defaults to the memorized selection, else all modules except those disabled
    in scancat.yml. `attr` is the Project field the selection persists to (each
    phase remembers its picks separately)."""
    modules = RECON_MODULES if modules is None else modules
    # A saved project pick always wins. On a project's first run, everything is
    # checked except the modules scancat.yml lists under disabled_modules.
    disabled = disabled_modules()
    default_enabled = getattr(proj, attr) or \
        [m.name for m in modules if m.name not in disabled]
    choices = [questionary.Choice(m.name, checked=(m.name in default_enabled))
               for m in modules]
    enabled = checkbox("Select modules to run:", choices) or []

    setattr(proj, attr, enabled)
    proj.save()
    print(colored(f"[+] Modules: [{','.join(enabled)}]", "cyan"))
    return enabled


def select_scan_modules(proj):
    """Scan (nmap) module picker. Same as select_modules, but if the custom
    mode is selected it also prompts for the nmap flags to run (remembered
    between runs); with no flags given, the custom mode is dropped."""
    from .phases import SCAN_MODULES
    from .plugins.nmap import NmapCustomModule

    enabled = select_modules(proj, SCAN_MODULES, "enabled_scan_modules")
    if NmapCustomModule.name in enabled:
        flags = questionary.text(
            "Custom nmap flags (override the global flags):",
            default=proj.custom_scan_flags or "").ask()
        proj.custom_scan_flags = (flags or "").strip()
        proj.save()
        if not proj.custom_scan_flags:
            print(colored("[!] No custom flags given; skipping nmap-custom.",
                          "yellow"))
            enabled = [m for m in enabled if m != NmapCustomModule.name]
    return enabled
