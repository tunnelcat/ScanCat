import argparse
import asyncio
import os
import shutil
import subprocess
import sys

from termcolor import colored

from .banner import display_banner
from .folderselect import (ensure_project, select_scope, select_modules,
                          select_scan_modules)
from .recon import run_modules, MODULES
from .plugins.nmap import SCAN_MODULES, scan_needs_root
from .scope import cmd_scope, ensure_scope, ensure_scan_scope
from .tools import warn_missing_tools


def _prime_sudo():
    """Cache sudo credentials before the scan TUI starts, so root-requiring
    modes can run as `sudo -n nmap` without a password prompt appearing (and
    hanging) inside the alternate-screen display. Returns True if usable."""
    if shutil.which("sudo") is None:
        print(colored("[-] sudo not found; run scancat as root for raw scans.",
                      "red"))
        return False
    print(colored("[*] Some selected scan modes need root; caching sudo "
                  "credentials...", "cyan"))
    try:
        ok = subprocess.call(["sudo", "-v"]) == 0
    except OSError:
        ok = False
    if not ok:
        print(colored("[!] sudo authentication failed; raw scan modes may not "
                      "work.", "yellow"))
    return ok


def recon_mode(args, proj):
    scope = select_scope(proj)
    if not scope:
        print("No subfolders in scope. Nothing to do.")
        return
    enabled_modules = select_modules(proj)
    if not enabled_modules:
        print("No modules selected. Nothing to run.")
        return
    active = ensure_scope(proj, scope)
    if not active:
        print("No subfolders have targets in scope. Nothing to run.")
        return
    asyncio.run(run_modules(proj, active, MODULES, enabled_modules))


def scan_mode(args, proj):
    scope = select_scope(proj)
    if not scope:
        print("No subfolders in scope. Nothing to do.")
        return
    enabled_modules = select_scan_modules(proj)
    if not enabled_modules:
        print("No scan modules selected. Nothing to run.")
        return
    active = ensure_scan_scope(proj, scope)
    if not active:
        print("No subfolders have targets in the scan scope. Nothing to run.")
        return
    proj.use_sudo = False
    if scan_needs_root(enabled_modules, proj) and os.geteuid() != 0:
        # Prime sudo up front; if it fails, abort here rather than opening the
        # TUI only for every root scan mode to fail on `sudo -n`.
        if not _prime_sudo():
            print(colored("[-] Root scan modes need sudo; aborting before the "
                          "scan starts.", "red"))
            return
        proj.use_sudo = True
    asyncio.run(run_modules(proj, active, SCAN_MODULES, enabled_modules))


def vuln_mode(args, proj):
    if args.nuclei:
        print("Running vulnerability scan with Nuclei - TODO")
    if args.brute:
        print("Running brute-force vulnerability scan - TODO")
    if not (args.nuclei or args.brute):
        print("Running vuln mode - TODO")


def main():
    display_banner()
    warn_missing_tools()

    parser = argparse.ArgumentParser(
        description="A tool for recon, scanning, and vulnerability assessment."
    )
    subparsers = parser.add_subparsers(
        dest="mode", required=True,
        help="Mode of operation: recon, scan, or vuln")

    recon_parser = subparsers.add_parser("recon", help="Recon mode")
    recon_parser.set_defaults(func=recon_mode)

    scan_parser = subparsers.add_parser("scan", help="Scan mode")
    scan_parser.set_defaults(func=scan_mode)

    vuln_parser = subparsers.add_parser("vuln", help="Vulnerability assessment mode")
    vuln_parser.add_argument("-n", "--nuclei", action="store_true",
                             help="Run Nuclei-based vulnerability scan")
    vuln_parser.add_argument("-b", "--brute", action="store_true",
                             help="Run brute-force vulnerability scan")
    vuln_parser.set_defaults(func=vuln_mode)

    scope_parser = subparsers.add_parser(
        "scope", help="Manage per-subfolder target scope",
        description="Manage the target scope (domains, IPs, CIDRs, IP ranges) "
                    "stored per subfolder, split by phase: 'recon' seeds "
                    "subdomain discovery, 'scan' is what nmap targets.",
        epilog="examples:\n"
               "  scancat scope add example.com 10.0.0.0/24 --phase recon --sub ext\n"
               "  scancat scope list --phase recon --sub ext\n"
               "  scancat scope expand --sub ext        # recon hosts -> scan scope\n"
               "  scancat scope edit --phase scan --sub ext\n"
               "  scancat scope exclude sip.example.com --phase scan --sub ext",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    scope_sub = scope_parser.add_subparsers(
        dest="scope_cmd", metavar="{add,exclude,rm,list,edit,expand,import}")

    def add_phase(p):
        p.add_argument("-p", "--phase", required=True, choices=("recon", "scan"),
                       help="which scope: recon (seed domains) or scan (nmap)")

    def add_sub(p, helptext="subfolder(s); repeatable or comma-separated"):
        p.add_argument("-s", "--sub", action="append", help=helptext)

    for name, help_text in (
            ("add", "Add target(s) to scope"),
            ("exclude", "Add target(s) as exclusions (carved out of scope)"),
            ("rm", "Remove (soft-delete) target(s) from scope")):
        p = scope_sub.add_parser(name, help=help_text, description=help_text)
        p.add_argument("value", nargs="+",
                       help="target(s): domain, ip, cidr, or ip range")
        add_phase(p)
        add_sub(p)
        if name != "rm":
            p.add_argument("--note", help="optional note stored with the entry")

    p = scope_sub.add_parser("list", help="Show current scope",
                             description="Show the active scope, grouped by "
                                         "phase, for one subfolder or all.")
    p.add_argument("-p", "--phase", choices=("recon", "scan"),
                   help="filter to one phase (default: all phases)")
    add_sub(p, "subfolder(s) (default: all)")

    p = scope_sub.add_parser(
        "edit", help="Edit a subfolder's scope in $EDITOR",
        description="Open a phase's scope in $EDITOR and reconcile on save: "
                    "added lines are inserted, removed lines disabled.")
    add_phase(p)
    add_sub(p, "subfolder to edit")

    p = scope_sub.add_parser(
        "expand", help="Pull recon-discovered hosts into the scan scope",
        description="Add recon-discovered hosts to the scan scope. By default "
                    "only resolvable hosts are added and scan_noise "
                    "(autodiscover.*, etc.) is skipped. Hosts already in the "
                    "scan scope are left as-is (removals aren't undone).")
    add_sub(p)
    p.add_argument("--include-unresolvable-hosts", action="store_true",
                   help="also add hosts that didn't resolve")
    p.add_argument("--include-scan-noise", action="store_true",
                   help="don't skip scan_noise matches")

    p = scope_sub.add_parser(
        "import", help="Copy scope entries from one phase to another",
        description="Copy the active scope (targets and exclusions) from one "
                    "phase into another. Entries already present in the "
                    "destination phase are left as-is (removals aren't undone).")
    p.add_argument("--from", dest="from_phase", required=True,
                   choices=("recon", "scan"), help="source phase")
    p.add_argument("--to", dest="to_phase", required=True,
                   choices=("recon", "scan"), help="destination phase")
    add_sub(p)
    scope_parser.set_defaults(func=cmd_scope, scope_parser=scope_parser)

    # Print full help if no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    proj = ensure_project(".")
    args.func(args, proj)
