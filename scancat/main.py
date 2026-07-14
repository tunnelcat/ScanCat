import argparse
import asyncio
import sys

from .banner import display_banner
from .folderselect import ensure_project, select_scope, select_modules
from .recon import run_recon
from .scope import cmd_scope, ensure_scope
from .tools import warn_missing_tools


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
    asyncio.run(run_recon(proj, active, enabled_modules))


def scan_mode(args, proj):
    print("Running scan mode - TODO")


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
                    "stored per subfolder. Scope is the source of truth for "
                    "what recon and scanning run against.",
        epilog="examples:\n"
               "  scancat scope add example.com 10.0.0.0/24 --sub ext\n"
               "  scancat scope add api.example.com --sub ext --note client-confirmed\n"
               "  scancat scope exclude 10.0.0.5 --sub ext --note decommissioned\n"
               "  scancat scope rm old.example.com --sub ext\n"
               "  scancat scope edit --sub ext\n"
               "  scancat scope list",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    scope_sub = scope_parser.add_subparsers(
        dest="scope_cmd", metavar="{add,exclude,rm,list,edit}")
    for name, help_text in (
            ("add", "Add target(s) to scope"),
            ("exclude", "Add target(s) as exclusions (carved out of scope)"),
            ("rm", "Remove (soft-delete) target(s) from scope")):
        p = scope_sub.add_parser(name, help=help_text, description=help_text)
        p.add_argument("value", nargs="+",
                       help="target(s): domain, ip, cidr, or ip range")
        p.add_argument("-s", "--sub", action="append",
                       help="subfolder(s); repeatable or comma-separated "
                            "(default: the only subfolder, else required)")
        if name != "rm":
            p.add_argument("--note", help="optional note stored with the entry")
    p = scope_sub.add_parser("list", help="Show current scope",
                             description="Show the active scope for a subfolder "
                                         "(or all subfolders by default).")
    p.add_argument("-s", "--sub", action="append",
                   help="subfolder(s) (default: all)")
    p = scope_sub.add_parser(
        "edit", help="Edit a subfolder's scope in $EDITOR",
        description="Open the subfolder's scope in $EDITOR and reconcile on "
                    "save: added lines are inserted, removed lines disabled.")
    p.add_argument("-s", "--sub", action="append", help="subfolder to edit")
    scope_parser.set_defaults(func=cmd_scope, scope_parser=scope_parser)

    # Print full help if no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    proj = ensure_project(".")
    args.func(args, proj)
