import argparse
import asyncio
import os
import subprocess
import sys

from .banner import display_banner
from .folderselect import ensure_project, select_scope, select_modules, ensure_domains_files
from .recon import run_recon
from .tools import warn_missing_tools


def open_editor(file_path):
    editor = os.environ.get("EDITOR", "nano")  # default to nano if unset
    subprocess.call([editor, file_path])


def recon_mode(args, proj):
    scope = select_scope(proj)
    if not scope:
        print("No subfolders in scope. Nothing to do.")
        return
    enabled_modules = select_modules(proj)
    if not enabled_modules:
        print("No modules selected. Nothing to run.")
        return
    active = ensure_domains_files(proj, scope, open_editor)
    if not active:
        print("No subfolders have domains. Nothing to run.")
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

    # Print full help if no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    proj = ensure_project(".")
    args.func(args, proj)
