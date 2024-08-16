import argparse
import os
import sys
import subprocess
from .banner import display_banner
from .folderselect import folder_select_menu


def main(): 
    display_banner()

    def open_editor(file_path):
        editor = os.environ.get('EDITOR', 'nano')  # Default to 'nano' if no editor is set
        subprocess.call([editor, file_path])

    def read_domains(file_path):
        if not os.path.exists(file_path):
            print(f"File '{file_path}' not found.")
            create = input("Do you want to create and edit the file now? [Enter one domain per line] (y/n): ").strip().lower()
            if create == 'y':
                open_editor(file_path)
            else:
                print("No domains file provided. Exiting.")
                sys.exit(1)

        with open(file_path, 'r') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]  # might not need line startswith ignoring comments
        return domains

    def recon_mode(args):
        file_path = args.file if args.file else "domains.txt"
        domains = read_domains(file_path)
        print(f"Running recon mode with domains: {domains}")

    
    # Create the main parser
    parser = argparse.ArgumentParser(description="A tool for recon, scanning, and vulnerability assessment.")
    
    # Add the mode/module argument (positional argument)
    parser.add_argument("mode", choices=["recon", "scan", "vuln"], help="Mode of operation: recon, scan, or vuln")

    # Add an optional argument for recon mode to specify a file
    parser.add_argument("-f", "--file", help="File containing list of domains for recon mode")

    # Add an optional argument for additional parameters
    # parser.add_argument("params", nargs=argparse.REMAINDER, help="Optional parameters for the selected mode")

    # Parse the arguments
    args = parser.parse_args()

    # Dispatch to the appropriate function based on the mode
    if args.mode == "recon":
        recon_mode(args)
    elif args.mode == "scan":
        print(f"Running scan mode with parameters: {args.params}")
    elif args.mode == "vuln":
        print(f"Running vuln mode with parameters: {args.params}")
    else:
        parser.print_help()
        sys.exit(1)

