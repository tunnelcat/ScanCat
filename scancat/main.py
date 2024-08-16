import argparse
import os
import sys
import subprocess
import json
from .banner import display_banner
from .folderselect import folder_select_menu

def theharvester(domains):
    # run theHarvester and get json/xml output -> parse json for uniq sorted emails and hosts for each domain
    if not(os.path.exists('theHarvester') and os.path.isdir('theHarvester')):
        os.mkdir('theHarvester')
    os.chdir('theHarvester')

    for domain in domains:
        subprocess.run(["theHarvester", "-d", domain, "-b", "all", "-f", f"theHarvester-{domain}.json"])  # theHarvester strips the last .* from filename so use .json as placeholder
    
    # parse json to get emails and subdomain results
    for domain in domains:
        with open(f'theHarvester-{domain}.json', 'r') as file:
            data = json.load(file) 

        available_keys = list(data.keys())
        emails = []
        hosts = [] 

        if 'emails' in available_keys:
            emails = data['emails']
        if 'hosts' in available_keys:
            hosts = data['hosts']

        print("Emails:", emails)
        print("Hosts:", hosts)
        
        # uniq sorted, case insensitive lists
        uniq_sorted_emails = sorted(set([email.split(':')[0].lower() for email in emails if '*' not in email]))
        uniq_sorted_hosts = sorted(set([host.split(':')[0].lower() for host in hosts if '*' not in host]))
        
        with open(f'theHarvester-{domain}-emails.txt', 'w') as file:
            for email in uniq_sorted_emails:
                file.write(f"{email}\n")
        with open(f'theHarvester-{domain}-hosts.txt', 'w') as file:
            for host in uniq_sorted_hosts:
                file.write(f"{host}\n")
    
    os.chdir('..')


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

        theharvester(domains)
        # amass(domains)


    def scan_mode(args):
        print("Running scan mode - TODO")

    def vuln_mode(args):
        if args.nuclei:
            print("Running vulnerability scan with Nuclei")
        if args.brute:
            print("Running brute-force vulnerability scan")

    parser = argparse.ArgumentParser(description="A tool for recon, scanning, and vulnerability assessment.")
    
    subparsers = parser.add_subparsers(dest="mode", required=True, help="Mode of operation: recon, scan, or vuln")

    # Recon mode parser
    recon_parser = subparsers.add_parser("recon", help="Recon mode")
    recon_parser.add_argument("-f", "--file", help="File containing list of domains for recon mode")
    recon_parser.set_defaults(func=recon_mode)

    # Scan mode parser
    scan_parser = subparsers.add_parser("scan", help="Scan mode")
    scan_parser.add_argument("-f", "--file", help="File containing list of domains for scan mode")
    scan_parser.set_defaults(func=scan_mode)

    # Vulnerability mode parser
    vuln_parser = subparsers.add_parser("vuln", help="Vulnerability assessment mode")
    vuln_parser.add_argument("-n", "--nuclei", action="store_true", help="Run Nuclei-based vulnerability scan")
    vuln_parser.add_argument("-b", "--brute", action="store_true", help="Run brute-force vulnerability scan")
    vuln_parser.set_defaults(func=vuln_mode)

    # Print full help if no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # Parse arguments and call appropriate function
    args = parser.parse_args()
    args.func(args)
