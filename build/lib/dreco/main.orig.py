import sys
from dreco.commands import (
    get_a_records,
    get_ns_records,
    get_aaaa_records,
    get_mx_records,
    sublist3r_scan,
    nmap_scan,
    fetch_robots_txt
)

def display_welcome_message():
    """Displays the welcome message and project information."""
    welcome_message = r"""
  ____                     
 |  _ \ _ __ ___  ___ ___  
 | | | | '__/ _ \/ __/ _ \ 
 | |_| | | |  __/ (_| (_) |
 |____/|_|  \___|\___\___/ 

                   by Th3 0w1
"""
    print(welcome_message)

def main():
    """Main function to execute the DReco tool."""
    display_welcome_message()

    # Prompt user for domain input
    domain = input("Enter the domain name to scan: ").strip()
    if not domain:
        print("[ERROR] No domain provided. Exiting...")
        sys.exit(1)

    print(f"\n[INFO] Scanning domain: {domain}\n")

    # Retrieve DNS records
    a_records = get_a_records(domain)
    ns_records = get_ns_records(domain)
    aaaa_records = get_aaaa_records(domain)
    mx_records = get_mx_records(domain)

    # Subdomain enumeration using Sublist3r
    sublist3r_scan(domain)

    # Prompt user for IP address for Nmap scan
    target_ip = input("Enter the target IP address for Nmap scan: ").strip()
    if not target_ip:
        print("[ERROR] No IP address provided. Exiting...")
        sys.exit(1)

    nmap_scan(target_ip)

    # Fetch and display robots.txt content
    fetch_robots_txt(domain)

if __name__ == "__main__":
    main()

