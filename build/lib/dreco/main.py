import sys
import csv
import os
import threading
from dreco.commands import (
    get_a_records,
    get_ns_records,
    get_aaaa_records,
    get_mx_records,
    sublist3r_scan,
    nmap_scan,
    fetch_robots_txt,
    get_all_ips,
    run_dnsrecon,
    run_dnsenum,
    log_and_print,
    log_failed_hits
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

def process_domain(domain):
    """Process a single domain."""
    log_and_print(f"\n[INFO] Scanning domain: {domain}\n")

    # Retrieve DNS records
    a_records = get_a_records(domain)
    ns_records = get_ns_records(domain)
    aaaa_records = get_aaaa_records(domain)
    mx_records = get_mx_records(domain)

    # Subdomain enumeration using Sublist3r
    subdomains = sublist3r_scan(domain)

    if not subdomains:
        log_failed_hits(f"[ERROR] No subdomains found for {domain}.")
        return

    log_and_print(f"[INFO] Found subdomains: {', '.join(subdomains)}")

    # Get all possible IP addresses for the domain and its subdomains
    ip_addresses = get_all_ips(domain)
    for subdomain in subdomains:
        ip_addresses.extend(get_all_ips(subdomain))
    
    ip_addresses = list(set(ip_addresses))
    if not ip_addresses:
        log_failed_hits(f"[ERROR] No IP addresses found for {domain} or its subdomains.")
        return

    log_and_print(f"[INFO] Found IP addresses: {', '.join(ip_addresses)}\n")

    # Run Nmap for each found IP address
    for ip in ip_addresses:
        log_and_print(f"[INFO] Scanning target IP: {ip}\n")
        nmap_scan(ip)

    # Run DNSRecon and DNSEnum after Nmap scans
    run_dnsrecon(domain)
    run_dnsenum(domain)

    # Fetch and display robots.txt content
    fetch_robots_txt(domain)

def main():
    """Main function to execute the DReco tool."""
    display_welcome_message()

    # Prompt user for input type
    print("Choose an option:")
    print("1. Single domain")
    print("2. Multiple domains (from a text file)")

    choice = input("Enter your choice (1 or 2): ").strip()

    if choice == '1':
        domain = input("Enter the domain name to scan: ").strip()
        if not domain:
            print("[ERROR] No domain provided. Exiting...")
            sys.exit(1)
        process_domain(domain)

    elif choice == '2':
        file_path = input("Enter the path to the domain list file: ").strip()
        if not os.path.isfile(file_path):
            print("[ERROR] File does not exist. Exiting...")
            sys.exit(1)

        with open(file_path, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]

        threads = []
        for domain in domains:
            thread = threading.Thread(target=process_domain, args=(domain,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    else:
        print("[ERROR] Invalid choice. Exiting...")
        sys.exit(1)

if __name__ == "__main__":
    main()

