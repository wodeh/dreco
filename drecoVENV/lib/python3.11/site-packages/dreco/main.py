import sys
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
    log_and_print  # Import the logging function
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

    log_and_print(f"\n[INFO] Scanning domain: {domain}\n")

    # Retrieve DNS records
    get_a_records(domain)
    get_ns_records(domain)
    get_aaaa_records(domain)
    get_mx_records(domain)

    # Subdomain enumeration using Sublist3r
    subdomains = sublist3r_scan(domain)

    if not subdomains:
        log_and_print("[ERROR] No subdomains found. Exiting...")
        sys.exit(1)

    log_and_print(f"[INFO] Found subdomains: {', '.join(subdomains)}")

    # Get all possible IP addresses for the domain and its subdomains
    ip_addresses = get_all_ips(domain)
    for subdomain in subdomains:
        ip_addresses.extend(get_all_ips(subdomain))
    
    ip_addresses = list(set(ip_addresses))
    if not ip_addresses:
        log_and_print("[ERROR] No IP addresses found for the domain or its subdomains. Exiting...")
        sys.exit(1)

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

if __name__ == "__main__":
    main()

