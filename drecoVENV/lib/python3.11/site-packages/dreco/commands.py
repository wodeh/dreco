import subprocess
import socket
import logging

# Set up logging
logging.basicConfig(
    filename='scan_output.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_and_print(message):
    """Logs message to both console and file."""
    print(message)
    logging.info(message)

def get_a_records(domain):
    """Retrieves A records for the specified domain."""
    log_and_print(f"Retrieving A records for {domain}...")
    return []

def get_ns_records(domain):
    """Retrieves NS records for the specified domain."""
    log_and_print(f"Retrieving NS records for {domain}...")
    return []

def get_aaaa_records(domain):
    """Retrieves AAAA records for the specified domain."""
    log_and_print(f"Retrieving AAAA records for {domain}...")
    return []

def get_mx_records(domain):
    """Retrieves MX records for the specified domain."""
    log_and_print(f"Retrieving MX records for {domain}...")
    return []

def sublist3r_scan(domain):
    """Runs Sublist3r to enumerate subdomains for the given domain."""
    log_and_print(f"Running Sublist3r for {domain}...")
    command = ['sublist3r', '-d', domain, '-o', '/dev/null']
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode == 0:
        subdomains = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("[") and not line.startswith("-"):
                if line.count('.') >= 1 and all(part for part in line.split('.')):
                    subdomains.append(line)
        return subdomains
    else:
        log_and_print("[ERROR] Failed to run Sublist3r.")
        return []

def get_all_ips(domain):
    """Fetches all possible IP addresses associated with the given domain and its subdomains."""
    ip_addresses = []
    try:
        main_ip = socket.gethostbyname(domain)
        ip_addresses.append(main_ip)
    except socket.gaierror:
        log_and_print(f"[ERROR] Could not resolve domain: {domain}")

    subdomains = sublist3r_scan(domain)
    for subdomain in subdomains:
        try:
            sub_ip = socket.gethostbyname(subdomain)
            ip_addresses.append(sub_ip)
        except socket.gaierror:
            log_and_print(f"[ERROR] Could not resolve subdomain: {subdomain}")

    return list(set(ip_addresses))

def nmap_scan(target_ip):
    """Runs Nmap on the specified IP address."""
    log_and_print(f"Running Nmap scan on {target_ip}...")
    command = ['nmap', '-sV', target_ip]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 0:
        log_and_print(result.stdout)
    else:
        log_and_print(f"[ERROR] Nmap scan failed for {target_ip}.")

def fetch_robots_txt(domain):
    """Fetches and displays the contents of robots.txt for the given domain."""
    try:
        response = subprocess.run(['curl', f'http://{domain}/robots.txt'], capture_output=True, text=True)
        if response.returncode == 0:
            log_and_print(response.stdout)
        else:
            log_and_print(f"[ERROR] Failed to fetch robots.txt for {domain}.")
    except Exception as e:
        log_and_print(f"[ERROR] Exception occurred: {e}")

def run_dnsrecon(domain):
    """Runs DNSRecon on the specified domain."""
    log_and_print(f"Running DNSRecon for {domain}...")
    command = ['dnsrecon', '-d', domain, '-a']
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 0:
        log_and_print(result.stdout)
    else:
        log_and_print(f"[ERROR] DNSRecon scan failed for {domain}.")

def run_dnsenum(domain):
    """Runs DNSEnum on the specified domain."""
    log_and_print(f"Running DNSEnum for {domain}...")
    command = ['dnsenum', domain]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 0:
        log_and_print(result.stdout)
    else:
        log_and_print(f"[ERROR] DNSEnum scan failed for {domain}.")

