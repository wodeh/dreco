import subprocess
import socket
import logging

# Set up logging for successful hits
logging.basicConfig(
    filename='scan_output.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Set up logging for failed hits
failed_logging = logging.getLogger('failed_hits')
failed_handler = logging.FileHandler('failed_hits.log')
failed_handler.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
failed_handler.setFormatter(formatter)
failed_logging.addHandler(failed_handler)

def log_and_print(message):
    """Logs message to both console and file."""
    print(message)
    logging.info(message)

def log_failed_hits(message):
    """Logs only failed hits."""
    print(message)
    failed_logging.error(message)

def get_a_records(domain):
    """Retrieves A records for the specified domain."""
    log_and_print(f"Retrieving A records for {domain}...")
    try:
        # Placeholder for actual logic to retrieve A records
        return []  # Replace with actual logic
    except Exception as e:
        log_failed_hits(f"[ERROR] Failed to retrieve A records for {domain}: {e}")
        return []

def get_ns_records(domain):
    """Retrieves NS records for the specified domain."""
    log_and_print(f"Retrieving NS records for {domain}...")
    try:
        # Placeholder for actual logic to retrieve NS records
        return []  # Replace with actual logic
    except Exception as e:
        log_failed_hits(f"[ERROR] Failed to retrieve NS records for {domain}: {e}")
        return []

def get_aaaa_records(domain):
    """Retrieves AAAA records for the specified domain."""
    log_and_print(f"Retrieving AAAA records for {domain}...")
    try:
        # Placeholder for actual logic to retrieve AAAA records
        return []  # Replace with actual logic
    except Exception as e:
        log_failed_hits(f"[ERROR] Failed to retrieve AAAA records for {domain}: {e}")
        return []

def get_mx_records(domain):
    """Retrieves MX records for the specified domain."""
    log_and_print(f"Retrieving MX records for {domain}...")
    try:
        # Placeholder for actual logic to retrieve MX records
        return []  # Replace with actual logic
    except Exception as e:
        log_failed_hits(f"[ERROR] Failed to retrieve MX records for {domain}: {e}")
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
        log_failed_hits(f"[ERROR] Sublist3r failed for {domain}: {result.stderr.strip()}")
        return []

def get_all_ips(domain):
    """Fetches all possible IP addresses associated with the given domain and its subdomains."""
    ip_addresses = []
    try:
        main_ip = socket.gethostbyname(domain)
        ip_addresses.append(main_ip)
    except socket.gaierror:
        log_failed_hits(f"[ERROR] Could not resolve domain: {domain}")

    subdomains = sublist3r_scan(domain)
    for subdomain in subdomains:
        try:
            sub_ip = socket.gethostbyname(subdomain)
            ip_addresses.append(sub_ip)
        except socket.gaierror:
            log_failed_hits(f"[ERROR] Could not resolve subdomain: {subdomain}")

    return list(set(ip_addresses))

def nmap_scan(target_ip):
    """Runs Nmap on the specified IP address."""
    log_and_print(f"Running Nmap scan on {target_ip}...")
    command = ['nmap', '-sV', target_ip]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode == 0:
        log_and_print(result.stdout)
    else:
        log_failed_hits(f"[ERROR] Nmap scan failed for {target_ip}: {result.stderr.strip()}")

def fetch_robots_txt(domain):
    """Fetches and displays the contents of robots.txt for the given domain."""
    try:
        response = subprocess.run(['curl', f'http://{domain}/robots.txt'], capture_output=True, text=True)
        if response.returncode == 0:
            log_and_print(response.stdout)
        else:
            log_failed_hits(f"[ERROR] Failed to fetch robots.txt for {domain}: {response.stderr.strip()}")
    except Exception as e:
        log_failed_hits(f"[ERROR] Exception occurred while fetching robots.txt for {domain}: {e}")

def run_dnsrecon(domain):
    """Runs DNSRecon on the specified domain."""
    log_and_print(f"Running DNSRecon for {domain}...")
    command = ['dnsrecon', '-d', domain, '-a']
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode == 0:
        log_and_print(result.stdout)
    else:
        log_failed_hits(f"[ERROR] DNSRecon scan failed for {domain}: {result.stderr.strip()}")

def run_dnsenum(domain):
    """Runs DNSEnum on the specified domain."""
    log_and_print(f"Running DNSEnum for {domain}...")
    command = ['dnsenum', '--no-brute', domain]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode == 0:
        log_and_print(result.stdout)
    else:
        log_failed_hits(f"[ERROR] DNSEnum scan failed for {domain}: {result.stderr.strip()}")

