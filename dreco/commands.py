import subprocess
import socket
import logging
import dns.resolver

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

def log_and_print_error(message):
    """Logs error message to a separate error log file."""
    with open('scan_errors.log', 'a') as error_log:
        error_log.write(f"{message}\n")

def get_a_records(domain):
    """Retrieves A records for the specified domain."""
    log_and_print(f"Retrieving A records for {domain}...")
    try:
        answers = dns.resolver.resolve(domain, 'A')
        records = [answer.to_text() for answer in answers]
        log_and_print(f"[SUCCESS] A records for {domain}: {', '.join(records)}")
        return records
    except Exception as e:
        log_and_print_error(f"[ERROR] Failed to retrieve A records for {domain}: {e}")
        return []

def get_ns_records(domain):
    """Retrieves NS records for the specified domain."""
    log_and_print(f"Retrieving NS records for {domain}...")
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        records = [answer.to_text() for answer in answers]
        log_and_print(f"[SUCCESS] NS records for {domain}: {', '.join(records)}")
        return records
    except Exception as e:
        log_and_print_error(f"[ERROR] Failed to retrieve NS records for {domain}: {e}")
        return []

def get_aaaa_records(domain):
    """Retrieves AAAA records for the specified domain."""
    log_and_print(f"Retrieving AAAA records for {domain}...")
    try:
        answers = dns.resolver.resolve(domain, 'AAAA')
        records = [answer.to_text() for answer in answers]
        log_and_print(f"[SUCCESS] AAAA records for {domain}: {', '.join(records)}")
        return records
    except Exception as e:
        log_and_print_error(f"[ERROR] Failed to retrieve AAAA records for {domain}: {e}")
        return []

def get_mx_records(domain):
    """Retrieves MX records for the specified domain."""
    log_and_print(f"Retrieving MX records for {domain}...")
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        records = [(answer.exchange.to_text(), answer.preference) for answer in answers]
        log_and_print(f"[SUCCESS] MX records for {domain}: {', '.join([f'{pref} {exch}' for exch, pref in records])}")
        return records
    except Exception as e:
        log_and_print_error(f"[ERROR] Failed to retrieve MX records for {domain}: {e}")
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
        log_and_print(f"[SUCCESS] Found subdomains for {domain}: {', '.join(subdomains)}")
        return subdomains
    else:
        log_and_print_error(f"[ERROR] Sublist3r failed for {domain}: {result.stderr.strip()}")
        return []

def get_all_ips(domain):
    """Fetches all possible IP addresses associated with the given domain and its subdomains."""
    ip_addresses = []
    try:
        main_ip = socket.gethostbyname(domain)
        ip_addresses.append(main_ip)
    except socket.gaierror:
        log_and_print_error(f"[ERROR] Could not resolve domain: {domain}")

    subdomains = sublist3r_scan(domain)
    for subdomain in subdomains:
        try:
            sub_ip = socket.gethostbyname(subdomain)
            ip_addresses.append(sub_ip)
        except socket.gaierror:
            log_and_print_error(f"[ERROR] Could not resolve subdomain: {subdomain}")

    return list(set(ip_addresses))

def nmap_scan(target_ip):
    """Runs Nmap on the specified IP address."""
    log_and_print(f"Running Nmap scan on {target_ip}...")
    command = ['nmap', '-sV', target_ip]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode == 0:
        log_and_print(result.stdout)
    else:
        log_and_print_error(f"[ERROR] Nmap scan failed for {target_ip}: {result.stderr.strip()}")

def fetch_robots_txt(domain):
    """Fetches and displays the contents of robots.txt for the given domain."""
    try:
        response = subprocess.run(['curl', f'http://{domain}/robots.txt'], capture_output=True, text=True)
        if response.returncode == 0:
            log_and_print(f"[SUCCESS] robots.txt for {domain}:\n{response.stdout}")
        else:
            log_and_print_error(f"[ERROR] Failed to fetch robots.txt for {domain}: {response.stderr.strip()}")
    except Exception as e:
        log_and_print_error(f"[ERROR] Exception occurred while fetching robots.txt for {domain}: {e}")

def run_dnsrecon(domain):
    """Runs DNSRecon on the specified domain."""
    log_and_print(f"Running DNSRecon for {domain}...")
    command = ['dnsrecon', '-d', domain, '-a']
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode == 0:
        log_and_print(result.stdout)
    else:
        log_and_print_error(f"[ERROR] DNSRecon scan failed for {domain}: {result.stderr.strip()}")

def run_dnsenum(domain):
    """Runs DNSEnum on the specified domain."""
    log_and_print(f"Running DNSEnum for {domain}...")
    command = ['dnsenum', '--no-brute', domain]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode == 0:
        log_and_print(result.stdout)
    else:
        log_and_print_error(f"[ERROR] DNSEnum scan failed for {domain}: {result.stderr.strip()}")

