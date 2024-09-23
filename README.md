# DReco

## Description
DReco is a comprehensive domain enumeration and scanning tool that integrates multiple utilities for assessing domain-related information.

## Features
- Retrieve A, NS, AAAA, and MX DNS records.
- Enumerate subdomains using Sublist3r.
- Scan for open ports using Nmap.
- Fetch the contents of the `robots.txt` file.
- Network information related to the domain.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/wodeh/dreco.git
   cd dreco
   Create Virtual Environment if needed -- 
        python -m venv:venv
        source venv/bin/activate

  pip install -r requirements.txt
  pip install .

## Running dreco
Simply type: dreco

