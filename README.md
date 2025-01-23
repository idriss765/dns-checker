# DNS Checker

A Python script to analyze DNS records and validate DNSSEC for a given domain.

## Features

- Retrieves SOA record details (primary nameserver, responsible email, serial, refresh, retry, expire, minimum TTL)
- Checks domain registration status and expiration date
- Verifies email-related DNS records (MX, SPF, DKIM, DMARC)
- Validates DNSSEC for domain, SOA, NS, and MX records

## Requirements

- Python 3.6+
- dnspython (`pip install dnspython`)
- python-whois (`pip install python-whois`)

## Installation

1. Clone this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

```bash
python3 dns_checker.py <domain>
```

Example:
```bash
python3 dns_checker.py example.com
```

## Output

The script will display:
- SOA record details
- Domain registration information
- Email-related DNS records
- DNSSEC validation results

## License

MIT License
