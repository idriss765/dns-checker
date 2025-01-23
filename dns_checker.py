#!/usr/bin/env python3
import sys
import dns.resolver
import dns.dnssec
import dns.rdatatype
import whois
from datetime import datetime

def get_soa_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, 'SOA')
        return {
            'primary_ns': answers[0].mname.to_text().rstrip('.'),
            'responsible': answers[0].rname.to_text().rstrip('.'),
            'serial': answers[0].serial,
            'refresh': answers[0].refresh,
            'retry': answers[0].retry,
            'expire': answers[0].expire,
            'minimum': answers[0].minimum
        }
    except Exception as e:
        print(f"Error getting SOA for {domain}: {e}")
        return None

def check_registration(domain):
    try:
        w = whois.whois(domain)
        return {
            'status': w.status,
            'expiration_date': w.expiration_date.strftime('%Y-%m-%d') if w.expiration_date else None
        }
    except Exception as e:
        print(f"Error checking registration for {domain}: {e}")
        return None

def check_email_records(domain):
    records = {}
    try:
        # Check MX records
        mx = dns.resolver.resolve(domain, 'MX')
        records['MX'] = [str(r.exchange) for r in mx]
    except Exception:
        records['MX'] = None
        
    try:
        # Check SPF record
        spf = dns.resolver.resolve(domain, 'TXT')
        records['SPF'] = [r.to_text() for r in spf if 'v=spf1' in r.to_text()]
    except Exception:
        records['SPF'] = None
        
    try:
        # Check DKIM record
        dkim = dns.resolver.resolve(f'default._domainkey.{domain}', 'TXT')
        records['DKIM'] = [r.to_text() for r in dkim]
    except Exception:
        records['DKIM'] = None
        
    try:
        # Check DMARC record
        dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        records['DMARC'] = [r.to_text() for r in dmarc]
    except Exception:
        records['DMARC'] = None
        
    return records

def validate_dnssec(domain, record_type):
    try:
        # First verify the record exists
        answer = dns.resolver.resolve(domain, record_type)
        name = answer.canonical_name
        
        # Then check for RRSIG
        try:
            rrsig = dns.resolver.resolve(name, dns.rdatatype.RRSIG, raise_on_no_answer=False)
            if rrsig.rrset:
                return True
            return False
        except dns.resolver.NoNameservers:
            # Some resolvers don't support DNSSEC queries
            return False
        except Exception as e:
            print(f"DNSSEC validation error for {domain} ({record_type}): {e}")
            return False
            
    except dns.resolver.NXDOMAIN:
        print(f"Domain {domain} does not exist")
        return False
    except dns.resolver.NoAnswer:
        print(f"No {record_type} record found for {domain}")
        return False
    except Exception as e:
        print(f"Error validating DNSSEC for {domain} ({record_type}): {e}")
        return False

def main(domain):
    print(f"Checking DNS records for: {domain}")
    
    # Get SOA record
    soa = get_soa_domain(domain)
    if soa:
        print("\nSOA Record:")
        print(f"Primary Nameserver: {soa['primary_ns']}")
        print(f"Responsible Email: {soa['responsible']}")
        print(f"Serial: {soa['serial']}")
        print(f"Refresh: {soa['refresh']}")
        print(f"Retry: {soa['retry']}")
        print(f"Expire: {soa['expire']}")
        print(f"Minimum TTL: {soa['minimum']}")
    
    # Check domain registration
    reg_info = check_registration(domain)
    if reg_info:
        print("\nRegistration Info:")
        print(f"Status: {reg_info['status']}")
        print(f"Expiration: {reg_info['expiration_date']}")
    
    # Check email records
    email_records = check_email_records(domain)
    print("\nEmail Records:")
    for record_type, values in email_records.items():
        print(f"{record_type}: {values}")
    
    # Validate DNSSEC
    print("\nDNSSEC Validation:")
    print(f"Domain: {validate_dnssec(domain, 'A')}")
    print(f"SOA: {validate_dnssec(soa['primary_ns'], 'SOA')}" if soa else "SOA: No SOA record found")
    
    # Validate NS records
    try:
        ns = dns.resolver.resolve(domain, 'NS')
        for nameserver in ns:
            print(f"NS {nameserver}: {validate_dnssec(str(nameserver), 'A')}")
    except Exception as e:
        print(f"Error validating NS records: {e}")
    
    # Validate email records
    if email_records['MX']:
        for mx in email_records['MX']:
            print(f"MX {mx}: {validate_dnssec(mx, 'A')}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 dns_checker.py <domain>")
        sys.exit(1)
        
    domain = sys.argv[1]
    main(domain)
