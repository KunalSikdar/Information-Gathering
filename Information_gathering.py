#!/usr/bin/env python3
import os
from time import process_time_ns
import whois
import dns.resolver
import dns.exception
import shodan
import requests
import sys
import argparse
import socket
import json
from typing import Optional


def print_banner():
    print("""
██╗  ██╗██╗   ██╗███╗   ██╗ █████╗ ██╗     
██║ ██╔╝██║   ██║████╗  ██║██╔══██╗██║     
█████╔╝ ██║   ██║██╔██╗ ██║███████║██║     
██╔═██╗ ██║   ██║██║╚██╗██║██╔══██║██║     
██║  ██╗╚██████╔╝██║ ╚████║██║  ██║███████╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
    Advanced Information Gathering Tool
    """)


def get_whois_info(domain: str) -> None:
    """Fetch WHOIS information for the domain."""
    print("[+] Fetching WHOIS information...")
    try:
        w = whois.whois(domain)
        print("[+] WHOIS information found:")
        print(f"    Domain Name: {getattr(w, 'name', 'N/A')}")
        print(f"    Registrar: {getattr(w, 'registrar', 'N/A')}")
        print(f"    Creation Date: {getattr(w, 'creation_date', 'N/A')}")
        print(f"    Expiration Date: {getattr(w, 'expiration_date', 'N/A')}")
        print(f"    Registrant: {getattr(w, 'registrant', 'N/A')}")
        print(f"    Registrant Country: {getattr(w, 'registrant_country', 'N/A')}")
        print()
    except Exception as e:
        print(f"[!] WHOIS lookup failed: {str(e)}")


def get_dns_info(domain: str) -> None:
    """Fetch DNS records for the domain."""
    print("[+] Enumerating DNS records...")
    record_types = ['A', 'NS', 'MX', 'TXT', 'CNAME', 'SOA']

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            print(f"[+] {record_type} Records:")
            for rdata in answers:
                print(f"    {rdata.to_text().strip()}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            pass
        except Exception as e:
            print(f"[!] Error resolving {record_type}: {str(e)}")
    print()


def get_geolocation_info(domain: str) -> None:
    """Fetch geolocation information for the domain's IP."""
    print("[+] Fetching geolocation information...")
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f"https://geolocation-db.com/json/{ip}", timeout=10).json()

        if response.get('country_code'):
            print("[+] Geolocation information:")
            print(f"    IP Address: {ip}")
            print(f"    Country: {response.get('country_name', 'N/A')}")
            print(f"    City: {response.get('city', 'N/A')}")
            print(f"    State: {response.get('state', 'N/A')}")
            print(f"    Latitude: {response.get('latitude', 'N/A')}")
            print(f"    Longitude: {response.get('longitude', 'N/A')}")
        else:
            print("[!] No geolocation data available")
    except Exception as e:
        print(f"[!] Geolocation lookup failed: {str(e)}")
    print()


def get_shodan_info(ip: str, api_key: str) -> None:
    """Fetch Shodan information for the IP address."""
    if not api_key or api_key == "YOUR_SHODAN_API_KEY":
        print("[!] Shodan API key not configured. Skipping Shodan search.")
        return

    print("[+] Searching Shodan...")
    try:
        api = shodan.Shodan(api_key)
        results = api.search(ip)

        print(f"[+] Shodan results found: {results['total']} total matches")
        for result in results['matches'][:5]:  # Limit to first 5 results
            print(f"\n    IP: {result.get('ip_str', 'N/A')}")
            print(f"    Port: {result.get('port', 'N/A')}")
            print(f"    OS: {result.get('os', 'N/A')}")
            print(f"    Product: {result.get('product', 'N/A')}")
            print(f"    Data: {result.get('data', 'N/A')[:200]}...")
        print()
    except shodan.APIError as e:
        print(f"[!] Shodan API error: {str(e)}")
    except Exception as e:
        print(f"[!] Shodan search failed: {str(e)}")


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Information Gathering Tool for reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 info_gather.py -d example.com
  python3 info_gather.py -d example.com -s 8.8.8.8 --shodan-api YOUR_API_KEY
        """
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain for footprinting")
    parser.add_argument("-s", "--shodan-ip", dest="shodan_ip", help="IP address for Shodan search")
    parser.add_argument("--shodan-api", help="Shodan API key (optional, set as env var SHODAN_API_KEY)")

    args = parser.parse_args()

    # Get Shodan API key from args or environment
    api_key = args.shodan_api or os.getenv('SHODAN_API_KEY')

    print_banner()
    start_time = process_time_ns()

    get_whois_info(args.domain)
    get_dns_info(args.domain)
    get_geolocation_info(args.domain)

    if args.shodan_ip:
        get_shodan_info(args.shodan_ip, api_key)

    elapsed = (process_time_ns() - start_time) / 1e9
    print(f"[+] Reconnaissance complete in {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()