#!/usr/bin/env python3
# Website Information Extractor
# Extracts comprehensive information about a website including domain, IP, DNS, WHOIS, ASN, blacklist status

import socket
import whois
import dns.resolver
import requests
import json
import ipaddress
import time
import re
import sys
import ssl
from urllib.parse import urlparse
from datetime import datetime
from ipwhois import IPWhois
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

class WebsiteInfoExtractor:
    def __init__(self, url, timeout=10, verbose=False):
        """
        Initialize the Website Information Extractor
        
        Args:
            url (str): The URL or domain to analyze
            timeout (int): Timeout in seconds for network requests
            verbose (bool): Whether to print verbose output
        """
        self.timeout = timeout
        self.verbose = verbose
        self.results = {
            "domain": "",
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "hosting_info": {
                "provider": "",
                "server_location": "",
                "server_type": ""
            },
            "dns_records": {},
            "whois_data": {},
            "asn_info": {},
            "blacklist_status": {},
            "related_domains": []
        }
        
        # Process the input URL/domain
        self.url = self._process_url(url)
        self.domain = self._extract_domain(self.url)
        self.results["domain"] = self.domain
        
        # User agent for requests
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def _process_url(self, url):
        """Process and normalize the input URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url
    
    def _extract_domain(self, url):
        """Extract domain from URL"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Handle cases where netloc might include port or credentials
        domain = domain.split(':')[0]  # Remove port if present
        domain = domain.split('@')[-1]  # Remove credentials if present
        
        # Handle IPv6 addresses in square brackets
        if domain.startswith('[') and ']' in domain:
            # Extract IPv6 address from square brackets
            ipv6_match = re.match(r'\[(.*?)\]', domain)
            if ipv6_match:
                domain = ipv6_match.group(1)
                return domain
        
        # Handle numeric IP addresses in different formats
        if re.match(r'^(\d+)$', domain):
            # This could be a decimal IP address
            try:
                # Convert decimal to dotted quad notation
                n = int(domain)
                domain = f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"
            except:
                pass
        
        # Handle hexadecimal notation (0xC0A80001)
        elif domain.lower().startswith('0x'):
            try:
                # Convert hex to dotted quad notation
                n = int(domain, 16)
                domain = f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"
            except:
                pass
        
        # Handle IDN (Internationalized Domain Names)
        try:
            if domain.startswith('xn--') or any(ord(c) > 127 for c in domain):
                domain = domain.encode('idna').decode('ascii')
        except Exception as e:
            if self.verbose:
                print(f"Warning: Error handling IDN: {e}")
        
        return domain
    
    def _log(self, message):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            print(f"[INFO] {message}")
    
    def extract_ip_addresses(self):
        """Extract IPv4 and IPv6 addresses for the domain"""
        self._log(f"Extracting IP addresses for {self.domain}")
        
        # Get IPv4 addresses
        try:
            ipv4_info = socket.getaddrinfo(self.domain, None, socket.AF_INET)
            self.results["ipv4_addresses"] = list(set(info[4][0] for info in ipv4_info))
        except socket.gaierror as e:
            self._log(f"Error getting IPv4 addresses: {e}")
        
        # Get IPv6 addresses
        try:
            ipv6_info = socket.getaddrinfo(self.domain, None, socket.AF_INET6)
            self.results["ipv6_addresses"] = list(set(info[4][0] for info in ipv6_info))
        except socket.gaierror as e:
            self._log(f"Error getting IPv6 addresses: {e}")
        
        return self.results["ipv4_addresses"], self.results["ipv6_addresses"]
    
    def extract_dns_records(self):
        """Extract various DNS records for the domain"""
        self._log(f"Extracting DNS records for {self.domain}")
        
        dns_record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'CAA']
        dns_results = {}
        
        for record_type in dns_record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                records = []
                
                for answer in answers:
                    if record_type == 'MX':
                        records.append(f"{answer.preference} {answer.exchange}")
                    elif record_type == 'SOA':
                        records.append(f"mname: {answer.mname}, rname: {answer.rname}, " +
                                     f"serial: {answer.serial}, refresh: {answer.refresh}, " +
                                     f"retry: {answer.retry}, expire: {answer.expire}, " +
                                     f"minimum: {answer.minimum}")
                    else:
                        records.append(str(answer))
                
                if records:
                    dns_results[record_type] = records
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
                self._log(f"No {record_type} records found: {e}")
            except Exception as e:
                self._log(f"Error querying {record_type} records: {e}")
        
        self.results["dns_records"] = dns_results
        return dns_results
    
    def extract_whois_data(self):
        """Extract WHOIS data for the domain"""
        self._log(f"Extracting WHOIS data for {self.domain}")
        
        whois_data = {}
        try:
            w = whois.whois(self.domain)
            
            # Handle common WHOIS fields
            whois_data["registrar"] = w.registrar
            
            # Handle creation date
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    whois_data["creation_date"] = str(w.creation_date[0])
                else:
                    whois_data["creation_date"] = str(w.creation_date)
            
            # Handle expiration date
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    whois_data["expiration_date"] = str(w.expiration_date[0])
                else:
                    whois_data["expiration_date"] = str(w.expiration_date)
            
            # Add updated date
            if w.updated_date:
                if isinstance(w.updated_date, list):
                    whois_data["updated_date"] = str(w.updated_date[0])
                else:
                    whois_data["updated_date"] = str(w.updated_date)
            
            # Add nameservers
            if w.name_servers:
                if isinstance(w.name_servers, list):
                    whois_data["nameservers"] = [ns.lower() for ns in w.name_servers]
                else:
                    whois_data["nameservers"] = [w.name_servers.lower()]
            
            # Add registrant info if available and not private
            if hasattr(w, 'registrant') and w.registrant:
                whois_data["registrant"] = w.registrant
            
            # Add status
            if w.status:
                if isinstance(w.status, list):
                    whois_data["status"] = w.status
                else:
                    whois_data["status"] = [w.status]
            
            # Add country
            if hasattr(w, 'country') and w.country:
                whois_data["country"] = w.country
            
            # Add organization
            if hasattr(w, 'org') and w.org:
                whois_data["organization"] = w.org
                
        except Exception as e:
            self._log(f"Error extracting WHOIS data: {e}")
        
        self.results["whois_data"] = whois_data
        return whois_data
    
    def extract_hosting_info(self):
        """Extract hosting provider and server information"""
        self._log(f"Extracting hosting information for {self.domain}")
        
        hosting_info = {
            "provider": "Unknown",
            "server_location": "Unknown",
            "server_type": "Unknown"
        }
        
        # Get server details from HTTP headers
        try:
            response = requests.get(self.url, headers=self.headers, timeout=self.timeout, verify=False)
            
            # Get server type
            if 'Server' in response.headers:
                hosting_info["server_type"] = response.headers['Server']
            
            # Try to get additional info from headers
            if 'X-Powered-By' in response.headers:
                hosting_info["technology"] = response.headers['X-Powered-By']
            
            # Try to get hosting provider from IP info if we have IPv4 addresses
            if self.results["ipv4_addresses"]:
                ip = self.results["ipv4_addresses"][0]
                ip_info = self._get_ip_geolocation(ip)
                
                if ip_info:
                    hosting_info["server_location"] = self._format_location(ip_info)
                    if "org" in ip_info:
                        hosting_info["provider"] = ip_info["org"]
        
        except requests.RequestException as e:
            self._log(f"Error fetching hosting info: {e}")
        
        self.results["hosting_info"] = hosting_info
        return hosting_info
    
    def _get_ip_geolocation(self, ip):
        """Get geolocation info for an IP address"""
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            self._log(f"Error getting IP geolocation: {e}")
        return None
    
    def _format_location(self, ip_info):
        """Format location info from IP geolocation data"""
        location_parts = []
        for field in ["city", "region", "country"]:
            if field in ip_info and ip_info[field]:
                location_parts.append(ip_info[field])
        
        if location_parts:
            return ", ".join(location_parts)
        return "Unknown"
    
    def extract_asn_info(self):
        """Extract ASN (Autonomous System Number) information"""
        self._log(f"Extracting ASN information")
        
        asn_info = {}
        
        # Use the first IPv4 address if available
        if not self.results["ipv4_addresses"]:
            self.extract_ip_addresses()
            
        if self.results["ipv4_addresses"]:
            ip = self.results["ipv4_addresses"][0]
            try:
                obj = IPWhois(ip)
                results = obj.lookup_rdap()
                
                if results:
                    asn_info["asn"] = results.get("asn")
                    asn_info["asn_cidr"] = results.get("asn_cidr")
                    asn_info["asn_country_code"] = results.get("asn_country_code")
                    asn_info["asn_description"] = results.get("asn_description")
                    
                    # Get network info
                    if "network" in results:
                        network = results["network"]
                        asn_info["network_name"] = network.get("name")
                        asn_info["network_range"] = f"{network.get('start_address')} - {network.get('end_address')}"
            
            except Exception as e:
                self._log(f"Error getting ASN info: {e}")
        
        self.results["asn_info"] = asn_info
        return asn_info
    
    def check_blacklist_status(self):
        """Check if the domain or IP is in various blacklists"""
        self._log(f"Checking blacklist status for {self.domain}")
        
        blacklist_status = {
            "domain_blacklisted": False,
            "ip_blacklisted": False,
            "blacklists": []
        }
        
        # We'll use a few free APIs to check blacklists
        # For a production system, you might want to use a paid service with better coverage
        
        # Check domain using Google Safe Browsing API (this would require an API key)
        # For this example, we'll just simulate the check
        
        # Check IP reputation using AbuseIPDB (would require API key)
        # Again, this is just a simulation for the example
        
        # For demonstration purposes, we'll use a simplified check
        blacklist_domains = [
            "spam.com", "malware.org", "phishing.net", "scam.io",
            "blacklist.com", "malicious.xyz", "blocked.site"
        ]
        
        is_blacklisted = any(bl_domain in self.domain for bl_domain in blacklist_domains)
        blacklist_status["domain_blacklisted"] = is_blacklisted
        
        if is_blacklisted:
            blacklist_status["blacklists"].append("Example Blacklist")
        
        # In a real implementation, you would check multiple blacklist services
        # such as Spamhaus, SURBL, PhishTank, etc.
        
        self.results["blacklist_status"] = blacklist_status
        return blacklist_status
    
    def find_related_domains(self):
        """Find domain neighbors and related domains"""
        self._log(f"Finding related domains for {self.domain}")
        
        related_domains = []
        
        # Skip IP addresses for related domains
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', self.domain):
            self._log("Domain is an IP address, skipping related domains search")
            self.results["related_domains"] = []
            return []
            
        # Skip non-standard TLDs or numerics
        try:
            # Extract TLD and domain name without TLD
            domain_parts = self.domain.split('.')
            if len(domain_parts) < 2:
                self._log("Domain does not have enough parts for TLD extraction")
                self.results["related_domains"] = []
                return []
                
            tld = domain_parts[-1]
            domain_name = domain_parts[-2]
            
            # Generate potential related domains
            # 1. Same domain name with different TLDs
            common_tlds = ['com', 'net', 'org', 'io', 'co', 'info', 'biz', 'app']
            for tld_variant in common_tlds:
                if tld_variant != tld:
                    related_domains.append(f"{domain_name}.{tld_variant}")
            
            # 2. Domain typos and variations - just a few examples
            typo_domains = []
            
            # Character substitution
            substitutions = {
                'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'], 
                'o': ['0'], 's': ['5', '$'], 't': ['7']
            }
            
            for char in domain_name:
                if char.lower() in substitutions:
                    for substitute in substitutions[char.lower()]:
                        typo_domain = domain_name.replace(char, substitute)
                        typo_domains.append(f"{typo_domain}.{tld}")
            
            # Character omission
            for i in range(len(domain_name)):
                typo_domain = domain_name[:i] + domain_name[i+1:]
                if len(typo_domain) > 2:  # Skip very short domains
                    typo_domains.append(f"{typo_domain}.{tld}")
            
            # Double character
            for i in range(len(domain_name)):
                typo_domain = domain_name[:i] + domain_name[i] + domain_name[i:]
                typo_domains.append(f"{typo_domain}.{tld}")
            
            # Add a few examples to the results (would be too many otherwise)
            for typo in typo_domains[:5]:
                related_domains.append(typo)
        except Exception as e:
            self._log(f"Error generating related domains: {e}")
        
        self.results["related_domains"] = related_domains
        return related_domains
    
    def extract_ssl_info(self):
        """Extract SSL certificate information if the site uses HTTPS"""
        self._log(f"Extracting SSL certificate information for {self.domain}")
        
        ssl_info = {
            "has_ssl": False,
            "issuer": "",
            "valid_from": "",
            "valid_until": "",
            "san_domains": []
        }
        
        if self.url.startswith('https://'):
            try:
                context = ssl.create_default_context()
                with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        cert = ssock.getpeercert()
                        
                        ssl_info["has_ssl"] = True
                        
                        # Get issuer
                        issuer_dict = dict(x[0] for x in cert['issuer'])
                        if 'organizationName' in issuer_dict:
                            ssl_info["issuer"] = issuer_dict['organizationName']
                        elif 'commonName' in issuer_dict:
                            ssl_info["issuer"] = issuer_dict['commonName']
                        
                        # Get validity dates
                        ssl_info["valid_from"] = cert['notBefore']
                        ssl_info["valid_until"] = cert['notAfter']
                        
                        # Get Subject Alternative Names (SAN)
                        if 'subjectAltName' in cert:
                            sans = cert['subjectAltName']
                            san_domains = []
                            for san_type, san_value in sans:
                                if san_type == 'DNS':
                                    san_domains.append(san_value)
                            ssl_info["san_domains"] = san_domains
            
            except Exception as e:
                self._log(f"Error extracting SSL info: {e}")
        
        self.results["ssl_info"] = ssl_info
        return ssl_info
    
    def extract_all_info(self):
        """Extract all available information about the website"""
        self._log(f"Starting comprehensive extraction for {self.domain}")
        
        # Extract information in order
        try:
            # Use ThreadPoolExecutor for parallel extraction when possible
            with ThreadPoolExecutor(max_workers=3) as executor:
                # These can run in parallel
                ip_future = executor.submit(self.extract_ip_addresses)
                dns_future = executor.submit(self.extract_dns_records)
                whois_future = executor.submit(self.extract_whois_data)
                
                # Wait for IP addresses to be available
                ip_future.result()
                
                # These may depend on IP info
                hosting_future = executor.submit(self.extract_hosting_info)
                asn_future = executor.submit(self.extract_asn_info)
                blacklist_future = executor.submit(self.check_blacklist_status)
                ssl_future = executor.submit(self.extract_ssl_info)
                
                # Wait for all to complete
                hosting_future.result()
                asn_future.result()
                blacklist_future.result()
                dns_future.result()
                whois_future.result()
                ssl_future.result()
            
            # Find related domains (less time-sensitive)
            self.find_related_domains()
            
        except Exception as e:
            print(f"Error during information extraction: {e}")
        
        return self.results


def pretty_print_results(results):
    """Format and print the results in a more readable way"""
    print("\n" + "="*60)
    print(f"WEBSITE INFORMATION: {results['domain']}")
    print("="*60)
    
    # Print domain and IP addresses
    print("\n[DOMAIN AND IP ADDRESSES]")
    print(f"Domain: {results['domain']}")
    if results["ipv4_addresses"]:
        print(f"IPv4 Addresses: {', '.join(results['ipv4_addresses'])}")
    if results["ipv6_addresses"]:
        print(f"IPv6 Addresses: {', '.join(results['ipv6_addresses'])}")
    
    # Print hosting information
    print("\n[HOSTING INFORMATION]")
    hosting = results["hosting_info"]
    print(f"Provider: {hosting.get('provider', 'Unknown')}")
    print(f"Server Location: {hosting.get('server_location', 'Unknown')}")
    print(f"Server Type: {hosting.get('server_type', 'Unknown')}")
    
    # Print DNS records
    print("\n[DNS RECORDS]")
    for record_type, records in results["dns_records"].items():
        print(f"{record_type} Records:")
        for record in records:
            print(f"  {record}")
    
    # Print WHOIS data
    print("\n[WHOIS INFORMATION]")
    for key, value in results["whois_data"].items():
        if isinstance(value, list):
            print(f"{key.replace('_', ' ').title()}: {', '.join(str(v) for v in value)}")
        else:
            print(f"{key.replace('_', ' ').title()}: {value}")
    
    # Print ASN information
    print("\n[ASN INFORMATION]")
    asn = results["asn_info"]
    if asn:
        for key, value in asn.items():
            print(f"{key.replace('_', ' ').title()}: {value}")
    else:
        print("No ASN information available")
    
    # Print SSL information if available
    if "ssl_info" in results:
        print("\n[SSL CERTIFICATE]")
        ssl = results["ssl_info"]
        print(f"Has SSL: {ssl.get('has_ssl', False)}")
        if ssl.get('has_ssl', False):
            print(f"Issuer: {ssl.get('issuer', 'Unknown')}")
            print(f"Valid From: {ssl.get('valid_from', 'Unknown')}")
            print(f"Valid Until: {ssl.get('valid_until', 'Unknown')}")
            if ssl.get('san_domains'):
                print(f"SAN Domains: {', '.join(ssl.get('san_domains', []))}")
    
    # Print blacklist status
    print("\n[BLACKLIST STATUS]")
    blacklist = results["blacklist_status"]
    print(f"Domain Blacklisted: {blacklist.get('domain_blacklisted', False)}")
    print(f"IP Blacklisted: {blacklist.get('ip_blacklisted', False)}")
    if blacklist.get('blacklists'):
        print(f"Blacklists: {', '.join(blacklist.get('blacklists', []))}")
    
    # Print related domains
    print("\n[RELATED DOMAINS]")
    if results["related_domains"]:
        for domain in results["related_domains"]:
            print(f"  {domain}")
    else:
        print("No related domains found")
    
    print("\n" + "="*60 + "\n")


def main():
    # Get URL from command line or prompt
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("Enter a URL or domain to analyze: ")
    
    print(f"\nAnalyzing {url}...\n")
    start_time = time.time()
    
    try:
        # Initialize extractor with verbose output
        extractor = WebsiteInfoExtractor(url, verbose=True)
        
        # Extract all information
        results = extractor.extract_all_info()
        
        # Print results
        pretty_print_results(results)
        
        print(f"Analysis completed in {time.time() - start_time:.2f} seconds")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 