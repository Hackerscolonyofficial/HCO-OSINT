#!/usr/bin/env python3
"""
HCO OSINT Tool - Advanced Open Source Intelligence Tool
With authentication system, countdown, and YouTube redirection
"""

import os
import sys
import time
import json
import socket
import requests
import whois
import dns.resolver
from urllib.parse import urlparse
import re
import threading
from datetime import datetime

# Check if running on Termux
IS_TERMUX = os.path.exists('/data/data/com.termux/files/usr')

# Colors for output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Tool states
UNLOCKED = 0
COUNTDOWN = 1
LOCKED = 2
SUCCESS = 3

# Initialize tool state
tool_state = LOCKED
countdown_time = 10  # seconds
start_time = 0
youtube_url = "https://www.youtube.com/channel/UC9P7GSPQpPxjc6Uu-cx-F8w"

# Check and install required packages
def check_dependencies():
    required_packages = ['requests', 'python-whois', 'dnspython']
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'python-whois':
                import whois
            elif package == 'dnspython':
                import dns.resolver
            else:
                __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"{Colors.YELLOW}Installing missing dependencies...{Colors.END}")
        if IS_TERMUX:
            for package in missing_packages:
                os.system(f"pip install {package}")
        else:
            os.system(f"pip3 install {' '.join(missing_packages)}")
        
        # Check again after installation
        for package in missing_packages:
            try:
                __import__(package.replace('-', '_'))
            except ImportError:
                print(f"{Colors.RED}Failed to install {package}. Please install it manually.{Colors.END}")
                return False
    return True

# Authentication system
def show_lock_screen():
    os.system('clear')
    print(f"\n{Colors.RED}{Colors.BOLD}╔{'═'*60}╗{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}║{'TOOL IS LOCKED! 🔐':^60}║{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}║{'═'*60}║{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}║{'Subscribe to our YouTube channel and':^60}║{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}║{'click the bell icon to unlock the tool! 🔓':^60}║{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}║{'═'*60}║{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}║{'YouTube: Hackers Colony Official':^60}║{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}╚{'═'*60}╝{Colors.END}")
    print(f"\n{Colors.CYAN}1. Subscribe on YouTube")
    print(f"2. I've already subscribed (Unlock)")
    print(f"3. Exit{Colors.END}")
    
    try:
        choice = input(f"\n{Colors.YELLOW}Select option: {Colors.END}")
        return choice
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Operation cancelled. Exiting...{Colors.END}")
        sys.exit(0)

def show_countdown():
    os.system('clear')
    print(f"\n{Colors.BLUE}{Colors.BOLD}╔{'═'*60}╗{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}║{'REDIRECTING TO YOUTUBE...':^60}║{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}╚{'═'*60}╝{Colors.END}")
    
    # Open YouTube channel
    try:
        import webbrowser
        webbrowser.open(youtube_url)
        print(f"{Colors.GREEN}✓ YouTube channel opened in browser{Colors.END}")
    except:
        print(f"{Colors.YELLOW}Please visit: {youtube_url}{Colors.END}")
    
    # Countdown animation
    print(f"\n{Colors.GREEN}{Colors.BOLD}Please subscribe and click the bell icon!{Colors.END}")
    print(f"{Colors.YELLOW}Return to this tool after subscribing.{Colors.END}")
    print()
    
    for i in range(countdown_time, 0, -1):
        minutes = i // 60
        seconds = i % 60
        countdown_str = f"{minutes:02d}:{seconds:02d}"
        
        print(f"{Colors.RED}{Colors.BOLD}⏰ Time remaining: {countdown_str}{Colors.END}", end='\r')
        time.sleep(1)
    
    print(f"{Colors.RED}{Colors.BOLD}⏰ Time remaining: 00:00{' '*10}{Colors.END}")
    return True

def show_unlock_screen():
    os.system('clear')
    print(f"\n{Colors.BLUE}{Colors.BOLD}╔{'═'*60}╗{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}║{'TOOL UNLOCKED! 🔓':^60}║{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}╚{'═'*60}╝{Colors.END}")
    
    # Draw blue box with red text
    print(f"\n{Colors.BLUE}{Colors.BOLD}╔{'═'*40}╗{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}║{Colors.RED}{'HCO OSINT by Azhar':^40}{Colors.BLUE}║{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}╚{'═'*40}╝{Colors.END}")
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}Thank you for subscribing!{Colors.END}")
    print(f"{Colors.CYAN}You now have full access to the HCO OSINT Tool.{Colors.END}")
    
    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")
    return True

# Advanced OSINT functions
def advanced_domain_info(domain):
    print(f"\n{Colors.CYAN}{Colors.BOLD}[+] Advanced Domain Analysis for: {domain}{Colors.END}")
    
    results = {}
    
    # WHOIS lookup with more details
    try:
        print(f"{Colors.YELLOW}[+] Performing comprehensive WHOIS lookup...{Colors.END}")
        domain_info = whois.whois(domain)
        results['whois'] = {
            'registrar': domain_info.registrar,
            'creation_date': str(domain_info.creation_date),
            'expiration_date': str(domain_info.expiration_date),
            'updated_date': str(domain_info.updated_date),
            'name_servers': domain_info.name_servers,
            'status': domain_info.status,
            'emails': domain_info.emails,
            'dnssec': domain_info.dnssec,
            'name': domain_info.name,
            'org': domain_info.org,
            'address': domain_info.address,
            'city': domain_info.city,
            'state': domain_info.state,
            'zipcode': domain_info.zipcode,
            'country': domain_info.country
        }
    except Exception as e:
        results['whois'] = {'error': str(e)}
    
    # Comprehensive DNS enumeration
    try:
        print(f"{Colors.YELLOW}[+] Enumerating all DNS records...{Colors.END}")
        dns_results = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_results[record_type] = [str(r) for r in answers]
            except:
                dns_results[record_type] = []
        
        results['dns'] = dns_results
    except Exception as e:
        results['dns'] = {'error': str(e)}
    
    # Subdomain enumeration
    try:
        print(f"{Colors.YELLOW}[+] Advanced subdomain enumeration...{Colors.END}")
        subdomains = []
        common_subdomains = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 
            'webdisk', 'cpanel', 'whm', 'autodiscover', 'dev', 'test',
            'blog', 'api', 'secure', 'admin', 'forum', 'news', 'vpn',
            'ns2', 'mysql', 'email', 'shop', 'portal', 'cloud', 'cdn',
            'static', 'media', 'download', 'uploads', 'server', 'proxy',
            'firewall', 'router', 'network', 'internal', 'external'
        ]
        
        for sub in common_subdomains:
            full_domain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                subdomains.append(full_domain)
                print(f"{Colors.GREEN}[+] Found subdomain: {full_domain}{Colors.END}")
            except socket.gaierror:
                continue
        
        results['subdomains'] = subdomains
    except Exception as e:
        results['subdomains'] = {'error': str(e)}
    
    # HTTP headers and security analysis
    try:
        print(f"{Colors.YELLOW}[+] Analyzing HTTP headers and security...{Colors.END}")
        headers_results = {}
        
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{domain}"
                response = requests.get(url, timeout=10, verify=False)
                headers_results[protocol] = {
                    'status_code': response.status_code,
                    'server': response.headers.get('Server', 'Unknown'),
                    'x-powered-by': response.headers.get('X-Powered-By', 'Unknown'),
                    'security_headers': {
                        'strict-transport-security': response.headers.get('Strict-Transport-Security', 'Missing'),
                        'x-frame-options': response.headers.get('X-Frame-Options', 'Missing'),
                        'x-content-type-options': response.headers.get('X-Content-Type-Options', 'Missing'),
                        'x-xss-protection': response.headers.get('X-XSS-Protection', 'Missing'),
                    }
                }
            except:
                headers_results[protocol] = {'error': f'Could not connect via {protocol}'}
        
        results['http_analysis'] = headers_results
    except Exception as e:
        results['http_analysis'] = {'error': str(e)}
    
    return results

def advanced_ip_info(ip):
    print(f"\n{Colors.CYAN}{Colors.BOLD}[+] Advanced IP Analysis for: {ip}{Colors.END}")
    
    results = {}
    
    try:
        # Get detailed IP information from ip-api.com
        print(f"{Colors.YELLOW}[+] Querying detailed IP information...{Colors.END}")
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        
        if response['status'] == 'success':
            results['ip_info'] = {
                'country': response.get('country', 'Unknown'),
                'region': response.get('regionName', 'Unknown'),
                'city': response.get('city', 'Unknown'),
                'zip': response.get('zip', 'Unknown'),
                'lat': response.get('lat', 'Unknown'),
                'lon': response.get('lon', 'Unknown'),
                'timezone': response.get('timezone', 'Unknown'),
                'isp': response.get('isp', 'Unknown'),
                'org': response.get('org', 'Unknown'),
                'as': response.get('as', 'Unknown')
            }
        else:
            results['ip_info'] = {'error': 'Failed to get IP information'}
    except Exception as e:
        results['ip_info'] = {'error': str(e)}
    
    # Advanced port scanning
    try:
        print(f"{Colors.YELLOW}[+] Performing advanced port scan...{Colors.END}")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                        993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"{Colors.GREEN}[+] Open port found: {port}{Colors.END}")
                sock.close()
            except:
                pass
        
        results['open_ports'] = open_ports
    except Exception as e:
        results['open_ports'] = {'error': str(e)}
    
    return results

def advanced_email_info(email):
    print(f"\n{Colors.CYAN}{Colors.BOLD}[+] Advanced Email Analysis for: {email}{Colors.END}")
    
    results = {}
    
    # Check if email is valid
    email_regex = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    if not re.search(email_regex, email):
        results['error'] = 'Invalid email format'
        return results
    
    # Extract domain from email
    domain = email.split('@')[1]
    
    # Get comprehensive domain information
    results['domain_info'] = advanced_domain_info(domain)
    
    # Advanced email verification
    try:
        print(f"{Colors.YELLOW}[+] Performing advanced email verification...{Colors.END}")
        
        # Check if email was involved in data breaches
        print(f"{Colors.YELLOW}[+] Checking data breaches...{Colors.END}")
        try:
            # Using haveibeenpwned API
            headers = {'User-Agent': 'HCO-OSINT-Tool-v2.0'}
            hibp_response = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers=headers, timeout=10)
            
            if hibp_response.status_code == 200:
                breaches = hibp_response.json()
                results['breaches'] = [{
                    'Name': b.get('Name', 'Unknown'),
                    'Title': b.get('Title', 'Unknown'),
                    'Domain': b.get('Domain', 'Unknown'),
                    'BreachDate': b.get('BreachDate', 'Unknown'),
                    'AddedDate': b.get('AddedDate', 'Unknown'),
                    'PwnCount': b.get('PwnCount', 'Unknown'),
                    'Description': b.get('Description', 'Unknown'),
                } for b in breaches]
            else:
                results['breaches'] = 'No breaches found or API limit exceeded'
        except Exception as e:
            results['breaches'] = {'error': str(e)}
        
    except Exception as e:
        results['email_validation'] = {'error': str(e)}
    
    return results

# Save results to file
def save_results(data, filename):
    try:
        with open(filename, 'w') as f:
            if isinstance(data, dict):
                json.dump(data, f, indent=4)
            else:
                f.write(str(data))
        print(f"{Colors.GREEN}[+] Results saved to: {filename}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] Error saving results: {e}{Colors.END}")

# Main menu
def main_menu():
    os.system('clear')
    print(f"\n{Colors.BLUE}{Colors.BOLD}╔{'═'*60}╗{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}║{'HCO OSINT TOOL - MAIN MENU':^60}║{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}╚{'═'*60}╝{Colors.END}")
    
    print(f"\n{Colors.CYAN}{Colors.BOLD}1. Advanced Domain Information Gathering")
    print(f"2. Advanced IP Address Information Gathering")
    print(f"3. Advanced Email Information Gathering")
    print(f"4. Phone Number Information Gathering")
    print(f"5. Social Media Analysis")
    print(f"6. Metadata Extraction")
    print(f"7. Exit{Colors.END}")
    print()
    
    try:
        choice = input(f"{Colors.YELLOW}Select an option (1-7): {Colors.END}")
        
        if choice == "1":
            target = input("Enter domain name (example.com): ").strip()
            if target:
                results = advanced_domain_info(target)
                print(f"\n{Colors.GREEN}{Colors.BOLD}[+] Domain Information Results:{Colors.END}")
                print(json.dumps(results, indent=4))
                
                # Save results
                filename = f"domain_{target}_{int(time.time())}.json"
                save_results(results, filename)
            else:
                print(f"{Colors.RED}[-] Please enter a valid domain{Colors.END}")
        
        elif choice == "2":
            target = input("Enter IP address: ").strip()
            if target:
                results = advanced_ip_info(target)
                print(f"\n{Colors.GREEN}{Colors.BOLD}[+] IP Information Results:{Colors.END}")
                print(json.dumps(results, indent=4))
                
                # Save results
                filename = f"ip_{target}_{int(time.time())}.json"
                save_results(results, filename)
            else:
                print(f"{Colors.RED}[-] Please enter a valid IP address{Colors.END}")
        
        elif choice == "3":
            target = input("Enter email address: ").strip()
            if target:
                results = advanced_email_info(target)
                print(f"\n{Colors.GREEN}{Colors.BOLD}[+] Email Information Results:{Colors.END}")
                print(json.dumps(results, indent=4))
                
                # Save results
                filename = f"email_{target}_{int(time.time())}.json"
                save_results(results, filename)
            else:
                print(f"{Colors.RED}[-] Please enter a valid email address{Colors.END}")
        
        elif choice == "4":
            target = input("Enter phone number: ").strip()
            if target:
                print(f"{Colors.YELLOW}[+] Phone analysis feature coming soon!{Colors.END}")
            else:
                print(f"{Colors.RED}[-] Please enter a valid phone number{Colors.END}")
        
        elif choice == "5":
            target = input("Enter username or profile URL: ").strip()
            if target:
                print(f"{Colors.YELLOW}[+] Social media analysis feature coming soon!{Colors.END}")
            else:
                print(f"{Colors.RED}[-] Please enter a valid username or URL{Colors.END}")
        
        elif choice == "6":
            target = input("Enter file path or URL: ").strip()
            if target:
                print(f"{Colors.YELLOW}[+] Metadata extraction feature coming soon!{Colors.END}")
            else:
                print(f"{Colors.RED}[-] Please enter a valid file path or URL{Colors.END}")
        
        elif choice == "7":
            print(f"{Colors.GREEN}[+] Thank you for using HCO OSINT Tool. Goodbye!{Colors.END}")
            sys.exit(0)
        
        else:
            print(f"{Colors.RED}[-] Invalid option. Please try again.{Colors.END}")
    
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Operation cancelled by user. Exiting...{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[-] An error occurred: {e}{Colors.END}")

# Main function
def main():
    global tool_state
    
    # Check dependencies
    if not check_dependencies():
        print(f"{Colors.RED}[-] Failed to install required dependencies. Exiting...{Colors.END}")
        sys.exit(1)
    
    # Authentication system
    while tool_state != UNLOCKED:
        if tool_state == LOCKED:
            choice = show_lock_screen()
            
            if choice == "1":
                tool_state = COUNTDOWN
            elif choice == "2":
                tool_state = SUCCESS
            elif choice == "3":
                print(f"{Colors.GREEN}[+] Thank you for using HCO OSINT Tool. Goodbye!{Colors.END}")
                sys.exit(0)
            else:
                print(f"{Colors.RED}[-] Invalid option. Please try again.{Colors.END}")
                time.sleep(2)
        
        elif tool_state == COUNTDOWN:
            if show_countdown():
                tool_state = SUCCESS
        
        elif tool_state == SUCCESS:
            if show_unlock_screen():
                tool_state = UNLOCKED
    
    # Main tool loop
    while True:
        main_menu()
        print()
        input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")

if __name__ == "__main__":
    main()
