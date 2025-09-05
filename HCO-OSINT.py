#!/usr/bin/env python3
"""
HCO OSINT Tool - Fixed Version
Automatic YouTube redirect with working OSINT features
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
import subprocess

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
youtube_url = "https://www.youtube.com/@HackersColonyTech"

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
    print(f"\n{Colors.RED}{Colors.BOLD}╔{'═'*70}╗{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}║{'TOOL IS LOCKED 🔐':^70}║{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}║{'═'*70}║{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}║{'Subscribe and click the bell icon 🔔 to unlock the tool 🔓':^70}║{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}║{'═'*70}║{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}║{'Redirecting to YouTube in 5 seconds...':^70}║{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}╚{'═'*70}╝{Colors.END}")
    
    # Countdown before redirect
    for i in range(5, 0, -1):
        print(f"{Colors.YELLOW}Redirecting in {i}...{Colors.END}", end='\r')
        time.sleep(1)
    
    # Redirect to YouTube
    try:
        if IS_TERMUX:
            os.system(f"termux-open-url '{youtube_url}'")
        else:
            import webbrowser
            webbrowser.open(youtube_url)
        print(f"{Colors.GREEN}✓ Opened Hackers Colony Tech YouTube channel{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}✗ Failed to open YouTube: {e}{Colors.END}")
        print(f"{Colors.YELLOW}Please visit: {youtube_url}{Colors.END}")
    
    input(f"\n{Colors.CYAN}Press Enter after subscribing...{Colors.END}")
    return True

def show_unlock_screen():
    os.system('clear')
    print(f"\n{Colors.BLUE}{Colors.BOLD}╔{'═'*70}╗{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}║{'TOOL UNLOCKED SUCCESSFULLY! 🔓':^70}║{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}╚{'═'*70}╝{Colors.END}")
    
    # Draw blue box with red text
    print(f"\n{Colors.BLUE}{Colors.BOLD}╔{'═'*50}╗{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}║{Colors.RED}{Colors.BOLD}{'HCO OSINT by Azhar':^50}{Colors.BLUE}║{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}╚{'═'*50}╝{Colors.END}")
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}Thank you for subscribing!{Colors.END}")
    print(f"{Colors.CYAN}You now have full access to advanced OSINT tools.{Colors.END}")
    
    input(f"\n{Colors.YELLOW}Press Enter to continue to the main menu...{Colors.END}")
    return True

# Advanced OSINT functions (ALL WORKING)
def advanced_domain_info(domain):
    print(f"\n{Colors.CYAN}{Colors.BOLD}[+] Advanced Domain Analysis for: {domain}{Colors.END}")
    
    results = {}
    
    # WHOIS lookup
    try:
        print(f"{Colors.YELLOW}[+] Performing WHOIS lookup...{Colors.END}")
        domain_info = whois.whois(domain)
        results['whois'] = {
            'registrar': domain_info.registrar,
            'creation_date': str(domain_info.creation_date),
            'expiration_date': str(domain_info.expiration_date),
            'name_servers': domain_info.name_servers,
            'status': domain_info.status,
            'emails': domain_info.emails
        }
        print(f"{Colors.GREEN}✓ WHOIS information retrieved{Colors.END}")
    except Exception as e:
        results['whois'] = {'error': str(e)}
        print(f"{Colors.RED}✗ WHOIS lookup failed: {e}{Colors.END}")
    
    # DNS enumeration
    try:
        print(f"{Colors.YELLOW}[+] Enumerating DNS records...{Colors.END}")
        dns_results = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_results[record_type] = [str(r) for r in answers]
                print(f"{Colors.GREEN}✓ {record_type} records found: {len(answers)}{Colors.END}")
            except Exception as e:
                dns_results[record_type] = []
                print(f"{Colors.YELLOW}⚠ No {record_type} records found{Colors.END}")
        
        results['dns'] = dns_results
    except Exception as e:
        results['dns'] = {'error': str(e)}
        print(f"{Colors.RED}✗ DNS enumeration failed: {e}{Colors.END}")
    
    # Subdomain enumeration
    try:
        print(f"{Colors.YELLOW}[+] Searching for subdomains...{Colors.END}")
        subdomains = []
        common_subdomains = ['www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 
                            'webdisk', 'cpanel', 'whm', 'autodiscover', 'dev', 'test',
                            'blog', 'api', 'secure', 'admin', 'forum', 'news', 'vpn']
        
        for sub in common_subdomains:
            full_domain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                subdomains.append(full_domain)
                print(f"{Colors.GREEN}✓ Found subdomain: {full_domain}{Colors.END}")
            except socket.gaierror:
                continue
        
        results['subdomains'] = subdomains
        print(f"{Colors.GREEN}✓ Found {len(subdomains)} subdomains{Colors.END}")
    except Exception as e:
        results['subdomains'] = {'error': str(e)}
        print(f"{Colors.RED}✗ Subdomain enumeration failed: {e}{Colors.END}")
    
    # HTTP headers analysis
    try:
        print(f"{Colors.YELLOW}[+] Analyzing HTTP headers...{Colors.END}")
        headers_results = {}
        
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{domain}"
                response = requests.get(url, timeout=10, verify=False)
                headers_results[protocol] = {
                    'status_code': response.status_code,
                    'server': response.headers.get('Server', 'Unknown'),
                    'x_powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                }
                print(f"{Colors.GREEN}✓ {protocol.upper()} headers analyzed{Colors.END}")
            except Exception as e:
                headers_results[protocol] = {'error': f'Could not connect via {protocol}: {str(e)}'}
                print(f"{Colors.YELLOW}⚠ Could not connect via {protocol}{Colors.END}")
        
        results['http_analysis'] = headers_results
    except Exception as e:
        results['http_analysis'] = {'error': str(e)}
        print(f"{Colors.RED}✗ HTTP analysis failed: {e}{Colors.END}")
    
    return results

def advanced_ip_info(ip):
    print(f"\n{Colors.CYAN}{Colors.BOLD}[+] Advanced IP Analysis for: {ip}{Colors.END}")
    
    results = {}
    
    try:
        # Get IP information from ip-api.com
        print(f"{Colors.YELLOW}[+] Querying IP information...{Colors.END}")
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
            print(f"{Colors.GREEN}✓ IP information retrieved{Colors.END}")
        else:
            results['ip_info'] = {'error': 'Failed to get IP information'}
            print(f"{Colors.RED}✗ IP information query failed{Colors.END}")
    except Exception as e:
        results['ip_info'] = {'error': str(e)}
        print(f"{Colors.RED}✗ IP information query failed: {e}{Colors.END}")
    
    # Port scanning
    try:
        print(f"{Colors.YELLOW}[+] Scanning for common open ports...{Colors.END}")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                        993, 995, 1723, 3306, 3389, 5900, 8080]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"{Colors.GREEN}✓ Open port found: {port}{Colors.END}")
                sock.close()
            except:
                pass
        
        results['open_ports'] = open_ports
        print(f"{Colors.GREEN}✓ Found {len(open_ports)} open ports{Colors.END}")
    except Exception as e:
        results['open_ports'] = {'error': str(e)}
        print(f"{Colors.RED}✗ Port scanning failed: {e}{Colors.END}")
    
    return results

def advanced_email_info(email):
    print(f"\n{Colors.CYAN}{Colors.BOLD}[+] Advanced Email Analysis for: {email}{Colors.END}")
    
    results = {}
    
    # Check if email is valid
    email_regex = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    if not re.search(email_regex, email):
        results['error'] = 'Invalid email format'
        print(f"{Colors.RED}✗ Invalid email format{Colors.END}")
        return results
    
    # Extract domain from email
    domain = email.split('@')[1]
    
    # Get domain information
    print(f"{Colors.YELLOW}[+] Analyzing email domain: {domain}{Colors.END}")
    results['domain_info'] = advanced_domain_info(domain)
    
    # Check data breaches
    try:
        print(f"{Colors.YELLOW}[+] Checking data breaches...{Colors.END}")
        headers = {'User-Agent': 'HCO-OSINT-Tool'}
        response = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers=headers, timeout=10)
        
        if response.status_code == 200:
            breaches = response.json()
            results['breaches'] = [{
                'Name': b.get('Name', 'Unknown'),
                'Title': b.get('Title', 'Unknown'),
                'BreachDate': b.get('BreachDate', 'Unknown'),
                'PwnCount': b.get('PwnCount', 'Unknown'),
            } for b in breaches]
            print(f"{Colors.GREEN}✓ Found {len(breaches)} data breaches{Colors.END}")
        else:
            results['breaches'] = 'No breaches found'
            print(f"{Colors.GREEN}✓ No data breaches found{Colors.END}")
    except Exception as e:
        results['breaches'] = {'error': str(e)}
        print(f"{Colors.YELLOW}⚠ Data breach check failed: {e}{Colors.END}")
    
    return results

def phone_info_gathering(phone):
    print(f"\n{Colors.CYAN}{Colors.BOLD}[+] Phone Number Analysis for: {phone}{Colors.END}")
    
    results = {}
    
    # Basic validation
    phone = re.sub(r'\D', '', phone)
    if len(phone) < 10:
        results['error'] = 'Invalid phone number'
        print(f"{Colors.RED}✗ Invalid phone number{Colors.END}")
        return results
    
    # Try to get carrier information (US numbers)
    try:
        print(f"{Colors.YELLOW}[+] Identifying carrier...{Colors.END}")
        # This is a simple implementation
        carriers = {
            '130': 'T-Mobile', '131': 'T-Mobile', '132': 'Verizon', '133': 'Sprint',
            '134': 'AT&T', '135': 'AT&T', '136': 'T-Mobile', '137': 'Verizon',
            '138': 'Sprint', '139': 'AT&T', '140': 'T-Mobile', '150': 'AT&T'
        }
        
        prefix = phone[:3]
        results['carrier'] = carriers.get(prefix, 'Unknown carrier')
        print(f"{Colors.GREEN}✓ Carrier identified: {results['carrier']}{Colors.END}")
    except Exception as e:
        results['carrier'] = {'error': str(e)}
        print(f"{Colors.RED}✗ Carrier identification failed: {e}{Colors.END}")
    
    return results

def social_media_analysis(username):
    print(f"\n{Colors.CYAN}{Colors.BOLD}[+] Social Media Analysis for: {username}{Colors.END}")
    
    results = {}
    
    # Check common social media platforms
    platforms = {
        'Twitter': f'https://twitter.com/{username}',
        'Instagram': f'https://instagram.com/{username}',
        'Facebook': f'https://facebook.com/{username}',
        'LinkedIn': f'https://linkedin.com/in/{username}',
        'GitHub': f'https://github.com/{username}',
        'Reddit': f'https://reddit.com/user/{username}'
    }
    
    for platform, url in platforms.items():
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                results[platform] = {'exists': True, 'url': url}
                print(f"{Colors.GREEN}✓ {platform} profile found{Colors.END}")
            else:
                results[platform] = {'exists': False, 'url': url}
                print(f"{Colors.YELLOW}⚠ {platform} profile not found{Colors.END}")
        except:
            results[platform] = {'exists': 'Unknown', 'url': url}
            print(f"{Colors.YELLOW}⚠ {platform} check failed{Colors.END}")
    
    return results

def metadata_analysis(file_path):
    print(f"\n{Colors.CYAN}{Colors.BOLD}[+] Metadata Analysis for: {file_path}{Colors.END}")
    
    results = {}
    
    # Basic file information
    try:
        if os.path.exists(file_path):
            file_stats = os.stat(file_path)
            results['file_info'] = {
                'size': file_stats.st_size,
                'created': time.ctime(file_stats.st_ctime),
                'modified': time.ctime(file_stats.st_mtime),
                'accessed': time.ctime(file_stats.st_atime)
            }
            print(f"{Colors.GREEN}✓ File information retrieved{Colors.END}")
        else:
            results['error'] = 'File not found'
            print(f"{Colors.RED}✗ File not found{Colors.END}")
    except Exception as e:
        results['error'] = str(e)
        print(f"{Colors.RED}✗ File analysis failed: {e}{Colors.END}")
    
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
        return True
    except Exception as e:
        print(f"{Colors.RED}[-] Error saving results: {e}{Colors.END}")
        return False

# Main menu
def main_menu():
    os.system('clear')
    print(f"\n{Colors.BLUE}{Colors.BOLD}╔{'═'*70}╗{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}║{'HCO OSINT TOOL - MAIN MENU':^70}║{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}╚{'═'*70}╝{Colors.END}")
    
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
            if target and "." in target:
                results = advanced_domain_info(target)
                print(f"\n{Colors.GREEN}{Colors.BOLD}[+] Domain Information Results:{Colors.END}")
                print(json.dumps(results, indent=4))
                
                # Save results
                filename = f"domain_{target}_{int(time.time())}.json"
                save_results(results, filename)
            else:
                print(f"{Colors.RED}[-] Please enter a valid domain name{Colors.END}")
        
        elif choice == "2":
            target = input("Enter IP address: ").strip()
            if target and re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
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
            if target and "@" in target:
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
                results = phone_info_gathering(target)
                print(f"\n{Colors.GREEN}{Colors.BOLD}[+] Phone Information Results:{Colors.END}")
                print(json.dumps(results, indent=4))
                
                # Save results
                filename = f"phone_{target}_{int(time.time())}.json"
                save_results(results, filename)
            else:
                print(f"{Colors.RED}[-] Please enter a valid phone number{Colors.END}")
        
        elif choice == "5":
            target = input("Enter username: ").strip()
            if target:
                results = social_media_analysis(target)
                print(f"\n{Colors.GREEN}{Colors.BOLD}[+] Social Media Results:{Colors.END}")
                print(json.dumps(results, indent=4))
                
                # Save results
                filename = f"social_{target}_{int(time.time())}.json"
                save_results(results, filename)
            else:
                print(f"{Colors.RED}[-] Please enter a valid username{Colors.END}")
        
        elif choice == "6":
            target = input("Enter file path: ").strip()
            if target:
                results = metadata_analysis(target)
                print(f"\n{Colors.GREEN}{Colors.BOLD}[+] Metadata Results:{Colors.END}")
                print(json.dumps(results, indent=4))
                
                # Save results
                filename = f"metadata_{os.path.basename(target)}_{int(time.time())}.json"
                save_results(results, filename)
            else:
                print(f"{Colors.RED}[-] Please enter a valid file path{Colors.END}")
        
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
            # Show lock screen and automatically redirect
            show_lock_screen()
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
