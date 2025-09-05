#!/usr/bin/env python3
"""
HCO OSINT Tool - Real Information Gathering Tool
For ethical hackers and cybersecurity researchers
"""

import os
import sys
import socket
import requests
import whois
import dns.resolver
import json
import time
from urllib.parse import urlparse
import subprocess
import re

# Check if running on Termux
IS_TERMUX = os.path.exists('/data/data/com.termux/files/usr')

# Banner
def print_banner():
    os.system('clear' if not IS_TERMUX else 'termux-clipboard -c >/dev/null 2>&1')
    print("\033[1;31m" + "="*60)
    print("           HCO OSINT TOOL BY AZHAR")
    print("="*60)
    print("    Open Source Intelligence Gathering Tool")
    print("        For Ethical Hackers & Researchers")
    print("="*60 + "\033[0m")
    print()

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
        print("Installing missing dependencies...")
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
                print(f"Failed to install {package}. Please install it manually.")
                return False
    return True

# Domain information gathering
def domain_info_gathering(domain):
    print(f"\n\033[1;34m[+] Gathering information for: {domain}\033[0m")
    
    results = {}
    
    # WHOIS lookup
    try:
        print("[+] Performing WHOIS lookup...")
        domain_info = whois.whois(domain)
        results['whois'] = {
            'registrar': domain_info.registrar,
            'creation_date': str(domain_info.creation_date),
            'expiration_date': str(domain_info.expiration_date),
            'name_servers': domain_info.name_servers,
            'emails': domain_info.emails
        }
    except Exception as e:
        results['whois'] = {'error': str(e)}
    
    # DNS enumeration
    try:
        print("[+] Enumerating DNS records...")
        dns_results = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
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
        print("[+] Searching for subdomains...")
        subdomains = []
        common_subdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'cpanel', 
                            'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev',
                            'www2', 'admin', 'forum', 'news', 'vpn', 'ns2', 'mysql', 'ftp', 'news', 'u', 'email']
        
        for sub in common_subdomains:
            full_domain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                subdomains.append(full_domain)
            except socket.gaierror:
                continue
        
        results['subdomains'] = subdomains
    except Exception as e:
        results['subdomains'] = {'error': str(e)}
    
    # HTTP headers
    try:
        print("[+] Analyzing HTTP headers...")
        url = f"http://{domain}"
        response = requests.get(url, timeout=10)
        results['http_headers'] = dict(response.headers)
    except:
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10, verify=False)
            results['http_headers'] = dict(response.headers)
        except Exception as e:
            results['http_headers'] = {'error': str(e)}
    
    return results

# IP information gathering
def ip_info_gathering(ip):
    print(f"\n\033[1;34m[+] Gathering information for IP: {ip}\033[0m")
    
    results = {}
    
    try:
        # Get IP information from ip-api.com
        print("[+] Querying IP information...")
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        
        if response['status'] == 'success':
            results['ip_info'] = {
                'country': response['country'],
                'region': response['regionName'],
                'city': response['city'],
                'zip': response['zip'],
                'lat': response['lat'],
                'lon': response['lon'],
                'timezone': response['timezone'],
                'isp': response['isp'],
                'org': response['org'],
                'as': response['as']
            }
        else:
            results['ip_info'] = {'error': 'Failed to get IP information'}
    except Exception as e:
        results['ip_info'] = {'error': str(e)}
    
    # Reverse DNS lookup
    try:
        print("[+] Performing reverse DNS lookup...")
        hostname = socket.gethostbyaddr(ip)
        results['reverse_dns'] = hostname[0]
    except:
        results['reverse_dns'] = 'Not found'
    
    # Check open ports
    try:
        print("[+] Scanning for common open ports...")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        open_ports = []
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        
        results['open_ports'] = open_ports
    except Exception as e:
        results['open_ports'] = {'error': str(e)}
    
    return results

# Email information gathering
def email_info_gathering(email):
    print(f"\n\033[1;34m[+] Gathering information for email: {email}\033[0m")
    
    results = {}
    
    # Check if email is valid
    email_regex = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    if not re.search(email_regex, email):
        results['error'] = 'Invalid email format'
        return results
    
    # Extract domain from email
    domain = email.split('@')[1]
    
    # Get domain information
    results['domain_info'] = domain_info_gathering(domain)
    
    # Check if email exists using haveibeenpwned API (anonymously)
    try:
        print("[+] Checking if email was involved in data breaches...")
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {'User-Agent': 'HCO-OSINT-Tool'}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            breaches = response.json()
            results['breaches'] = [{'Name': b['Name'], 'BreachDate': b['BreachDate']} for b in breaches]
        else:
            results['breaches'] = 'No breaches found or API limit exceeded'
    except Exception as e:
        results['breaches'] = {'error': str(e)}
    
    return results

# Phone number information
def phone_info_gathering(phone):
    print(f"\n\033[1;34m[+] Gathering information for phone: {phone}\033[0m")
    
    results = {}
    
    # Basic validation
    phone = re.sub(r'\D', '', phone)
    if len(phone) < 10:
        results['error'] = 'Invalid phone number'
        return results
    
    # Try to get carrier information
    try:
        print("[+] Identifying carrier...")
        # This is a simple implementation - in a real tool you'd use a proper API
        carriers = {
            '130': 'T-Mobile',
            '131': 'T-Mobile',
            '132': 'Verizon',
            '133': 'Sprint',
            '134': 'AT&T',
            '135': 'AT&T',
            '136': 'T-Mobile',
            '137': 'Verizon',
            '138': 'Sprint',
            '139': 'AT&T'
        }
        
        prefix = phone[:3]
        results['carrier'] = carriers.get(prefix, 'Unknown carrier')
    except Exception as e:
        results['carrier'] = {'error': str(e)}
    
    # Try to get location based on area code (US only)
    try:
        print("[+] Estimating location...")
        area_codes = {
            '201': 'New Jersey',
            '202': 'Washington DC',
            '203': 'Connecticut',
            '205': 'Alabama',
            '206': 'Washington',
            '212': 'New York',
            '213': 'California',
            '214': 'Texas',
            '215': 'Pennsylvania',
            '216': 'Ohio',
            '217': 'Illinois',
            '218': 'Minnesota',
            '219': 'Indiana',
            '224': 'Illinois',
            '225': 'Louisiana',
            '228': 'Mississippi',
            '229': 'Georgia',
            '231': 'Michigan',
            '234': 'Ohio',
            '239': 'Florida',
            '240': 'Maryland',
            '248': 'Michigan',
            '251': 'Alabama',
            '252': 'North Carolina',
            '253': 'Washington',
            '254': 'Texas',
            '256': 'Alabama',
            '260': 'Indiana',
            '262': 'Wisconsin',
            '267': 'Pennsylvania',
            '269': 'Michigan',
            '270': 'Kentucky',
            '272': 'Pennsylvania',
            '276': 'Virginia',
            '281': 'Texas',
            '301': 'Maryland',
            '302': 'Delaware',
            '303': 'Colorado',
            '304': 'West Virginia',
            '305': 'Florida',
            '307': 'Wyoming',
            '308': 'Nebraska',
            '309': 'Illinois',
            '310': 'California',
            '312': 'Illinois',
            '313': 'Michigan',
            '314': 'Missouri',
            '315': 'New York',
            '316': 'Kansas',
            '317': 'Indiana',
            '318': 'Louisiana',
            '319': 'Iowa',
            '320': 'Minnesota',
            '321': 'Florida',
            '323': 'California',
            '325': 'Texas',
            '330': 'Ohio',
            '331': 'Illinois',
            '334': 'Alabama',
            '336': 'North Carolina',
            '337': 'Louisiana',
            '339': 'Massachusetts',
            '347': 'New York',
            '351': 'Massachusetts',
            '352': 'Florida',
            '360': 'Washington',
            '361': 'Texas',
            '385': 'Utah',
            '386': 'Florida',
            '401': 'Rhode Island',
            '402': 'Nebraska',
            '404': 'Georgia',
            '405': 'Oklahoma',
            '406': 'Montana',
            '407': 'Florida',
            '408': 'California',
            '409': 'Texas',
            '410': 'Maryland',
            '412': 'Pennsylvania',
            '413': 'Massachusetts',
            '414': 'Wisconsin',
            '415': 'California',
            '417': 'Missouri',
            '419': 'Ohio',
            '423': 'Tennessee',
            '424': 'California',
            '425': 'Washington',
            '430': 'Texas',
            '432': 'Texas',
            '434': 'Virginia',
            '435': 'Utah',
            '440': 'Ohio',
            '443': 'Maryland',
            '445': 'Pennsylvania',
            '464': 'Illinois',
            '469': 'Texas',
            '470': 'Georgia',
            '475': 'Connecticut',
            '478': 'Georgia',
            '479': 'Arkansas',
            '480': 'Arizona',
            '484': 'Pennsylvania',
            '501': 'Arkansas',
            '502': 'Kentucky',
            '503': 'Oregon',
            '504': 'Louisiana',
            '505': 'New Mexico',
            '507': 'Minnesota',
            '508': 'Massachusetts',
            '509': 'Washington',
            '510': 'California',
            '512': 'Texas',
            '513': 'Ohio',
            '515': 'Iowa',
            '516': 'New York',
            '517': 'Michigan',
            '518': 'New York',
            '520': 'Arizona',
            '530': 'California',
            '540': 'Virginia',
            '541': 'Oregon',
            '551': 'New Jersey',
            '559': 'California',
            '561': 'Florida',
            '562': 'California',
            '563': 'Iowa',
            '564': 'Washington',
            '567': 'Ohio',
            '570': 'Pennsylvania',
            '571': 'Virginia',
            '573': 'Missouri',
            '574': 'Indiana',
            '575': 'New Mexico',
            '580': 'Oklahoma',
            '585': 'New York',
            '586': 'Michigan',
            '601': 'Mississippi',
            '602': 'Arizona',
            '603': 'New Hampshire',
            '605': 'South Dakota',
            '606': 'Kentucky',
            '607': 'New York',
            '608': 'Wisconsin',
            '609': 'New Jersey',
            '610': 'Pennsylvania',
            '612': 'Minnesota',
            '614': 'Ohio',
            '615': 'Tennessee',
            '616': 'Michigan',
            '617': 'Massachusetts',
            '618': 'Illinois',
            '619': 'California',
            '620': 'Kansas',
            '623': 'Arizona',
            '626': 'California',
            '630': 'Illinois',
            '631': 'New York',
            '636': 'Missouri',
            '641': 'Iowa',
            '646': 'New York',
            '650': 'California',
            '651': 'Minnesota',
            '657': 'California',
            '660': 'Missouri',
            '661': 'California',
            '662': 'Mississippi',
            '667': 'Maryland',
            '669': 'California',
            '670': 'Northern Mariana Islands',
            '671': 'Guam',
            '678': 'Georgia',
            '681': 'West Virginia',
            '682': 'Texas',
            '684': 'American Samoa',
            '701': 'North Dakota',
            '702': 'Nevada',
            '703': 'Virginia',
            '704': 'North Carolina',
            '706': 'Georgia',
            '707': 'California',
            '708': 'Illinois',
            '712': 'Iowa',
            '713': 'Texas',
            '714': 'California',
            '715': 'Wisconsin',
            '716': 'New York',
            '717': 'Pennsylvania',
            '718': 'New York',
            '719': 'Colorado',
            '720': 'Colorado',
            '724': 'Pennsylvania',
            '725': 'Nevada',
            '727': 'Florida',
            '731': 'Tennessee',
            '732': 'New Jersey',
            '734': 'Michigan',
            '737': 'Texas',
            '740': 'Ohio',
            '747': 'California',
            '754': 'Florida',
            '757': 'Virginia',
            '760': 'California',
            '762': 'Georgia',
            '763': 'Minnesota',
            '765': 'Indiana',
            '769': 'Mississippi',
            '770': 'Georgia',
            '772': 'Florida',
            '773': 'Illinois',
            '774': 'Massachusetts',
            '775': 'Nevada',
            '779': 'Illinois',
            '781': 'Massachusetts',
            '785': 'Kansas',
            '786': 'Florida',
            '787': 'Puerto Rico',
            '801': 'Utah',
            '802': 'Vermont',
            '803': 'South Carolina',
            '804': 'Virginia',
            '805': 'California',
            '806': 'Texas',
            '808': 'Hawaii',
            '810': 'Michigan',
            '812': 'Indiana',
            '813': 'Florida',
            '814': 'Pennsylvania',
            '815': 'Illinois',
            '816': 'Missouri',
            '817': 'Texas',
            '818': 'California',
            '828': 'North Carolina',
            '830': 'Texas',
            '831': 'California',
            '832': 'Texas',
            '843': 'South Carolina',
            '845': 'New York',
            '847': 'Illinois',
            '848': 'New Jersey',
            '850': 'Florida',
            '856': 'New Jersey',
            '857': 'Massachusetts',
            '858': 'California',
            '859': 'Kentucky',
            '860': 'Connecticut',
            '862': 'New Jersey',
            '863': 'Florida',
            '864': 'South Carolina',
            '865': 'Tennessee',
            '870': 'Arkansas',
            '872': 'Illinois',
            '878': 'Pennsylvania',
            '901': 'Tennessee',
            '903': 'Texas',
            '904': 'Florida',
            '906': 'Michigan',
            '907': 'Alaska',
            '908': 'New Jersey',
            '909': 'California',
            '910': 'North Carolina',
            '912': 'Georgia',
            '913': 'Kansas',
            '914': 'New York',
            '915': 'Texas',
            '916': 'California',
            '917': 'New York',
            '918': 'Oklahoma',
            '919': 'North Carolina',
            '920': 'Wisconsin',
            '925': 'California',
            '928': 'Arizona',
            '931': 'Tennessee',
            '936': 'Texas',
            '937': 'Ohio',
            '939': 'Puerto Rico',
            '940': 'Texas',
            '941': 'Florida',
            '947': 'Michigan',
            '949': 'California',
            '951': 'California',
            '952': 'Minnesota',
            '954': 'Florida',
            '956': 'Texas',
            '957': 'New Mexico',
            '959': 'Connecticut',
            '970': 'Colorado',
            '971': 'Oregon',
            '972': 'Texas',
            '973': 'New Jersey',
            '975': 'Missouri',
            '978': 'Massachusetts',
            '979': 'Texas',
            '980': 'North Carolina',
            '984': 'North Carolina',
            '985': 'Louisiana',
            '989': 'Michigan'
        }
        
        area_code = phone[:3]
        results['location'] = area_codes.get(area_code, 'Unknown location')
    except Exception as e:
        results['location'] = {'error': str(e)}
    
    return results

# Save results to file
def save_results(data, filename):
    try:
        with open(filename, 'w') as f:
            if isinstance(data, dict):
                json.dump(data, f, indent=4)
            else:
                f.write(str(data))
        print(f"\033[1;32m[+] Results saved to: {filename}\033[0m")
    except Exception as e:
        print(f"\033[1;31m[-] Error saving results: {e}\033[0m")

# Main menu
def main_menu():
    print_banner()
    print("\033[1;36m1. Domain Information Gathering")
    print("2. IP Address Information Gathering")
    print("3. Email Information Gathering")
    print("4. Phone Number Information Gathering")
    print("5. Exit\033[0m")
    print()
    
    try:
        choice = input("\033[1;33mSelect an option (1-5): \033[0m")
        
        if choice == "1":
            target = input("Enter domain name (example.com): ").strip()
            if target:
                results = domain_info_gathering(target)
                print("\n\033[1;32m[+] Domain Information Results:\033[0m")
                print(json.dumps(results, indent=4))
                
                # Save results
                filename = f"domain_{target}_{int(time.time())}.json"
                save_results(results, filename)
            else:
                print("\033[1;31m[-] Please enter a valid domain\033[0m")
        
        elif choice == "2":
            target = input("Enter IP address: ").strip()
            if target:
                results = ip_info_gathering(target)
                print("\n\033[1;32m[+] IP Information Results:\033[0m")
                print(json.dumps(results, indent=4))
                
                # Save results
                filename = f"ip_{target}_{int(time.time())}.json"
                save_results(results, filename)
            else:
                print("\033[1;31m[-] Please enter a valid IP address\033[0m")
        
        elif choice == "3":
            target = input("Enter email address: ").strip()
            if target:
                results = email_info_gathering(target)
                print("\n\033[1;32m[+] Email Information Results:\033[0m")
                print(json.dumps(results, indent=4))
                
                # Save results
                filename = f"email_{target}_{int(time.time())}.json"
                save_results(results, filename)
            else:
                print("\033[1;31m[-] Please enter a valid email address\033[0m")
        
        elif choice == "4":
            target = input("Enter phone number: ").strip()
            if target:
                results = phone_info_gathering(target)
                print("\n\033[1;32m[+] Phone Information Results:\033[0m")
                print(json.dumps(results, indent=4))
                
                # Save results
                filename = f"phone_{target}_{int(time.time())}.json"
                save_results(results, filename)
            else:
                print("\033[1;31m[-] Please enter a valid phone number\033[0m")
        
        elif choice == "5":
            print("\033[1;32m[+] Thank you for using HCO OSINT Tool. Goodbye!\033[0m")
            sys.exit(0)
        
        else:
            print("\033[1;31m[-] Invalid option. Please try again.\033[0m")
    
    except KeyboardInterrupt:
        print("\n\033[1;32m[+] Operation cancelled by user. Exiting...\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\033[1;31m[-] An error occurred: {e}\033[0m")

# Main function
def main():
    # Check dependencies
    if not check_dependencies():
        print("\033[1;31m[-] Failed to install required dependencies. Exiting...\033[0m")
        sys.exit(1)
    
    # Main loop
    while True:
        main_menu()
        print()
        input("\033[1;33mPress Enter to continue...\033[0m")

if __name__ == "__main__":
    main()
