#!/usr/bin/env python3
"""
══════════════════════════════════════════════════════
🚀🔍 HCO-OSINT - Advanced OSINT Tool by Azhar 🔍🚀
══════════════════════════════════════════════════════

📺 YouTube : https://youtube.com/@hackers_colony_tech
📷 Instagram : https://www.instagram.com/hackers_colony_official
💬 Telegram : https://t.me/hackersColony
💻 Website : https://hackerscolonyofficial.blogspot.com/?m=1
🎭 Discord : https://discord.gg/Xpq9nCGD

Disclaimer ⚠️  
This tool is made for **educational and research purposes only**.  
Hackers Colony or Azhar will not be responsible for any misuse.  

✨ Code by Azhar (Hackers Colony)

Requirements:
colorama
requests
dnspython
phonenumbers
"""

import os
import sys
import time
import requests
import webbrowser
import json
import socket
import re
from colorama import Fore, Style, init
import dns.resolver
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from urllib.parse import urlparse
import concurrent.futures

# Initialize colorama
init(autoreset=True)

# Path to store unlock flag
UNLOCK_FILE = os.path.expanduser("~/.hco_osint_unlock")

# ---------- Unlock / YouTube Redirect ----------
def unlock():
    if os.path.exists(UNLOCK_FILE):
        # Check if the file has valid content
        try:
            with open(UNLOCK_FILE, "r") as f:
                content = f.read().strip()
                if content == "unlocked":
                    return
        except:
            pass

    os.system("clear")
    print(Fore.RED + Style.BRIGHT + "══════════════════════════════════════════════════════")
    print(Fore.RED + Style.BRIGHT + "       🔒 HCO-OSINT Tool Locked 🔒       ")
    print(Fore.CYAN + "You must subscribe to Hackers Colony Tech")
    print(Fore.CYAN + "and click the bell 🔔 to unlock the tool.")
    print(Fore.RED + Style.BRIGHT + "══════════════════════════════════════════════════════\n")
    print(Fore.YELLOW + "Note: After subscribing, the tool will redirect you back automatically.")

    for i in range(5, 0, -1):
        print(Fore.YELLOW + f"Redirecting to YouTube in {i} seconds...", end="\r")
        time.sleep(1)

    try:
        # Try using termux on Android
        os.system("termux-open-url 'https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya'")
    except:
        # Fallback for other systems
        webbrowser.open("https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya")

    # Wait a bit for the browser to open
    time.sleep(3)
    
    # Create the unlock file
    with open(UNLOCK_FILE, "w") as f:
        f.write("unlocked")
    
    print(Fore.GREEN + "\nTool unlocked! Loading HCO-OSINT...")
    time.sleep(2)

# ---------- Banner ----------
def banner():
    os.system("clear")
    print(Fore.MAGENTA + Style.BRIGHT + """
╔══════════════════════════════════════════════════════╗
║        🚀 HCO-OSINT TOOL 🚀          ║
║    By Azhar - Hackers Colony Team    ║
╚══════════════════════════════════════════════════════╝
""")

# ---------- Advanced OSINT Functions ----------
def ip_lookup():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ").strip()
    if not ip:
        print(Fore.RED + "[-] IP address cannot be empty!")
        return
        
    try:
        # Validate IP format
        socket.inet_aton(ip)
        
        # Use multiple sources for IP lookup
        print(Fore.YELLOW + "\n[*] Gathering information from multiple sources...")
        
        # Source 1: ip-api.com
        r1 = requests.get(f"http://ip-api.com/json/{ip}", timeout=10).json()
        if r1.get('status') == 'success':
            print(Fore.GREEN + "\n[+] IP Lookup Results (ip-api.com):\n")
            print(f"{Fore.YELLOW}IP:{' ':12}{Fore.WHITE}{r1.get('query', 'N/A')}")
            print(f"{Fore.YELLOW}Country:{' ':8}{Fore.WHITE}{r1.get('country', 'N/A')}")
            print(f"{Fore.YELLOW}Region:{' ':9}{Fore.WHITE}{r1.get('regionName', 'N/A')}")
            print(f"{Fore.YELLOW}City:{' ':11}{Fore.WHITE}{r1.get('city', 'N/A')}")
            print(f"{Fore.YELLOW}ISP:{' ':12}{Fore.WHITE}{r1.get('isp', 'N/A')}")
            print(f"{Fore.YELLOW}Organization:{' ':4}{Fore.WHITE}{r1.get('org', 'N/A')}")
            print(f"{Fore.YELLOW}ASN:{' ':12}{Fore.WHITE}{r1.get('as', 'N/A')}")
            print(f"{Fore.YELLOW}Latitude:{' ':8}{Fore.WHITE}{r1.get('lat', 'N/A')}")
            print(f"{Fore.YELLOW}Longitude:{' ':7}{Fore.WHITE}{r1.get('lon', 'N/A')}")
            print(f"{Fore.YELLOW}Timezone:{' ':8}{Fore.WHITE}{r1.get('timezone', 'N/A')}")
            print(f"{Fore.YELLOW}ZIP:{' ':12}{Fore.WHITE}{r1.get('zip', 'N/A')}")
        else:
            print(Fore.RED + "[-] ip-api.com lookup failed")
            
        # Source 2: ipinfo.io (with token if available)
        try:
            r2 = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10).json()
            print(Fore.GREEN + "\n[+] Additional Information (ipinfo.io):\n")
            if 'hostname' in r2:
                print(f"{Fore.YELLOW}Hostname:{' ':8}{Fore.WHITE}{r2.get('hostname', 'N/A')}")
            if 'anycast' in r2:
                print(f"{Fore.YELLOW}Anycast:{' ':9}{Fore.WHITE}{r2.get('anycast', 'N/A')}")
            if 'company' in r2:
                print(f"{Fore.YELLOW}Company:{' ':9}{Fore.WHITE}{r2.get('company', {}).get('name', 'N/A')}")
        except:
            print(Fore.RED + "[-] ipinfo.io lookup failed")
            
    except socket.error:
        print(Fore.RED + "[-] Invalid IP address format")
    except requests.RequestException as e:
        print(Fore.RED + f"[-] Network error: {e}")
    except Exception as e:
        print(Fore.RED + f"[-] Error in IP Lookup: {e}")

def domain_lookup():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ").strip()
    if not domain:
        print(Fore.RED + "[-] Domain cannot be empty!")
        return
        
    if not domain.startswith("http"):
        domain = "http://" + domain
        
    parsed = urlparse(domain).netloc
    if not parsed:
        print(Fore.RED + "[-] Invalid domain format")
        return
        
    try:
        # WHOIS lookup
        r = requests.get(f"https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName={parsed}&apiKey=demo", timeout=10)
        if r.status_code == 200:
            data = r.json()
            print(Fore.GREEN + "\n[+] Domain Lookup Results:\n")
            
            if 'create_date' in data:
                print(f"{Fore.YELLOW}Created:{' ':9}{Fore.WHITE}{data.get('create_date', 'N/A')}")
            if 'update_date' in data:
                print(f"{Fore.YELLOW}Updated:{' ':9}{Fore.WHITE}{data.get('update_date', 'N/A')}")
            if 'expire_date' in data:
                print(f"{Fore.YELLOW}Expires:{' ':9}{Fore.WHITE}{data.get('expire_date', 'N/A')}")
            if 'registrar' in data:
                print(f"{Fore.YELLOW}Registrar:{' ':7}{Fore.WHITE}{data.get('registrar', 'N/A')}")
            if 'registrant_organization' in data:
                print(f"{Fore.YELLOW}Organization:{' ':4}{Fore.WHITE}{data.get('registrant_organization', 'N/A')}")
            if 'registrant_country' in data:
                print(f"{Fore.YELLOW}Country:{' ':8}{Fore.WHITE}{data.get('registrant_country', 'N/A')}")
                
        else:
            print(Fore.RED + "[-] WHOIS lookup failed, trying alternative...")
            # Fallback to hackertarget
            r2 = requests.get(f"https://api.hackertarget.com/whois/?q={parsed}", timeout=10)
            if r2.status_code == 200:
                print(Fore.GREEN + "\n[+] WHOIS Results:\n")
                print(Fore.WHITE + r2.text)
            else:
                print(Fore.RED + "[-] All WHOIS lookups failed")
                
    except requests.RequestException as e:
        print(Fore.RED + f"[-] Network error: {e}")
    except Exception as e:
        print(Fore.RED + f"[-] Error in Domain Lookup: {e}")

def headers_lookup():
    url = input(Fore.CYAN + "\n[?] Enter URL: ").strip()
    if not url:
        print(Fore.RED + "[-] URL cannot be empty!")
        return
        
    if not url.startswith("http"):
        url = "http://" + url
        
    try:
        # Send request with custom headers to look more like a browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        r = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        print(Fore.GREEN + "\n[+] HTTP Headers:\n")
        
        security_headers = [
            'server', 'x-powered-by', 'x-frame-options', 'x-content-type-options',
            'strict-transport-security', 'content-security-policy', 'x-xss-protection'
        ]
        
        for k, v in r.headers.items():
            if k.lower() in security_headers:
                print(f"{Fore.YELLOW}{k:<25}: {Fore.GREEN}{v}")
            else:
                print(f"{Fore.YELLOW}{k:<25}: {Fore.WHITE}{v}")
                
        # Check for common security headers
        print(Fore.GREEN + "\n[+] Security Analysis:\n")
        security_issues = []
        if 'x-frame-options' not in r.headers:
            security_issues.append("Missing X-Frame-Options (clickjacking protection)")
        if 'x-content-type-options' not in r.headers:
            security_issues.append("Missing X-Content-Type-Options (MIME sniffing protection)")
        if 'strict-transport-security' not in r.headers and url.startswith('https'):
            security_issues.append("Missing HSTS header (HTTPS enforcement)")
            
        if security_issues:
            for issue in security_issues:
                print(Fore.RED + f"[-] {issue}")
        else:
            print(Fore.GREEN + "[+] Basic security headers are present")
            
    except requests.RequestException as e:
        print(Fore.RED + f"[-] Error fetching URL: {e}")
    except Exception as e:
        print(Fore.RED + f"[-] Error in HTTP Headers Lookup: {e}")

def phone_lookup():
    number = input(Fore.CYAN + "\n[?] Enter Phone Number (with country code): ").strip()
    if not number:
        print(Fore.RED + "[-] Phone number cannot be empty!")
        return
        
    try:
        pn = phonenumbers.parse(number)
        if not phonenumbers.is_valid_number(pn):
            print(Fore.RED + "[-] Invalid phone number")
            return
            
        print(Fore.GREEN + "\n[+] Phone Lookup Results:\n")
        print(Fore.YELLOW + "Country      : " + Fore.WHITE + str(geocoder.description_for_number(pn, "en")))
        print(Fore.YELLOW + "Carrier      : " + Fore.WHITE + str(carrier.name_for_number(pn, "en")))
        print(Fore.YELLOW + "Time Zones   : " + Fore.WHITE + str(timezone.time_zones_for_number(pn)))
        print(Fore.YELLOW + "Line Type    : " + Fore.WHITE + str(phonenumbers.number_type(pn)))
        print(Fore.YELLOW + "Is Valid     : " + Fore.WHITE + str(phonenumbers.is_valid_number(pn)))
        print(Fore.YELLOW + "Is Possible  : " + Fore.WHITE + str(phonenumbers.is_possible_number(pn)))
        
        # Try to get additional information from numverify (free tier)
        try:
            api_key = "demo"  # Replace with your API key for full functionality
            r = requests.get(f"http://apilayer.net/api/validate?access_key={api_key}&number={number}&format=1", timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get('valid'):
                    print(Fore.YELLOW + "Line Type    : " + Fore.WHITE + data.get('line_type', 'N/A'))
                    print(Fore.YELLOW + "Carrier      : " + Fore.WHITE + data.get('carrier', 'N/A'))
                    print(Fore.YELLOW + "Country Code : " + Fore.WHITE + data.get('country_code', 'N/A'))
                    print(Fore.YELLOW + "Location     : " + Fore.WHITE + data.get('location', 'N/A'))
                    print(Fore.YELLOW + "Local Format : " + Fore.WHITE + data.get('local_format', 'N/A'))
                    print(Fore.YELLOW + "Int'l Format : " + Fore.WHITE + data.get('international_format', 'N/A'))
        except:
            print(Fore.YELLOW + "\n[i] Additional phone data not available in demo mode")
            
    except phonenumbers.NumberParseException:
        print(Fore.RED + "[-] Invalid phone number format")
    except Exception as e:
        print(Fore.RED + f"[-] Error in Phone Lookup: {e}")

def email_lookup():
    email = input(Fore.CYAN + "\n[?] Enter Email: ").strip()
    if not email:
        print(Fore.RED + "[-] Email cannot be empty!")
        return
        
    # Basic email validation
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        print(Fore.RED + "[-] Invalid email format")
        return
        
    domain = email.split("@")[-1]
    print(Fore.GREEN + f"\n[+] Email Lookup Results for {email}:\n")
    
    try:
        # MX Records
        print(Fore.YELLOW + "[*] Checking MX records...")
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            print(Fore.GREEN + "[+] MX Records found:")
            for rdata in answers:
                print(f"{Fore.WHITE}- {rdata.exchange} (priority {rdata.preference})")
        except dns.resolver.NoAnswer:
            print(Fore.RED + "[-] No MX records found")
        except dns.resolver.NXDOMAIN:
            print(Fore.RED + f"[-] Domain {domain} does not exist")
            return
        except Exception as e:
            print(Fore.RED + f"[-] Error checking MX records: {e}")
            
        # Check if email exists using Hunter.io (demo mode)
        try:
            print(Fore.YELLOW + "[*] Checking email validity...")
            # This is a demo API call - you need to replace with a real API key
            r = requests.get(f"https://api.hunter.io/v2/email-verifier?email={email}&api_key=demo", timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get('data', {}).get('result') == 'deliverable':
                    print(Fore.GREEN + "[+] Email appears to be valid (deliverable)")
                else:
                    print(Fore.RED + "[-] Email may not be valid")
            else:
                print(Fore.YELLOW + "[i] Email verification service unavailable in demo mode")
        except:
            print(Fore.YELLOW + "[i] Email verification skipped (demo mode)")
            
        # Check for breaches with HaveIBeenPwned (API simulation)
        print(Fore.YELLOW + "[*] Checking for data breaches...")
        print(Fore.YELLOW + "[i] This would require API access to HIBP in full version")
        
    except Exception as e:
        print(Fore.RED + f"[-] Error in Email Lookup: {e}")

def username_lookup():
    username = input(Fore.CYAN + "\n[?] Enter Username: ").strip()
    if not username:
        print(Fore.RED + "[-] Username cannot be empty!")
        return
        
    print(Fore.GREEN + f"\n[+] Searching for username '{username}' across platforms...\n")
    
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Facebook": f"https://facebook.com/{username}",
        "Telegram": f"https://t.me/{username}",
        "Reddit": f"https://reddit.com/user/{username}",
        "YouTube": f"https://youtube.com/@{username}",
        "LinkedIn": f"https://linkedin.com/in/{username}",
        "Pinterest": f"https://pinterest.com/{username}",
        "Tumblr": f"https://{username}.tumblr.com",
        "Flickr": f"https://flickr.com/people/{username}",
        "Vimeo": f"https://vimeo.com/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Medium": f"https://medium.com/@{username}",
        "Dev.to": f"https://dev.to/{username}",
    }
    
    # Check platforms in parallel for faster results
    def check_platform(name, url):
        try:
            r = requests.get(url, timeout=5, allow_redirects=False)
            if r.status_code == 200:
                return f"{Fore.GREEN}[+] {name:<15}: {Fore.WHITE}{url}"
            elif r.status_code in [301, 302]:
                return f"{Fore.YELLOW}[?] {name:<15}: {Fore.WHITE}{url} (redirects)"
            else:
                return f"{Fore.RED}[-] {name:<15}: {Fore.WHITE}Not found"
        except:
            return f"{Fore.RED}[-] {name:<15}: {Fore.WHITE}Error checking"
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_platform = {executor.submit(check_platform, name, url): name for name, url in platforms.items()}
        for future in concurrent.futures.as_completed(future_to_platform):
            print(future.result())

def dns_lookup():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ").strip()
    if not domain:
        print(Fore.RED + "[-] Domain cannot be empty!")
        return
        
    try:
        # Get all record types
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        
        print(Fore.GREEN + f"\n[+] DNS Lookup Results for {domain}:\n")
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                print(Fore.YELLOW + f"{record_type} Records:")
                for rdata in answers:
                    print(f"  {Fore.WHITE}{rdata}")
                print()
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as e:
                print(Fore.RED + f"  Error retrieving {record_type} records: {e}")
                
    except Exception as e:
        print(Fore.RED + f"[-] Error in DNS Lookup: {e}")

def whois_lookup():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ").strip()
    if not domain:
        print(Fore.RED + "[-] Domain cannot be empty!")
        return
        
    try:
        # Use whois command if available
        try:
            import whois
            w = whois.whois(domain)
            print(Fore.GREEN + "\n[+] WHOIS Lookup Results:\n")
            
            if w.domain_name:
                print(f"{Fore.YELLOW}Domain Name:{' ':6}{Fore.WHITE}{w.domain_name}")
            if w.registrar:
                print(f"{Fore.YELLOW}Registrar:{' ':8}{Fore.WHITE}{w.registrar}")
            if w.creation_date:
                print(f"{Fore.YELLOW}Creation Date:{' ':4}{Fore.WHITE}{w.creation_date}")
            if w.expiration_date:
                print(f"{Fore.YELLOW}Expiration Date:{' ':2}{Fore.WHITE}{w.expiration_date}")
            if w.updated_date:
                print(f"{Fore.YELLOW}Updated Date:{' ':5}{Fore.WHITE}{w.updated_date}")
            if w.name_servers:
                print(f"{Fore.YELLOW}Name Servers:{' ':5}{Fore.WHITE}{', '.join(w.name_servers)}")
            if w.status:
                print(f"{Fore.YELLOW}Status:{' ':10}{Fore.WHITE}{', '.join(w.status)}")
            if w.emails:
                print(f"{Fore.YELLOW}Emails:{' ':10}{Fore.WHITE}{', '.join(w.emails)}")
                
        except ImportError:
            # Fallback to API
            r = requests.get(f"https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName={domain}&apiKey=demo", timeout=10)
            if r.status_code == 200:
                data = r.json()
                print(Fore.GREEN + "\n[+] WHOIS Lookup Results:\n")
                for key, value in data.items():
                    if value and key not in ['whois_data', 'domain_name_unicode']:
                        print(f"{Fore.YELLOW}{key:<20}: {Fore.WHITE}{value}")
            else:
                print(Fore.RED + "[-] WHOIS lookup failed")
                
    except Exception as e:
        print(Fore.RED + f"[-] Error in WHOIS Lookup: {e}")

def subdomain_scan():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ").strip()
    if not domain:
        print(Fore.RED + "[-] Domain cannot be empty!")
        return
        
    print(Fore.YELLOW + f"\n[*] Scanning for subdomains of {domain}...")
    print(Fore.YELLOW + "[*] This may take a while...\n")
    
    # Common subdomains list
    subdomains = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
        'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
        'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
        'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
        'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal',
        'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3',
        'chat', 'download', 'remote', 'db', 'forums', 'store', 'feeds', 'monitor',
        'direct', 'dc', 's', 'preview', 'dns', 'server', 'tools', 'bgp', 'msoid',
        'gallery', 'ftp2', 'members', 'live', 'content', 'sites', 'development',
        'webmaster', 'panel', 'my', 'start', 'data', 'ssl', 'search', 'staging',
        'files', 'feed', 'dhcp', 'services', 'newsite', 'lyncdiscover', 'wsus',
        'manager', 'help', 'pic', 'exchange', 'uploads', 'en', 'sharepoint', 'pic',
        'office', 'server1', 'webcon', 'portal2', 'crm', 'apps', 'host', 'adfs',
        'ad', 'git', 'svn', 'vps', 'cdn2', 'stage', 'archive', 'info', 'apps',
        'cloud', 'cms', 'backup', 'mx1', 'mx2', 'ns5', 'ns6', 'ns7', 'ns8'
    ]
    
    found_subdomains = []
    
    def check_subdomain(subdomain):
        url = f"http://{subdomain}.{domain}"
        try:
            requests.get(url, timeout=3)
            found_subdomains.append(url)
            print(Fore.GREEN + f"[+] Found: {url}")
            return url
        except:
            return None
    
    # Use threading to speed up the process
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_subdomain, sub) for sub in subdomains]
        for future in concurrent.futures.as_completed(futures):
            future.result()
    
    print(Fore.GREEN + f"\n[+] Found {len(found_subdomains)} subdomains")
    if found_subdomains:
        print(Fore.GREEN + "[+] Subdomains found:")
        for sub in found_subdomains:
            print(Fore.WHITE + f"  - {sub}")

def reverse_ip():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ").strip()
    if not ip:
        print(Fore.RED + "[-] IP address cannot be empty!")
        return
        
    try:
        # Validate IP format
        socket.inet_aton(ip)
        
        print(Fore.YELLOW + f"\n[*] Looking up domains hosted on {ip}...")
        
        # Use hackertarget API
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=15)
        if r.status_code == 200 and "error" not in r.text.lower() and "no domains" not in r.text.lower():
            domains = r.text.strip().split('\n')
            print(Fore.GREEN + f"\n[+] Found {len(domains)} domains on this IP:\n")
            for domain in domains:
                print(Fore.WHITE + f"  - {domain}")
        else:
            print(Fore.RED + "[-] No domains found or API limit reached")
            
    except socket.error:
        print(Fore.RED + "[-] Invalid IP address format")
    except Exception as e:
        print(Fore.RED + f"[-] Error in Reverse IP Lookup: {e}")

def trace_route():
    host = input(Fore.CYAN + "\n[?] Enter Host/Domain: ").strip()
    if not host:
        print(Fore.RED + "[-] Host cannot be empty!")
        return
        
    try:
        # Use system traceroute if available
        try:
            import subprocess
            result = subprocess.run(['traceroute', host], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                print(Fore.GREEN + "\n[+] Traceroute Results:\n")
                print(Fore.WHITE + result.stdout)
            else:
                # Fallback to API
                raise Exception("System traceroute failed")
        except:
            # API fallback
            r = requests.get(f"https://api.hackertarget.com/mtr/?q={host}", timeout=30)
            if r.status_code == 200:
                print(Fore.GREEN + "\n[+] Traceroute Results:\n")
                print(Fore.WHITE + r.text)
            else:
                print(Fore.RED + "[-] Traceroute failed")
                
    except Exception as e:
        print(Fore.RED + f"[-] Error in Traceroute: {e}")

def geoip_lookup():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ").strip()
    if not ip:
        print(Fore.RED + "[-] IP address cannot be empty!")
        return
        
    try:
        # Validate IP format
        socket.inet_aton(ip)
        
        # Use ipapi.co for detailed geolocation
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
        if r.status_code == 200:
            data = r.json()
            print(Fore.GREEN + "\n[+] GeoIP Information:\n")
            
            print(f"{Fore.YELLOW}IP:{' ':15}{Fore.WHITE}{data.get('ip', 'N/A')}")
            print(f"{Fore.YELLOW}City:{' ':14}{Fore.WHITE}{data.get('city', 'N/A')}")
            print(f"{Fore.YELLOW}Region:{' ':12}{Fore.WHITE}{data.get('region', 'N/A')}")
            print(f"{Fore.YELLOW}Country:{' ':11}{Fore.WHITE}{data.get('country_name', 'N/A')}")
            print(f"{Fore.YELLOW}Country Code:{' ':6}{Fore.WHITE}{data.get('country_code', 'N/A')}")
            print(f"{Fore.YELLOW}Postal Code:{' ':8}{Fore.WHITE}{data.get('postal', 'N/A')}")
            print(f"{Fore.YELLOW}Latitude:{' ':10}{Fore.WHITE}{data.get('latitude', 'N/A')}")
            print(f"{Fore.YELLOW}Longitude:{' ':9}{Fore.WHITE}{data.get('longitude', 'N/A')}")
            print(f"{Fore.YELLOW}Timezone:{' ':10}{Fore.WHITE}{data.get('timezone', 'N/A')}")
            print(f"{Fore.YELLOW}Currency:{' ':10}{Fore.WHITE}{data.get('currency', 'N/A')}")
            print(f"{Fore.YELLOW}Languages:{' ':9}{Fore.WHITE}{data.get('languages', 'N/A')}")
            print(f"{Fore.YELLOW}ASN:{' ':15}{Fore.WHITE}{data.get('asn', 'N/A')}")
            print(f"{Fore.YELLOW}Organization:{' ':6}{Fore.WHITE}{data.get('org', 'N/A')}")
            
        else:
            print(Fore.RED + "[-] GeoIP lookup failed")
            
    except socket.error:
        print(Fore.RED + "[-] Invalid IP address format")
    except Exception as e:
        print(Fore.RED + f"[-] Error in GeoIP Lookup: {e}")

def port_scan():
    host = input(Fore.CYAN + "\n[?] Enter Host/IP: ").strip()
    if not host:
        print(Fore.RED + "[-] Host cannot be empty!")
        return
        
    try:
        # Resolve host to IP if needed
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            print(Fore.RED + "[-] Could not resolve hostname")
            return
            
        print(Fore.YELLOW + f"\n[*] Scanning top ports on {ip}...")
        print(Fore.YELLOW + "[*] This may take a while...\n")
        
        # Common ports to scan
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
            993, 995, 1723, 3306, 3389, 5900, 8080
        ]
        
        open_ports = []
        
        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                        # Try to get service name
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        print(Fore.GREEN + f"[+] Port {port}/tcp open ({service})")
                    return result
            except:
                return -1
        
        # Use threading to speed up the scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_port, port) for port in common_ports]
            for future in concurrent.futures.as_completed(futures):
                future.result()
        
        if open_ports:
            print(Fore.GREEN + f"\n[+] Found {len(open_ports)} open ports")
        else:
            print(Fore.RED + "[-] No open ports found")
            
    except Exception as e:
        print(Fore.RED + f"[-] Error in Port Scan: {e}")

def social_media_lookup():
    username = input(Fore.CYAN + "\n[?] Enter Username: ").strip()
    if not username:
        print(Fore.RED + "[-] Username cannot be empty!")
        return
        
    print(Fore.GREEN + f"\n[+] Social Media Lookup for '{username}':\n")
    
    platforms = {
        "Instagram": f"https://www.instagram.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "Tumblr": f"https://{username}.tumblr.com",
        "Flickr": f"https://www.flickr.com/people/{username}",
        "Vimeo": f"https://vimeo.com/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Medium": f"https://medium.com/@{username}",
        "GitHub": f"https://github.com/{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Bitbucket": f"https://bitbucket.org/{username}",
        "Dribbble": f"https://dribbble.com/{username}",
        "Behance": f"https://www.behance.net/{username}",
        "Spotify": f"https://open.spotify.com/user/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "VK": f"https://vk.com/{username}",
        "Weibo": f"https://www.weibo.com/{username}",
    }
    
    found_profiles = []
    
    def check_platform(name, url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            r = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
            if r.status_code == 200:
                found_profiles.append((name, url))
                return f"{Fore.GREEN}[+] {name:<15}: {Fore.WHITE}{url}"
            elif r.status_code in [301, 302]:
                return f"{Fore.YELLOW}[?] {name:<15}: {Fore.WHITE}{url} (redirects)"
            else:
                return f"{Fore.RED}[-] {name:<15}: {Fore.WHITE}Not found"
        except:
            return f"{Fore.RED}[-] {name:<15}: {Fore.WHITE}Error checking"
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        future_to_platform = {executor.submit(check_platform, name, url): name for name, url in platforms.items()}
        for future in concurrent.futures.as_completed(future_to_platform):
            print(future.result())
    
    if found_profiles:
        print(Fore.GREEN + f"\n[+] Found {len(found_profiles)} social media profiles")
        print(Fore.GREEN + "[+] Profiles found:")
        for name, url in found_profiles:
            print(Fore.WHITE + f"  - {name}: {url}")

# ---------- Menu ----------
def menu():
    banner()
    print(Fore.CYAN + Style.BRIGHT + """
[1]  IP Lookup
[2]  Domain Lookup
[3]  HTTP Headers
[4]  Phone Lookup
[5]  Email Lookup
[6]  Username Lookup
[7]  DNS Lookup
[8]  WHOIS Lookup
[9]  Subdomain Scan
[10] Reverse IP Lookup
[11] Traceroute
[12] GeoIP Lookup
[13] Port Scan
[14] Social Media Lookup
[0]  Exit
""")

# ---------- Main ----------
def main():
    try:
        unlock()
        while True:
            menu()
            choice = input(Fore.YELLOW + "[?] Select option: ").strip()

            options = {
                "1": ip_lookup,
                "2": domain_lookup,
                "3": headers_lookup,
                "4": phone_lookup,
                "5": email_lookup,
                "6": username_lookup,
                "7": dns_lookup,
                "8": whois_lookup,
                "9": subdomain_scan,
                "10": reverse_ip,
                "11": trace_route,
                "12": geoip_lookup,
                "13": port_scan,
                "14": social_media_lookup
            }

            if choice == "0":
                print(Fore.GREEN + "\nExiting... Thank you for using HCO-OSINT!\n")
                sys.exit()
            elif choice in options:
                options[choice]()
            else:
                print(Fore.RED + "Invalid Choice!")

            input(Fore.CYAN + "\nPress Enter to continue...")
    except KeyboardInterrupt:
        print(Fore.RED + "\n\nExiting... Goodbye!")
        sys.exit()

if __name__ == "__main__":
    main()
