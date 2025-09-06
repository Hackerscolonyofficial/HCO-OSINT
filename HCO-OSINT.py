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
"""

import os
import sys
import time
import requests
import webbrowser
import json
import socket
import re
import subprocess
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
        try:
            with open(UNLOCK_FILE, "r") as f:
                content = f.read().strip()
                if content == "unlocked":
                    return
        except:
            pass

    os.system("clear")
    print(Fore.RED + Style.BRIGHT + "══════════════════════════════════════════════════════")
    print(Fore.RED + Style.BRIGHT + "                🔒 TOOL IS LOCKED 🔒                 ")
    print(Fore.RED + Style.BRIGHT + "══════════════════════════════════════════════════════")
    print(Fore.CYAN + "  You must subscribe to Hackers Colony Tech")
    print(Fore.CYAN + "  and click the bell 🔔 icon to unlock the tool")
    print(Fore.RED + Style.BRIGHT + "══════════════════════════════════════════════════════")
    print(Fore.YELLOW + "  We will redirect you to our YouTube channel")
    print(Fore.YELLOW + "  Subscribe and click the bell icon to unlock 🔓 the tool")
    print(Fore.RED + Style.BRIGHT + "══════════════════════════════════════════════════════")
    
    # Countdown with red numbers
    print(Fore.RED + Style.BRIGHT + "\n  Redirecting in: ")
    for i in range(9, 0, -1):
        if i > 5:
            color = Fore.RED
        elif i > 2:
            color = Fore.YELLOW
        else:
            color = Fore.GREEN
            
        print(color + Style.BRIGHT + f"  {i}", end=" ", flush=True)
        time.sleep(1)
    
    print(Fore.GREEN + Style.BRIGHT + " 0")
    
    try:
        os.system("termux-open-url 'https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya'")
    except:
        webbrowser.open("https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya")

    time.sleep(3)
    
    print(Fore.GREEN + "\n\nTool unlocked! Loading HCO-OSINT...")
    with open(UNLOCK_FILE, "w") as f:
        f.write("unlocked")
    time.sleep(2)

# ---------- Banner ----------
def banner():
    os.system("clear")
    print(Fore.BLUE + Style.BRIGHT + "╔══════════════════════════════════════════════════════╗")
    print(Fore.BLUE + Style.BRIGHT + "║" + Fore.RED + Style.BRIGHT + "        🚀 HCO-OSINT TOOL 🚀         " + Fore.BLUE + Style.BRIGHT + "║")
    print(Fore.BLUE + Style.BRIGHT + "║" + Fore.RED + Style.BRIGHT + "    By Azhar - Hackers Colony Team    " + Fore.BLUE + Style.BRIGHT + "║")
    print(Fore.BLUE + Style.BRIGHT + "╚══════════════════════════════════════════════════════╝")
    print()

# ---------- Advanced OSINT Functions ----------
def ip_lookup():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ").strip()
    if not ip:
        print(Fore.RED + "[-] IP address cannot be empty!")
        return
        
    try:
        socket.inet_aton(ip)
        print(Fore.YELLOW + "\n[*] Gathering information...")
        
        # IP-API
        r1 = requests.get(f"http://ip-api.com/json/{ip}", timeout=10).json()
        if r1.get('status') == 'success':
            print(Fore.GREEN + "\n[+] IP Lookup Results:\n")
            print(f"{Fore.YELLOW}IP: {Fore.WHITE}{r1.get('query', 'N/A')}")
            print(f"{Fore.YELLOW}Country: {Fore.WHITE}{r1.get('country', 'N/A')}")
            print(f"{Fore.YELLOW}Region: {Fore.WHITE}{r1.get('regionName', 'N/A')}")
            print(f"{Fore.YELLOW}City: {Fore.WHITE}{r1.get('city', 'N/A')}")
            print(f"{Fore.YELLOW}ISP: {Fore.WHITE}{r1.get('isp', 'N/A')}")
            print(f"{Fore.YELLOW}Organization: {Fore.WHITE}{r1.get('org', 'N/A')}")
            print(f"{Fore.YELLOW}ASN: {Fore.WHITE}{r1.get('as', 'N/A')}")
            print(f"{Fore.YELLOW}Lat/Lon: {Fore.WHITE}{r1.get('lat', 'N/A')}, {r1.get('lon', 'N/A')}")
            print(f"{Fore.YELLOW}Timezone: {Fore.WHITE}{r1.get('timezone', 'N/A')}")
            
    except socket.error:
        print(Fore.RED + "[-] Invalid IP address format")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

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
        print(Fore.YELLOW + "\n[*] Performing WHOIS lookup...")
        r = requests.get(f"https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName={parsed}&apiKey=demo", timeout=10)
        if r.status_code == 200:
            data = r.json()
            print(Fore.GREEN + "\n[+] Domain Information:\n")
            print(f"{Fore.YELLOW}Domain: {Fore.WHITE}{data.get('domain_name', 'N/A')}")
            print(f"{Fore.YELLOW}Created: {Fore.WHITE}{data.get('create_date', 'N/A')}")
            print(f"{Fore.YELLOW}Expires: {Fore.WHITE}{data.get('expire_date', 'N/A')}")
            print(f"{Fore.YELLOW}Registrar: {Fore.WHITE}{data.get('registrar', 'N/A')}")
            print(f"{Fore.YELLOW}Status: {Fore.WHITE}{data.get('domain_status', 'N/A')}")
        else:
            print(Fore.RED + "[-] WHOIS lookup failed")
                
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

def headers_lookup():
    url = input(Fore.CYAN + "\n[?] Enter URL: ").strip()
    if not url:
        print(Fore.RED + "[-] URL cannot be empty!")
        return
        
    if not url.startswith("http"):
        url = "http://" + url
        
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        r = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        print(Fore.GREEN + "\n[+] HTTP Headers:\n")
        
        for k, v in r.headers.items():
            print(f"{Fore.YELLOW}{k:<25}: {Fore.WHITE}{v}")
                
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

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
        print(f"{Fore.YELLOW}Country: {Fore.WHITE}{geocoder.description_for_number(pn, 'en')}")
        print(f"{Fore.YELLOW}Carrier: {Fore.WHITE}{carrier.name_for_number(pn, 'en')}")
        print(f"{Fore.YELLOW}Time Zones: {Fore.WHITE}{timezone.time_zones_for_number(pn)}")
        print(f"{Fore.YELLOW}Type: {Fore.WHITE}{phonenumbers.number_type(pn)}")
        print(f"{Fore.YELLOW}Valid: {Fore.WHITE}{phonenumbers.is_valid_number(pn)}")
        print(f"{Fore.YELLOW}Possible: {Fore.WHITE}{phonenumbers.is_possible_number(pn)}")
            
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

def email_lookup():
    email = input(Fore.CYAN + "\n[?] Enter Email: ").strip()
    if not email:
        print(Fore.RED + "[-] Email cannot be empty!")
        return
        
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        print(Fore.RED + "[-] Invalid email format")
        return
        
    domain = email.split("@")[-1]
    print(Fore.GREEN + f"\n[+] Email Lookup Results for {email}:\n")
    
    try:
        # MX Records with custom resolver - FIXED DNS ISSUE
        print(Fore.YELLOW + "[*] Checking MX records...")
        try:
            # Create a resolver with public DNS servers
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']  # Google and Cloudflare DNS
            
            answers = resolver.resolve(domain, 'MX')
            print(Fore.GREEN + "[+] MX Records found:")
            for rdata in answers:
                print(f"{Fore.WHITE}- {rdata.exchange} (priority {rdata.preference})")
        except dns.resolver.NoAnswer:
            print(Fore.RED + "[-] No MX records found")
        except dns.resolver.NXDOMAIN:
            print(Fore.RED + f"[-] Domain {domain} does not exist")
        except Exception as e:
            print(Fore.RED + f"[-] Error checking MX records: {str(e)}")
            
        # Check if domain exists
        print(Fore.YELLOW + "[*] Checking domain information...")
        try:
            # Try to get A record
            a_records = resolver.resolve(domain, 'A')
            print(Fore.GREEN + f"[+] Domain is active with {len(a_records)} IP addresses")
        except:
            print(Fore.RED + "[-] Domain may not be active")
            
        # Email breach check (simulated)
        print(Fore.YELLOW + "[*] Checking for data breaches...")
        print(Fore.YELLOW + "[i] This would check HaveIBeenPwned in full version")
        print(Fore.YELLOW + "[i] For full breach checking, API key is required")
        
    except Exception as e:
        print(Fore.RED + f"[-] Error: {str(e)}")

def username_lookup():
    username = input(Fore.CYAN + "\n[?] Enter Username: ").strip()
    if not username:
        print(Fore.RED + "[-] Username cannot be empty!")
        return
        
    print(Fore.GREEN + f"\n[+] Searching for '{username}' across platforms:\n")
    
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Facebook": f"https://facebook.com/{username}",
        "Reddit": f"https://reddit.com/user/{username}",
        "YouTube": f"https://youtube.com/@{username}",
        "LinkedIn": f"https://linkedin.com/in/{username}",
    }
    
    for name, url in platforms.items():
        print(f"{Fore.YELLOW}{name}: {Fore.WHITE}{url}")

def dns_lookup():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ").strip()
    if not domain:
        print(Fore.RED + "[-] Domain cannot be empty!")
        return
        
    try:
        print(Fore.GREEN + f"\n[+] DNS Records for {domain}:\n")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        # Use public DNS servers to avoid resolv.conf issues
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        
        for record_type in record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                print(Fore.YELLOW + f"{record_type} Records:")
                for rdata in answers:
                    print(f"  {Fore.WHITE}{rdata}")
                print()
            except:
                continue
                
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

def whois_lookup():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ").strip()
    if not domain:
        print(Fore.RED + "[-] Domain cannot be empty!")
        return
        
    try:
        print(Fore.YELLOW + "\n[*] Performing WHOIS lookup...")
        r = requests.get(f"https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName={domain}&apiKey=demo", timeout=10)
        if r.status_code == 200:
            data = r.json()
            print(Fore.GREEN + "\n[+] WHOIS Information:\n")
            for key, value in data.items():
                if value and key not in ['whois_data', 'domain_name_unicode']:
                    print(f"{Fore.YELLOW}{key}: {Fore.WHITE}{value}")
        else:
            print(Fore.RED + "[-] WHOIS lookup failed")
                
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

def subdomain_scan():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ").strip()
    if not domain:
        print(Fore.RED + "[-] Domain cannot be empty!")
        return
        
    print(Fore.YELLOW + f"\n[*] Scanning for subdomains of {domain}...")
    
    subdomains = [
        'www', 'mail', 'ftp', 'admin', 'webmail', 'server', 'ns1', 'ns2',
        'test', 'dev', 'blog', 'forum', 'shop', 'api', 'cdn', 'static'
    ]
    
    found = []
    for sub in subdomains:
        url = f"http://{sub}.{domain}"
        try:
            requests.get(url, timeout=3)
            found.append(url)
            print(Fore.GREEN + f"[+] Found: {url}")
        except:
            continue
    
    print(Fore.GREEN + f"\n[+] Found {len(found)} subdomains")

def reverse_ip():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ").strip()
    if not ip:
        print(Fore.RED + "[-] IP address cannot be empty!")
        return
        
    try:
        socket.inet_aton(ip)
        print(Fore.YELLOW + f"\n[*] Looking up domains on {ip}...")
        
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=15)
        if r.status_code == 200 and "error" not in r.text.lower():
            domains = r.text.strip().split('\n')
            if domains and domains[0]:
                print(Fore.GREEN + f"\n[+] Found {len(domains)} domains:")
                for domain in domains:
                    print(Fore.WHITE + f"  - {domain}")
            else:
                print(Fore.RED + "[-] No domains found")
        else:
            print(Fore.RED + "[-] Reverse IP lookup failed")
            
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

def trace_route():
    host = input(Fore.CYAN + "\n[?] Enter Host/Domain: ").strip()
    if not host:
        print(Fore.RED + "[-] Host cannot be empty!")
        return
        
    try:
        print(Fore.YELLOW + "\n[*] Performing traceroute...")
        result = subprocess.run(['traceroute', host], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(Fore.GREEN + "\n[+] Traceroute Results:\n")
            print(Fore.WHITE + result.stdout)
        else:
            print(Fore.RED + "[-] Traceroute failed")
                
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

def geoip_lookup():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ").strip()
    if not ip:
        print(Fore.RED + "[-] IP address cannot be empty!")
        return
        
    try:
        socket.inet_aton(ip)
        print(Fore.YELLOW + "\n[*] Getting GeoIP information...")
        
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get('status') == 'success':
                print(Fore.GREEN + "\n[+] GeoIP Information:\n")
                print(f"{Fore.YELLOW}IP: {Fore.WHITE}{data.get('query', 'N/A')}")
                print(f"{Fore.YELLOW}Country: {Fore.WHITE}{data.get('country', 'N/A')}")
                print(f"{Fore.YELLOW}City: {Fore.WHITE}{data.get('city', 'N/A')}")
                print(f"{Fore.YELLOW}ISP: {Fore.WHITE}{data.get('isp', 'N/A')}")
                print(f"{Fore.YELLOW}Lat/Lon: {Fore.WHITE}{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
            else:
                print(Fore.RED + "[-] GeoIP lookup failed")
        else:
            print(Fore.RED + "[-] GeoIP lookup failed")
            
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

def port_scan():
    host = input(Fore.CYAN + "\n[?] Enter Host/IP: ").strip()
    if not host:
        print(Fore.RED + "[-] Host cannot be empty!")
        return
        
    try:
        try:
            ip = socket.gethostbyname(host)
        except:
            print(Fore.RED + "[-] Could not resolve hostname")
            return
            
        print(Fore.YELLOW + f"\n[*] Scanning ports on {ip}...")
        
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3389]
        open_ports = []
        
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        print(Fore.GREEN + f"[+] Port {port}/tcp open ({service})")
            except:
                continue
        
        if open_ports:
            print(Fore.GREEN + f"\n[+] Found {len(open_ports)} open ports")
        else:
            print(Fore.RED + "[-] No open ports found")
            
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

def social_media_lookup():
    username = input(Fore.CYAN + "\n[?] Enter Username: ").strip()
    if not username:
        print(Fore.RED + "[-] Username cannot be empty!")
        return
        
    print(Fore.GREEN + f"\n[+] Social Media Profiles for '{username}':\n")
    
    platforms = {
        "Instagram": f"https://instagram.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Facebook": f"https://facebook.com/{username}",
        "LinkedIn": f"https://linkedin.com/in/{username}",
        "YouTube": f"https://youtube.com/@{username}",
        "Reddit": f"https://reddit.com/user/{username}",
        "GitHub": f"https://github.com/{username}",
        "Pinterest": f"https://pinterest.com/{username}",
    }
    
    for name, url in platforms.items():
        print(f"{Fore.YELLOW}{name}: {Fore.WHITE}{url}")

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
