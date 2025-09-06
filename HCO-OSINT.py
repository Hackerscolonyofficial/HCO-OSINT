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
══════════════════════════════════════════════════════
"""

import os
import sys
import time
import requests
import webbrowser
from colorama import Fore, Style, init
import dns.resolver
from urllib.parse import urlparse

# Initialize colorama
init(autoreset=True)

# Path to store device-wide unlock flag
UNLOCK_FILE = os.path.expanduser("~/.hco_osint_unlock")

# ---------- Unlock / YouTube Redirect ----------
def unlock():
    if os.path.exists(UNLOCK_FILE):
        return  # Already unlocked

    os.system("clear")
    print(Fore.RED + Style.BRIGHT + "══════════════════════════════════════")
    print(Fore.RED + Style.BRIGHT + "       🔒 HCO-OSINT Tool Locked 🔒       ")
    print(Fore.CYAN + "You must subscribe to Hackers Colony Tech")
    print(Fore.CYAN + "and click the bell 🔔 to unlock the tool.")
    print(Fore.RED + Style.BRIGHT + "══════════════════════════════════════\n")

    # Countdown
    for i in range(8, 0, -1):
        print(Fore.YELLOW + f"Redirecting to YouTube in {i} seconds...", end="\r")
        time.sleep(1)

    # Open YouTube channel
    youtube_link = "https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya"
    webbrowser.open(youtube_link)

    input(Fore.GREEN + "\nPress Enter after subscribing to continue...")

    # Create unlock file
    with open(UNLOCK_FILE, "w") as f:
        f.write("unlocked")

# ---------- Banner ----------
def banner():
    os.system("clear")
    print(Fore.MAGENTA + Style.BRIGHT + """
╔══════════════════════════════════════╗
║        🚀 HCO-OSINT TOOL 🚀          ║
║    By Azhar - Hackers Colony Team    ║
╚══════════════════════════════════════╝
""")

# ---------- OSINT Functions ----------
def ip_lookup():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ")
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}").json()
        print(Fore.GREEN + "\n[+] IP Lookup Results:\n")
        for k, v in r.items():
            print(f"{Fore.YELLOW}{k.title():<15}: {Fore.WHITE}{v}")
    except:
        print(Fore.RED + "Error in IP Lookup")

def domain_lookup():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ")
    if not domain.startswith("http"):
        domain = "http://" + domain
    parsed = urlparse(domain).netloc
    try:
        r = requests.get(f"https://api.hackertarget.com/whois/?q={parsed}")
        print(Fore.GREEN + "\n[+] Domain Lookup Results:\n")
        print(Fore.WHITE + r.text)
    except:
        print(Fore.RED + "Error in Domain Lookup")

def headers_lookup():
    url = input(Fore.CYAN + "\n[?] Enter URL: ")
    if not url.startswith("http"):
        url = "http://" + url
    try:
        r = requests.get(url)
        print(Fore.GREEN + "\n[+] HTTP Headers:\n")
        for k, v in r.headers.items():
            print(f"{Fore.YELLOW}{k:<20}: {Fore.WHITE}{v}")
    except:
        print(Fore.RED + "Error in HTTP Headers Lookup")

def phone_lookup():
    number = input(Fore.CYAN + "\n[?] Enter Phone Number (with country code): ")
    country_code = ''.join(filter(str.isdigit, number.split('+')[-1][:3]))
    print(Fore.GREEN + "\n[+] Phone Lookup Results:\n")
    print(Fore.YELLOW + "Country Code : " + Fore.WHITE + (country_code if country_code else "N/A"))
    print(Fore.YELLOW + "Carrier      : " + Fore.WHITE + "N/A")
    print(Fore.YELLOW + "Line Type    : " + Fore.WHITE + "N/A")

def email_lookup():
    email = input(Fore.CYAN + "\n[?] Enter Email: ")
    domain = email.split("@")[-1]
    print(Fore.GREEN + "\n[+] Email Lookup Results:\n")
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            print(f"{Fore.YELLOW}- {Fore.WHITE}{rdata.exchange}")
    except dns.resolver.NoAnswer:
        print(Fore.YELLOW + "No MX record found for this domain.")
    except dns.resolver.NXDOMAIN:
        print(Fore.RED + "Domain does not exist.")
    except Exception as e:
        print(Fore.RED + f"Error in Email Lookup: {e}")

def username_lookup():
    username = input(Fore.CYAN + "\n[?] Enter Username: ")
    print(Fore.GREEN + f"\n[+] Searching for username '{username}' across platforms...\n")
    platforms = ["github.com", "twitter.com", "instagram.com", "facebook.com", "t.me"]
    for site in platforms:
        print(f"{Fore.YELLOW}{site:<20}: {Fore.WHITE}https://{site}/{username}")

def dns_lookup():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/dnslookup/?q={domain}")
        print(Fore.GREEN + "\n[+] DNS Lookup Results:\n")
        print(Fore.WHITE + r.text)
    except:
        print(Fore.RED + "Error in DNS Lookup")

def whois_lookup():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/whois/?q={domain}")
        print(Fore.GREEN + "\n[+] WHOIS Lookup Results:\n")
        print(Fore.WHITE + r.text)
    except:
        print(Fore.RED + "Error in WHOIS Lookup")

def subdomain_scan():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        print(Fore.GREEN + "\n[+] Subdomain Scan Results:\n")
        print(Fore.WHITE + r.text)
    except:
        print(Fore.RED + "Error in Subdomain Scan")

def reverse_ip():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        print(Fore.GREEN + "\n[+] Reverse IP Results:\n")
        print(Fore.WHITE + r.text)
    except:
        print(Fore.RED + "Error in Reverse IP Lookup")

def trace_route():
    host = input(Fore.CYAN + "\n[?] Enter Host/Domain: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/mtr/?q={host}")
        print(Fore.GREEN + "\n[+] Traceroute:\n")
        print(Fore.WHITE + r.text)
    except:
        print(Fore.RED + "Error in Traceroute")

def geoip_lookup():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ")
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json").json()
        print(Fore.GREEN + "\n[+] GeoIP Information:\n")
        for k, v in r.items():
            print(f"{Fore.YELLOW}{k.title():<15}: {Fore.WHITE}{v}")
    except:
        print(Fore.RED + "Error in GeoIP Lookup")

def port_scan():
    host = input(Fore.CYAN + "\n[?] Enter Host/IP: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/nmap/?q={host}")
        print(Fore.GREEN + "\n[+] Port Scan Results:\n")
        print(Fore.WHITE + r.text)
    except:
        print(Fore.RED + "Error in Port Scan")

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
[0]  Exit
""")

# ---------- Main ----------
def main():
    unlock()  # Run unlock first
    while True:
        menu()
        choice = input(Fore.YELLOW + "[?] Select option: ")

        if choice == "1": ip_lookup()
        elif choice == "2": domain_lookup()
        elif choice == "3": headers_lookup()
        elif choice == "4": phone_lookup()
        elif choice == "5": email_lookup()
        elif choice == "6": username_lookup()
        elif choice == "7": dns_lookup()
        elif choice == "8": whois_lookup()
        elif choice == "9": subdomain_scan()
        elif choice == "10": reverse_ip()
        elif choice == "11": trace_route()
        elif choice == "12": geoip_lookup()
        elif choice == "13": port_scan()
        elif choice == "0":
            print(Fore.GREEN + "\nExiting... Bye!\n")
            sys.exit()
        else:
            print(Fore.RED + "Invalid Choice!")

        input(Fore.CYAN + "\nPress Enter to continue...")

if __name__ == "__main__":
    main()
