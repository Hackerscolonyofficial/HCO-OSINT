#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
This tool is made for educational and research purposes only.
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

init(autoreset=True)

# ---------------- API KEYS ----------------
SHODAN_API_KEY = "iph718pM0AvRkryYhYDWSXdEgcoa"
IPINFO_API_KEY = "d28f2d86535f4a"
WHOISXML_API_KEY = "at_yOcz6VLB6VJyKuDaAUDrI3F3fOi86"
ABSTRACT_API_KEY = "f97bc3bedb2944e8b16c02d76680fd44"

UNLOCK_FILE = os.path.expanduser("~/.hco_osint_unlock")

# ---------- Unlock / YouTube Redirect ----------
def unlock():
    if os.path.exists(UNLOCK_FILE):
        return
    os.system("clear")
    print(Fore.RED + Style.BRIGHT + "══════════════════════════════════════")
    print(Fore.RED + Style.BRIGHT + "       🔒 HCO-OSINT Tool Locked 🔒       ")
    print(Fore.CYAN + "You must subscribe to Hackers Colony Tech")
    print(Fore.CYAN + "and click the bell 🔔 to unlock the tool.")
    print(Fore.RED + Style.BRIGHT + "══════════════════════════════════════\n")
    for i in range(8, 0, -1):
        print(Fore.YELLOW + Style.BRIGHT + f"Redirecting to YouTube in {i} seconds...", end="\r")
        time.sleep(1)
    webbrowser.open("https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya")
    input(Fore.GREEN + "\nPress Enter after subscribing to continue...")
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
        r = requests.get(f"https://ipinfo.io/{ip}?token={IPINFO_API_KEY}").json()
        print(Fore.GREEN + "\n[+] IP Lookup Results:\n")
        for k, v in r.items():
            print(f"{Fore.YELLOW}{k.title():<15}: {Fore.WHITE}{v}")
    except:
        print(Fore.RED + "Error in IP Lookup")

def domain_lookup():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/whois/?q={domain}")
        print(Fore.GREEN + "\n[+] Domain Lookup Results:\n")
        print(Fore.WHITE + r.text)
    except:
        print(Fore.RED + "Error in Domain Lookup")

def headers_lookup():
    url = input(Fore.CYAN + "\n[?] Enter URL: ")
    try:
        r = requests.get(url)
        print(Fore.GREEN + "\n[+] HTTP Headers:\n")
        for k, v in r.headers.items():
            print(f"{Fore.YELLOW}{k:<20}: {Fore.WHITE}{v}")
    except:
        print(Fore.RED + "Error in HTTP Headers Lookup")

def phone_lookup():
    number = input(Fore.CYAN + "\n[?] Enter Phone Number (with country code): ")
    try:
        r = requests.get(f"https://abstractapi.com/v1/phone/validate/?api_key={ABSTRACT_API_KEY}&phone={number}").json()
        print(Fore.GREEN + "\n[+] Phone Lookup Results:\n")
        print(f"{Fore.YELLOW}Valid       : {Fore.WHITE}{r['valid']}")
        print(f"{Fore.YELLOW}Country     : {Fore.WHITE}{r['country']}")
        print(f"{Fore.YELLOW}Carrier     : {Fore.WHITE}{r['carrier']}")
        print(f"{Fore.YELLOW}Line Type   : {Fore.WHITE}{r['line_type']}")
    except:
        print(Fore.RED + "Error in Phone Lookup")

def email_lookup():
    email = input(Fore.CYAN + "\n[?] Enter Email: ")
    try:
        r = requests.get(f"https://abstractapi.com/v1/email/validate/?api_key={ABSTRACT_API_KEY}&email={email}").json()
        print(Fore.GREEN + "\n[+] Email Lookup Results:\n")
        print(f"{Fore.YELLOW}Valid       : {Fore.WHITE}{r['deliverability']}")
        print(f"{Fore.YELLOW}Domain      : {Fore.WHITE}{r['domain']}")
        print(f"{Fore.YELLOW}Is Free     : {Fore.WHITE}{r['is_free_email']}")
    except:
        print(Fore.RED + "Error in Email Lookup")

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
        r = requests.get(f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOISXML_API_KEY}&domainName={domain}&outputFormat=JSON").json()
        print(Fore.GREEN + "\n[+] WHOIS Lookup Results:\n")
        print(Fore.WHITE + r)
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
        r = requests.get(f"https://ipinfo.io/{ip}?token={IPINFO_API_KEY}").json()
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
def menu_options():
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
    unlock()
    while True:
        menu_options()
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
