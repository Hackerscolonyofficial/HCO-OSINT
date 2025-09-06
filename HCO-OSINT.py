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
import socket
import webbrowser
import requests
from colorama import Fore, Style, init
import dns.resolver
import whois
from ipwhois import IPWhois

# Initialize colorama
init(autoreset=True)
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
    # Countdown
    for i in range(8, 0, -1):
        print(Fore.YELLOW + Style.BRIGHT + f"Redirecting to YouTube in {i} seconds...", end="\r")
        time.sleep(1)
    # Open YouTube channel
    youtube_link = "https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya"
    webbrowser.open(youtube_link)
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
        r = requests.get(f"http://ip-api.com/json/{ip}").json()
        print(Fore.GREEN + "\n[+] IP Lookup Results:\n")
        for k, v in r.items():
            print(f"{Fore.YELLOW}{k.title():<15}: {Fore.WHITE}{v}")
    except:
        print(Fore.RED + "Error in IP Lookup")

def domain_lookup():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ")
    try:
        w = whois.whois(domain)
        print(Fore.GREEN + "\n[+] Domain/WHOIS Lookup Results:\n")
        for key, value in w.items():
            print(f"{Fore.YELLOW}{key:<15}: {Fore.WHITE}{value}")
    except:
        print(Fore.RED + "Error in Domain/WHOIS Lookup")

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
        if number.startswith('+'):
            country = number[1:4]
            print(Fore.GREEN + "\n[+] Phone Lookup Results:\n")
            print(f"{Fore.YELLOW}Country Code : {Fore.WHITE}{country}")
            print(f"{Fore.YELLOW}Carrier      : {Fore.WHITE}N/A")
            print(f"{Fore.YELLOW}Line Type    : {Fore.WHITE}N/A")
        else:
            print(Fore.RED + "Invalid number format. Include country code e.g. +918340246110")
    except:
        print(Fore.RED + "Error in Phone Lookup")

def email_lookup():
    email = input(Fore.CYAN + "\n[?] Enter Email: ")
    try:
        domain = email.split("@")[1]
        answers = dns.resolver.resolve(domain, 'MX')
        print(Fore.GREEN + "\n[+] Email MX Records:\n")
        for rdata in answers:
            print(f"{Fore.YELLOW}- {Fore.WHITE}{rdata.exchange}")
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
        answers = dns.resolver.resolve(domain, 'A')
        print(Fore.GREEN + "\n[+] DNS Lookup Results:\n")
        for rdata in answers:
            print(f"{Fore.YELLOW}- {Fore.WHITE}{rdata}")
    except:
        print(Fore.RED + "Error in DNS Lookup")

def subdomain_scan():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ")
    common_subs = ["www", "mail", "ftp", "ns1", "ns2"]
    print(Fore.GREEN + "\n[+] Subdomain Scan Results:\n")
    for sub in common_subs:
        try:
            ip = socket.gethostbyname(f"{sub}.{domain}")
            print(f"{Fore.YELLOW}{sub:<10}: {Fore.WHITE}{ip}")
        except:
            pass

def reverse_ip():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ")
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        print(Fore.GREEN + "\n[+] Reverse IP Results:\n")
        print(f"{Fore.WHITE}{res.get('network', res)}")
    except:
        print(Fore.RED + "Error in Reverse IP Lookup")

def trace_route():
    host = input(Fore.CYAN + "\n[?] Enter Host/Domain: ")
    try:
        os.system(f"traceroute {host}")
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
        print(Fore.GREEN + "\n[+] Scanning common ports...\n")
        common_ports = [21,22,23,25,53,80,110,443,445,3389]
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"{Fore.YELLOW}Port {port:<5}: {Fore.WHITE}Open")
            else:
                print(f"{Fore.YELLOW}Port {port:<5}: {Fore.WHITE}Closed")
            sock.close()
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
    unlock()
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
        elif choice == "8": domain_lookup()  # WHOIS same as domain
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
