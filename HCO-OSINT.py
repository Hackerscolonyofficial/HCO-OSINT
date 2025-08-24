#!/usr/bin/env python3
"""
HCO-OSINT - Advanced OSINT Tool (Educational)
By Azhar (Hackers Colony)
"""

import os
import sys
import time
import webbrowser
import socket
import requests
import phonenumbers
from phonenumbers import geocoder, carrier, timezone

# Auto install dependencies
try:
    from colorama import Fore, Style, init
    from tabulate import tabulate
except ImportError:
    print("Installing required modules...")
    os.system("pip install colorama requests phonenumbers tabulate")
    from colorama import Fore, Style, init
    from tabulate import tabulate

init(autoreset=True)

YOUTUBE_LINK = "https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya"

# Unlock system
def unlock_tool():
    print(Fore.YELLOW + "\nThis tool is not free! Unlocking in:")
    for i in range(8, 0, -1):
        print(Fore.CYAN + str(i))
        time.sleep(1)
    print(Fore.GREEN + "\nRedirecting to YouTube...")
    webbrowser.open(YOUTUBE_LINK)
    input(Fore.MAGENTA + "\nAfter subscribing, press ENTER to continue...")

    # Show banner
    print(Fore.RED + Style.BRIGHT + "\n" + "="*40)
    print(Fore.GREEN + Style.BRIGHT + "      HCO OSINT by Azhar")
    print(Fore.RED + Style.BRIGHT + "="*40 + "\n")

# --- Features ---

def phone_lookup():
    number = input(Fore.CYAN + "Enter phone number with country code: ")
    try:
        parsed = phonenumbers.parse(number, None)
        data = [
            ["Number", number],
            ["Valid", phonenumbers.is_valid_number(parsed)],
            ["Possible", phonenumbers.is_possible_number(parsed)],
            ["Country", geocoder.description_for_number(parsed, "en")],
            ["Carrier", carrier.name_for_number(parsed, "en")],
            ["Timezone", timezone.time_zones_for_number(parsed)]
        ]
        print(Fore.GREEN + tabulate(data, headers=["Field", "Value"], tablefmt="fancy_grid"))
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def ip_lookup():
    ip = input(Fore.CYAN + "Enter IP address: ")
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        data = [[k, v] for k, v in res.items()]
        print(Fore.GREEN + tabulate(data, headers=["Field", "Value"], tablefmt="fancy_grid"))
    except:
        print(Fore.RED + "Failed to lookup IP")

def domain_lookup():
    domain = input(Fore.CYAN + "Enter domain: ")
    try:
        ip = socket.gethostbyname(domain)
        print(Fore.GREEN + f"\nResolved IP: {ip}")
        ip_lookup()
    except:
        print(Fore.RED + "Domain lookup failed")

def email_lookup():
    email = input(Fore.CYAN + "Enter email: ")
    # basic check
    data = [
        ["Email", email],
        ["Format Valid", "@" in email and "." in email],
        ["Domain", email.split("@")[-1]]
    ]
    print(Fore.GREEN + tabulate(data, headers=["Field", "Value"], tablefmt="fancy_grid"))

def username_lookup():
    username = input(Fore.CYAN + "Enter username: ")
    sites = ["https://github.com/", "https://twitter.com/", "https://instagram.com/", "https://facebook.com/"]
    results = []
    for s in sites:
        url = s + username
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                results.append([s, "Found"])
            else:
                results.append([s, "Not Found"])
        except:
            results.append([s, "Error"])
    print(Fore.GREEN + tabulate(results, headers=["Site", "Status"], tablefmt="fancy_grid"))

def shodan_like_scan():
    target = input(Fore.CYAN + "Enter target IP/Domain: ")
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
    results = []
    try:
        for p in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            try:
                s.connect((target, p))
                results.append([p, "Open"])
            except:
                results.append([p, "Closed"])
            s.close()
        print(Fore.GREEN + tabulate(results, headers=["Port", "Status"], tablefmt="fancy_grid"))
    except:
        print(Fore.RED + "Error scanning")

def http_headers():
    url = input(Fore.CYAN + "Enter URL (http/https): ")
    try:
        r = requests.get(url, timeout=5)
        data = [[k, v] for k, v in r.headers.items()]
        print(Fore.GREEN + tabulate(data, headers=["Header", "Value"], tablefmt="fancy_grid"))
    except:
        print(Fore.RED + "Could not fetch headers")

def port_scan():
    target = input(Fore.CYAN + "Enter IP/Domain: ")
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
    results = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect((target, p))
            results.append([p, "Open"])
        except:
            results.append([p, "Closed"])
        s.close()
    print(Fore.GREEN + tabulate(results, headers=["Port", "Status"], tablefmt="fancy_grid"))

# --- Main Menu ---
def main():
    unlock_tool()
    while True:
        print(Fore.YELLOW + "\nSelect an option:")
        print(Fore.CYAN + """
1. Phone Number Lookup
2. IP Lookup
3. Domain Lookup
4. Email Lookup
5. Username Lookup
6. Shodan-like Quick Scan
7. HTTP Headers Grabber
8. Port Scanner
9. Exit
""")
        choice = input(Fore.MAGENTA + "Enter choice: ")
        if choice == "1": phone_lookup()
        elif choice == "2": ip_lookup()
        elif choice == "3": domain_lookup()
        elif choice == "4": email_lookup()
        elif choice == "5": username_lookup()
        elif choice == "6": shodan_like_scan()
        elif choice == "7": http_headers()
        elif choice == "8": port_scan()
        elif choice == "9": sys.exit()
        else: print(Fore.RED + "Invalid choice")

if __name__ == "__main__":
    main()
