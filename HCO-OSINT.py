#!/usr/bin/env python3
"""
HCO-OSINT - Advanced Flashy OSINT Tool
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
from random import choice

# Auto-install dependencies
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

# --- Utility Functions ---
def colorful_message(msg):
    colors = [Fore.RED, Fore.GREEN, Fore.CYAN, Fore.MAGENTA, Fore.YELLOW, Fore.BLUE]
    print(choice(colors) + Style.BRIGHT + "\n" + msg + "\n" + Style.RESET_ALL)

def animated_countdown(start=5, prefix="Countdown"):
    for i in range(start, 0, -1):
        print(Fore.CYAN + f"{prefix}: {i} ", end="\r")
        time.sleep(1)
    print(" " * 50, end="\r")

def blinking_dots(duration=3):
    for _ in range(duration):
        for dots in ["   ", ".  ", ".. ", "..."]:
            print(Fore.YELLOW + f"Processing{dots}", end="\r")
            time.sleep(0.5)
    print(" " * 50, end="\r")

def unlock_tool():
    print(Fore.YELLOW + Style.BRIGHT + "\n🔒 HCO OSINT Lock System")
    print(Fore.CYAN + "To unlock the tool, we will redirect you to our YouTube channel.")
    print(Fore.CYAN + "Please subscribe and click the 🔔 bell icon to activate the tool!")
    animated_countdown(8, "Redirecting in")
    print(Fore.GREEN + "Opening YouTube...")
    webbrowser.open(YOUTUBE_LINK)
    input(Fore.MAGENTA + "\nAfter subscribing and clicking the bell, press ENTER to continue...")

def show_banner():
    neon_red = Fore.RED + Style.BRIGHT
    neon_green = Fore.GREEN + Style.BRIGHT
    print(neon_red + "\n" + "="*50)
    print(neon_green + "       HCO OSINT by Azhar")
    print(neon_red + "="*50 + "\n")

def educational_popup(feature_name):
    messages = {
        "phone": "📞 Phone Lookup gathers info: carrier, timezone, country, and validity.",
        "ip": "🌐 IP Lookup shows geolocation, ISP, and other info about an IP address.",
        "domain": "💻 Domain Lookup resolves domain to IP and performs extra IP checks.",
        "email": "✉️ Email Lookup checks format validity, domain, and common email leaks.",
        "username": "👤 Username Lookup checks multiple platforms and availability.",
        "shodan": "🔍 Shodan-like Scan checks common ports for openness and security hints.",
        "headers": "📜 HTTP Headers Grabber fetches server headers including server type, cookies, and security headers.",
        "port": "🛡️ Port Scanner scans common ports and extra ports for real scanning simulation."
    }
    colorful_message(messages.get(feature_name, "Feature completed!"))

def colorful_tabulate(data, headers):
    colored_data = []
    row_colors = [Fore.CYAN, Fore.MAGENTA]
    for i, row in enumerate(data):
        colored_row = [row_colors[i % 2] + str(cell) + Style.RESET_ALL for cell in row]
        colored_data.append(colored_row)
    return tabulate(colored_data, headers=headers, tablefmt="fancy_grid")

# --- Feature Mode Selector ---
def choose_mode():
    print(Fore.YELLOW + "\nChoose Mode:")
    print(Fore.CYAN + "1️⃣  Quick Mode\n2️⃣  Advanced Mode")
    mode = input(Fore.MAGENTA + "Enter choice: ")
    if mode not in ["1", "2"]:
        print(Fore.RED + "Invalid choice! Defaulting to Quick Mode.")
        mode = "1"
    return mode

# --- Features ---
def phone_lookup():
    mode = choose_mode()
    number = input(Fore.CYAN + "Enter phone number with country code: ")
    try:
        parsed = phonenumbers.parse(number, None)
        data = [
            ["Number", number],
            ["Valid", phonenumbers.is_valid_number(parsed)],
            ["Possible", phonenumbers.is_possible_number(parsed)]
        ]
        if mode == "2":
            data += [
                ["Country", geocoder.description_for_number(parsed, "en")],
                ["Carrier", carrier.name_for_number(parsed, "en")],
                ["Timezone", timezone.time_zones_for_number(parsed)],
                ["Number Type", phonenumbers.number_type(parsed)]
            ]
        blinking_dots()
        print(Fore.GREEN + colorful_tabulate(data, headers=["Field", "Value"]))
        educational_popup("phone")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def ip_lookup():
    mode = choose_mode()
    ip = input(Fore.CYAN + "Enter IP address: ")
    try:
        blinking_dots()
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        data = [[k, v] for k, v in res.items()]
        if mode == "2":
            try: data.append(["Reverse DNS", socket.getfqdn(ip)])
            except: pass
        print(Fore.GREEN + colorful_tabulate(data, headers=["Field", "Value"]))
        educational_popup("ip")
    except:
        print(Fore.RED + "Failed to lookup IP")

def domain_lookup():
    mode = choose_mode()
    domain = input(Fore.CYAN + "Enter domain: ")
    try:
        blinking_dots()
        ip = socket.gethostbyname(domain)
        print(Fore.GREEN + f"\nResolved IP: {ip}")
        if mode == "2":
            try: ips = socket.gethostbyname_ex(domain)[2]; print(Fore.CYAN + "Other resolved IPs: " + ", ".join(ips))
            except: pass
        ip_lookup()
        educational_popup("domain")
    except:
        print(Fore.RED + "Domain lookup failed")

def email_lookup():
    mode = choose_mode()
    email = input(Fore.CYAN + "Enter email: ")
    blinking_dots()
    data = [
        ["Email", email],
        ["Format Valid", "@" in email and "." in email]
    ]
    if mode == "2": data += [["Domain", email.split("@")[-1]]]
    print(Fore.GREEN + colorful_tabulate(data, headers=["Field", "Value"]))
    educational_popup("email")

def username_lookup():
    mode = choose_mode()
    username = input(Fore.CYAN + "Enter username: ")
    sites = ["https://github.com/", "https://twitter.com/", "https://instagram.com/", "https://facebook.com/"]
    results = []
    blinking_dots()
    for s in sites:
        url = s + username
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200: results.append([s, Fore.GREEN + "Found"])
            else: results.append([s, Fore.RED + "Not Found"])
        except: results.append([s, Fore.YELLOW + "Error"])
    if mode == "2": results.append(["Extra Scan", "Additional platform checks can be added"])
    print(colorful_tabulate(results, headers=["Site", "Status"]))
    educational_popup("username")

def shodan_like_scan():
    mode = choose_mode()
    target = input(Fore.CYAN + "Enter target IP/Domain: ")
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
    extra_ports = [8080, 8443, 3306, 1433, 5900] if mode == "2" else []
    ports = common_ports + extra_ports
    results = []
    print(Fore.YELLOW + "Starting Shodan-like port scan...")
    animated_countdown(3, "Scanning")
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try: s.connect((target, p)); results.append([p, Fore.GREEN + "Open"])
        except: results.append([p, Fore.RED + "Closed"])
        s.close()
    print(colorful_tabulate(results, headers=["Port", "Status"]))
    educational_popup("shodan")

def http_headers():
    mode = choose_mode()
    url = input(Fore.CYAN + "Enter URL (http/https): ")
    blinking_dots()
    try:
        r = requests.get(url, timeout=5)
        data = [[k, v] for k, v in r.headers.items()]
        if mode == "2":
            security_headers = ["Strict-Transport-Security", "X-Content-Type-Options", "Content-Security-Policy"]
            for sh in security_headers: data.append([sh, r.headers.get(sh, "Not Found")])
        print(colorful_tabulate(data, headers=["Header", "Value"]))
        educational_popup("headers")
    except:
        print(Fore.RED + "Could not fetch headers")

def port_scan():
    mode = choose_mode()
    target = input(Fore.CYAN + "Enter IP/Domain: ")
    common_ports = [21,22,23,25,53,80,110,139,143,443,445,3389]
    extra_ports = [8080, 8443, 3306, 1433, 5900] if mode=="2" else []
    ports = common_ports + extra_ports
    results = []
    print(Fore.YELLOW + "Starting advanced port scan...")
    animated_countdown(3, "Scanning")
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try: s.connect((target,p)); results.append([p, Fore.GREEN + "Open"])
        except: results.append([p, Fore.RED + "Closed"])
        s.close()
    print(colorful_tabulate(results, headers=["Port", "Status"]))
    educational_popup("port")

# --- Main Menu ---
def main():
    unlock_tool()
    show_banner()
    while True:
        print(Fore.YELLOW + "\nSelect an option:")
        print(Fore.CYAN + """
1️⃣  Phone Number Lookup
2️⃣  IP Lookup
3️⃣  Domain Lookup
4️⃣  Email Lookup
5️⃣  Username Lookup
6️⃣  Shodan-like Quick Scan
7️⃣  HTTP Headers Grabber
8️⃣  Port Scanner
9️⃣  Exit
""")
        choice = input(Fore.MAGENTA + "Enter choice: ")
        if choice=="1": phone_lookup()
        elif choice=="2": ip_lookup()
        elif choice=="3": domain_lookup()
        elif choice=="4": email_lookup()
        elif choice=="5": username_lookup()
        elif choice=="6": shodan_like_scan()
        elif choice=="7": http_headers()
        elif choice=="8": port_scan()
        elif choice=="9": sys.exit()
        else: print(Fore.RED + "Invalid choice")

if __name__=="__main__":
    main()
