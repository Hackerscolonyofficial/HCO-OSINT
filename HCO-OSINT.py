#!/usr/bin/env python3
import os
import sys
import time
import requests
import webbrowser
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Path to store device-wide unlock flag
UNLOCK_FILE = os.path.expanduser("~/.hco_osint_unlock")

# ---------- Unlock / YouTube Redirect ----------
def unlock():
    if os.path.exists(UNLOCK_FILE):
        return  # Already unlocked on this device

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

    # Wait for confirmation
    input(Fore.GREEN + "\nPress Enter after subscribing to continue...")

    # Create unlock file in home directory
    with open(UNLOCK_FILE, "w") as f:
        f.write("unlocked")

# ---------- Banner ----------
def banner():
    os.system("clear")
    print(Fore.MAGENTA + Style.BRIGHT + """
╔════════════════════════════╗
║      HCO-OSINT TOOL       ║
║      By Azhar (Hackers Colony)     ║
╚════════════════════════════╝
""")

# ---------- OSINT Functions ----------
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

# Add other OSINT functions here (ip_lookup, domain_lookup, etc.)

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
    unlock()  # Run device-wide unlock first
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
