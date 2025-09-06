#!/usr/bin/env python3
"""
HCO OSINT Tool
By Azhar (Hackers Colony)
"""

import os
import sys
import time
import requests
import socket
import whois
import json
from colorama import Fore, Style, init
init(autoreset=True)

# 🔒 Tool Lock Function
def tool_lock():
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

    # Redirect to YouTube app (Android intent)
    os.system("am start -a android.intent.action.VIEW -d 'https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya'")

    # Wait for confirmation
    input(Fore.GREEN + "\n✅ After subscribing, press Enter to continue...")

# Call the lock before running anything else
tool_lock()

# ───────────────────────────────────────────────
# Original Tool Code
# ───────────────────────────────────────────────

def banner():
    os.system("clear")
    print(Fore.MAGENTA + Style.BRIGHT + """
╔════════════════════════════╗
║      HCO-OSINT TOOL        ║
║  By Azhar (Hackers Colony) ║
╚════════════════════════════╝
""")
    print(Fore.CYAN + "📺 YouTube : https://youtube.com/@hackers_colony_tech\n")

def ip_lookup():
    ip = input(Fore.CYAN + "[?] Enter IP Address: ")
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json").json()
        print(Fore.GREEN + "\n[+] IP Lookup Results:\n")
        for k, v in r.items():
            print(f"{Fore.YELLOW}{k:<15}: {Fore.WHITE}{v}")
    except:
        print(Fore.RED + "Error in IP Lookup")

def domain_lookup():
    domain = input(Fore.CYAN + "[?] Enter Domain: ")
    try:
        w = whois.whois(domain)
        print(Fore.GREEN + "\n[+] WHOIS Results:\n")
        print(w)
    except:
        print(Fore.RED + "Error in Domain Lookup")

def reverse_ip():
    ip = input(Fore.CYAN + "[?] Enter IP Address: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        print(Fore.GREEN + "\n[+] Reverse IP Results:\n")
        print(Fore.WHITE + r.text)
    except:
        print(Fore.RED + "Error in Reverse IP Lookup")

def menu():
    banner()
    print(Fore.CYAN + Style.BRIGHT + """
[1]  IP Lookup
[2]  Domain Lookup
[3]  Reverse IP Lookup
[0]  Exit
""")

def main():
    while True:
        menu()
        choice = input(Fore.YELLOW + "[?] Select option: ")

        if choice == "1": ip_lookup()
        elif choice == "2": domain_lookup()
        elif choice == "3": reverse_ip()
        elif choice == "0":
            print(Fore.GREEN + "\nExiting... Bye!\n")
            sys.exit()
        else:
            print(Fore.RED + "Invalid Choice!")

        input(Fore.CYAN + "\nPress Enter to continue...")

if __name__ == "__main__":
    main()
