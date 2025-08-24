#!/usr/bin/env python3
"""
HCO-OSINT - Advanced OSINT Framework (Termux Friendly)
By Azhar (Hackers Colony)
"""

import os
import time
import socket
import requests
import json
import re
import datetime
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from tabulate import tabulate
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

BANNER = (
    Fore.CYAN + Style.BRIGHT +
    "\n" + "="*60 +
    f"\n   HCO OSINT by Azhar".upper() +
    "\n" + "="*60 + "\n"
)

def clear_screen():
    os.system("clear" if os.name == "posix" else "cls")

def header():
    clear_screen()
    print(BANNER)

def fancy_table(data, headers):
    return tabulate(data, headers, tablefmt="fancy_grid")

# ---------- FEATURE 1: IP Lookup ----------
def ip_lookup():
    ip = input(Fore.YELLOW + "Enter IP Address: ").strip()
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        data = [
            ["IP", res.get("query", "N/A")],
            ["ISP", res.get("isp", "N/A")],
            ["Org", res.get("org", "N/A")],
            ["Country", res.get("country", "N/A")],
            ["Region", res.get("regionName", "N/A")],
            ["City", res.get("city", "N/A")],
            ["ZIP", res.get("zip", "N/A")],
            ["Lat, Lon", f"{res.get('lat')}, {res.get('lon')}"],
            ["Timezone", res.get("timezone", "N/A")],
        ]
        print(fancy_table(data, ["Field", "Info"]))
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    input(Fore.GREEN + "\nPress Enter to continue...")

# ---------- FEATURE 2: Phone Lookup ----------
def phone_lookup():
    number = input(Fore.YELLOW + "Enter phone number with country code (+91...): ").strip()
    try:
        phone = phonenumbers.parse(number)
        data = [
            ["Valid", phonenumbers.is_valid_number(phone)],
            ["Possible", phonenumbers.is_possible_number(phone)],
            ["Region", geocoder.description_for_number(phone, "en")],
            ["Carrier", carrier.name_for_number(phone, "en")],
            ["Timezone", timezone.time_zones_for_number(phone)],
            ["National", phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.NATIONAL)],
            ["International", phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.INTERNATIONAL)]
        ]
        print(fancy_table(data, ["Field", "Info"]))
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    input(Fore.GREEN + "\nPress Enter to continue...")

# ---------- FEATURE 3: Email Lookup ----------
def email_lookup():
    email = input(Fore.YELLOW + "Enter Email: ").strip()
    domain = email.split("@")[-1]
    try:
        res = requests.get(f"https://api.eva.pingutil.com/email?email={email}").json()
        data = [
            ["Email", email],
            ["Valid", res.get("data", {}).get("deliverable", False)],
            ["Domain", domain],
            ["Disposable", res.get("data", {}).get("disposable", False)],
            ["MX Records", res.get("data", {}).get("mx", [])],
            ["Spam", res.get("data", {}).get("spam", False)]
        ]
        print(fancy_table(data, ["Field", "Info"]))
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    input(Fore.GREEN + "\nPress Enter to continue...")

# ---------- FEATURE 4: Username Lookup ----------
def username_lookup():
    username = input(Fore.YELLOW + "Enter Username: ").strip()
    sites = {
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://x.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Facebook": f"https://facebook.com/{username}"
    }
    data = []
    for site, url in sites.items():
        try:
            r = requests.get(url)
            status = "Found ✅" if r.status_code == 200 else "Not Found ❌"
            data.append([site, url, status])
        except:
            data.append([site, url, "Error"])
    print(fancy_table(data, ["Site", "Profile URL", "Status"]))
    input(Fore.GREEN + "\nPress Enter to continue...")

# ---------- FEATURE 5: Domain Lookup ----------
def domain_lookup():
    domain = input(Fore.YELLOW + "Enter Domain: ").strip()
    try:
        ip = socket.gethostbyname(domain)
        whois = requests.get(f"https://api.api-ninjas.com/v1/whois?domain={domain}",
                             headers={"X-Api-Key": "free"}).json()
        data = [
            ["Domain", domain],
            ["IP", ip],
            ["Registrar", whois.get("registrar", "N/A")],
            ["Creation Date", whois.get("creation_date", "N/A")],
            ["Expiration Date", whois.get("expiration_date", "N/A")],
            ["Updated", whois.get("updated_date", "N/A")],
        ]
        print(fancy_table(data, ["Field", "Info"]))
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    input(Fore.GREEN + "\nPress Enter to continue...")

# ---------- FEATURE 6: BIN Lookup ----------
def bin_lookup():
    bin_number = input(Fore.YELLOW + "Enter first 6 digits of card (BIN): ").strip()
    try:
        res = requests.get(f"https://lookup.binlist.net/{bin_number}").json()
        data = [
            ["Scheme", res.get("scheme", "N/A")],
            ["Type", res.get("type", "N/A")],
            ["Brand", res.get("brand", "N/A")],
            ["Bank", res.get("bank", {}).get("name", "N/A")],
            ["Country", res.get("country", {}).get("name", "N/A")],
            ["Currency", res.get("country", {}).get("currency", "N/A")]
        ]
        print(fancy_table(data, ["Field", "Info"]))
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    input(Fore.GREEN + "\nPress Enter to continue...")

# ---------- FEATURE 7: Social Media Email Search ----------
def social_email_search():
    email = input(Fore.YELLOW + "Enter Email for Social Search: ").strip()
    # Fake demo (real APIs require keys)
    data = [
        ["Facebook", "Not Available"],
        ["Instagram", "Not Available"],
        ["Twitter", "Not Available"],
        ["LinkedIn", "Not Available"]
    ]
    print(fancy_table(data, ["Platform", "Status"]))
    input(Fore.GREEN + "\nPress Enter to continue...")

# ---------- FEATURE 8: DNS Lookup ----------
def dns_lookup():
    domain = input(Fore.YELLOW + "Enter Domain for DNS Lookup: ").strip()
    try:
        records = socket.getaddrinfo(domain, None)
        data = [[i+1, r[4][0]] for i, r in enumerate(records)]
        print(fancy_table(data, ["#", "Resolved IP"]))
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    input(Fore.GREEN + "\nPress Enter to continue...")

# ---------- MAIN MENU ----------
def main():
    while True:
        header()
        print(Fore.GREEN + Style.BRIGHT + "Select Option:\n")
        print(" 1. IP Lookup")
        print(" 2. Phone Number Lookup")
        print(" 3. Email Lookup")
        print(" 4. Username Lookup")
        print(" 5. Domain Lookup")
        print(" 6. BIN Lookup")
        print(" 7. Social Media Email Search")
        print(" 8. DNS Lookup")
        print(" 9. Exit")

        choice = input(Fore.CYAN + "\nEnter choice: ").strip()

        if choice == "1": ip_lookup()
        elif choice == "2": phone_lookup()
        elif choice == "3": email_lookup()
        elif choice == "4": username_lookup()
        elif choice == "5": domain_lookup()
        elif choice == "6": bin_lookup()
        elif choice == "7": social_email_search()
        elif choice == "8": dns_lookup()
        elif choice == "9": break
        else: print(Fore.RED + "Invalid choice!"); time.sleep(1)

if __name__ == "__main__":
    main()
