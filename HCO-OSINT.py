#!/usr/bin/env python3
"""
HCO-OSINT - Advanced OSINT Toolkit
By Azhar (Hackers Colony)
Educational purposes only!
"""

import os
import sys
import time
import socket
import requests
import phonenumbers
from phonenumbers import geocoder, carrier, timezone

# Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def countdown_redirect():
    print(f"{RED}{BOLD}This tool is not free! To unlock, you must subscribe to our YouTube channel.{RESET}\n")
    for i in range(8, 4, -1):
        print(f"{YELLOW}{BOLD}{i}{RESET}")
        time.sleep(1)
    os.system("termux-open-url https://youtube.com/@hackers_colony_tech")
    input(f"\n{CYAN}Press Enter after subscribing and returning here...{RESET}")
    print(f"\n{RED}{BOLD}=========================={RESET}")
    print(f"{GREEN}{BOLD}     HCO-OSINT by Azhar    {RESET}")
    print(f"{RED}{BOLD}=========================={RESET}\n")

# ────────── OSINT FUNCTIONS ────────── #

def phone_lookup():
    num = input(f"{CYAN}Enter phone number (with country code): {RESET}")
    try:
        parsed = phonenumbers.parse(num)
        if phonenumbers.is_valid_number(parsed):
            print(f"{GREEN}✔ Valid number{RESET}")
            print(f"{YELLOW}Region: {RESET}{geocoder.description_for_number(parsed, 'en')}")
            print(f"{YELLOW}Carrier: {RESET}{carrier.name_for_number(parsed, 'en')}")
            print(f"{YELLOW}Timezone: {RESET}{timezone.time_zones_for_number(parsed)}")
        else:
            print(f"{RED}✘ Invalid number!{RESET}")
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")

def ip_lookup():
    ip = input(f"{CYAN}Enter IP address: {RESET}")
    try:
        url = f"http://ip-api.com/json/{ip}"
        r = requests.get(url).json()
        if r["status"] == "success":
            print(f"{GREEN}✔ IP Info for {ip}:{RESET}")
            for k,v in r.items():
                print(f"{YELLOW}{k}: {RESET}{v}")
        else:
            print(f"{RED}✘ Lookup failed!{RESET}")
    except:
        print(f"{RED}✘ Error connecting to API{RESET}")

def dns_lookup():
    domain = input(f"{CYAN}Enter domain: {RESET}")
    try:
        ip = socket.gethostbyname(domain)
        print(f"{GREEN}✔ {domain} resolves to {ip}{RESET}")
    except:
        print(f"{RED}✘ DNS resolution failed!{RESET}")

def headers_lookup():
    url = input(f"{CYAN}Enter website URL (https://...): {RESET}")
    try:
        r = requests.get(url)
        print(f"{GREEN}✔ Response Headers:{RESET}")
        for k,v in r.headers.items():
            print(f"{YELLOW}{k}: {RESET}{v}")
    except:
        print(f"{RED}✘ Failed to fetch headers!{RESET}")

def my_ip():
    try:
        ip = requests.get("https://api64.ipify.org").text
        print(f"{GREEN}Your Public IP: {RESET}{ip}")
    except:
        print(f"{RED}✘ Could not fetch your IP!{RESET}")

# ────────── MAIN MENU ────────── #

def menu():
    while True:
        print(f"""
{RED}{BOLD}==== HCO-OSINT Toolkit ===={RESET}
{CYAN}1.{RESET} Phone Number Lookup
{CYAN}2.{RESET} IP Address Lookup
{CYAN}3.{RESET} DNS Resolution
{CYAN}4.{RESET} Website Headers
{CYAN}5.{RESET} My Public IP
{CYAN}0.{RESET} Exit
""")
        choice = input(f"{YELLOW}Select option: {RESET}")
        
        if choice == "1": phone_lookup()
        elif choice == "2": ip_lookup()
        elif choice == "3": dns_lookup()
        elif choice == "4": headers_lookup()
        elif choice == "5": my_ip()
        elif choice == "0":
            print(f"{GREEN}Exiting...{RESET}")
            sys.exit()
        else:
            print(f"{RED}Invalid option!{RESET}")

# ────────── RUN TOOL ────────── #
if __name__ == "__main__":
    countdown_redirect()
    menu()
