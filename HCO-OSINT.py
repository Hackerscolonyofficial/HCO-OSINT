#!/usr/bin/env python3
import os
import sys
import time
import requests
import platform
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Path to store device-wide unlock flag
UNLOCK_FILE = os.path.expanduser("~/.hco_osint_unlock")

YOUTUBE = "https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya"

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

    for i in range(8, 0, -1):
        print(Fore.YELLOW + f"Redirecting to YouTube in {i} seconds...", end="\r")
        time.sleep(1)

    # Open YouTube properly on Android/Termux
    if "Android" in platform.platform() or os.path.exists("/data/data/com.termux"):
        os.system(f'am start -a android.intent.action.VIEW -d "{YOUTUBE}" >/dev/null 2>&1')
    else:
        import webbrowser
        webbrowser.open(YOUTUBE)

    input(Fore.GREEN + "\nPress Enter after subscribing to continue...")

    with open(UNLOCK_FILE, "w") as f:
        f.write("unlocked")

# ---------- Banner ----------
def banner():
    os.system("clear")
    print(Fore.MAGENTA + Style.BRIGHT + """
╔════════════════════════════╗
║        HCO-OSINT TOOL      ║
║ By Azhar (Hackers Colony)  ║
╚════════════════════════════╝
""")

# ---------- OSINT Functions ----------
def ip_lookup():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ")
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10).json()
        print(Fore.GREEN + "\n[+] IP Information:\n")
        for k, v in r.items():
            print(f"{Fore.YELLOW}{k:<12}: {Fore.WHITE}{v}")
    except Exception as e:
        print(Fore.RED + f"Error in IP Lookup: {e}")

def domain_lookup():
    dom = input(Fore.CYAN + "\n[?] Enter Domain: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/dnslookup/?q={dom}", timeout=10)
        print(Fore.GREEN + "\n[+] Domain Lookup Results:\n")
        print(Fore.WHITE + r.text)
    except Exception as e:
        print(Fore.RED + f"Error in Domain Lookup: {e}")

def headers_lookup():
    url = input(Fore.CYAN + "\n[?] Enter URL (http/https): ")
    try:
        r = requests.get(url, timeout=10)
        print(Fore.GREEN + "\n[+] HTTP Headers:\n")
        for k, v in r.headers.items():
            print(f"{Fore.YELLOW}{k:<20}: {Fore.WHITE}{v}")
    except Exception as e:
        print(Fore.RED + f"Error in Headers Lookup: {e}")

def phone_lookup():
    num = input(Fore.CYAN + "\n[?] Enter Phone Number with country code (+91...): ")
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone
        parsed = phonenumbers.parse(num, None)
        print(Fore.GREEN + "\n[+] Phone Number Info:\n")
        print(f"{Fore.YELLOW}Valid       : {Fore.WHITE}{phonenumbers.is_valid_number(parsed)}")
        print(f"{Fore.YELLOW}Region      : {Fore.WHITE}{geocoder.description_for_number(parsed, 'en')}")
        print(f"{Fore.YELLOW}Carrier     : {Fore.WHITE}{carrier.name_for_number(parsed, 'en')}")
        print(f"{Fore.YELLOW}Timezone    : {Fore.WHITE}{timezone.time_zones_for_number(parsed)}")
    except Exception as e:
        print(Fore.RED + f"Error in Phone Lookup: {e}")

def email_lookup():
    email = input(Fore.CYAN + "\n[?] Enter Email: ")
    try:
        import validators
        if not validators.email(email):
            print(Fore.RED + "Invalid email format.")
            return
        print(Fore.GREEN + "\n[+] Email Info (basic checks only)\n")
        domain = email.split("@")[-1]
        print(f"{Fore.YELLOW}Domain       : {Fore.WHITE}{domain}")
        r = requests.get(f"https://api.hackertarget.com/dnslookup/?q={domain}", timeout=10)
        print(Fore.YELLOW + "DNS Records:\n" + Fore.WHITE + r.text)
    except Exception as e:
        print(Fore.RED + f"Error in Email Lookup: {e}")

def username_lookup():
    user = input(Fore.CYAN + "\n[?] Enter Username: ")
    sites = ["https://github.com/{}", "https://twitter.com/{}", "https://instagram.com/{}"]
    print(Fore.GREEN + "\n[+] Checking common sites:\n")
    for s in sites:
        url = s.format(user)
        try:
            r = requests.get(url, timeout=8)
            if r.status_code == 200:
                print(Fore.YELLOW + f"Found: {Fore.WHITE}{url}")
            else:
                print(Fore.RED + f"Not Found: {url}")
        except:
            print(Fore.RED + f"Error accessing {url}")

def dns_lookup():
    dom = input(Fore.CYAN + "\n[?] Enter Domain: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/dnslookup/?q={dom}", timeout=10)
        print(Fore.GREEN + "\n[+] DNS Lookup Results:\n")
        print(Fore.WHITE + r.text)
    except Exception as e:
        print(Fore.RED + f"Error in DNS Lookup: {e}")

def whois_lookup():
    dom = input(Fore.CYAN + "\n[?] Enter Domain: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/whois/?q={dom}", timeout=10)
        print(Fore.GREEN + "\n[+] WHOIS Results:\n")
        print(Fore.WHITE + r.text)
    except Exception as e:
        print(Fore.RED + f"Error in WHOIS Lookup: {e}")

def subdomain_scan():
    dom = input(Fore.CYAN + "\n[?] Enter Domain: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={dom}", timeout=10)
        print(Fore.GREEN + "\n[+] Subdomains:\n")
        print(Fore.WHITE + r.text)
    except Exception as e:
        print(Fore.RED + f"Error in Subdomain Scan: {e}")

def reverse_ip():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=10)
        print(Fore.GREEN + "\n[+] Reverse IP Results:\n")
        print(Fore.WHITE + r.text)
    except Exception as e:
        print(Fore.RED + f"Error in Reverse IP Lookup: {e}")

def trace_route():
    host = input(Fore.CYAN + "\n[?] Enter Host/Domain: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/mtr/?q={host}", timeout=10)
        print(Fore.GREEN + "\n[+] Traceroute:\n")
        print(Fore.WHITE + r.text)
    except Exception as e:
        print(Fore.RED + f"Error in Traceroute: {e}")

def geoip_lookup():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ")
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10).json()
        print(Fore.GREEN + "\n[+] GeoIP Information:\n")
        for k, v in r.items():
            print(f"{Fore.YELLOW}{k.title():<15}: {Fore.WHITE}{v}")
    except Exception as e:
        print(Fore.RED + f"Error in GeoIP Lookup: {e}")

def port_scan():
    host = input(Fore.CYAN + "\n[?] Enter Host/IP: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/nmap/?q={host}", timeout=15)
        print(Fore.GREEN + "\n[+] Port Scan Results:\n")
        print(Fore.WHITE + r.text)
    except Exception as e:
        print(Fore.RED + f"Error in Port Scan: {e}")

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
