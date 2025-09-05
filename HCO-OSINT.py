#!/usr/bin/env python3
"""
HCO-OSINT Tool
By Azhar (Hackers Colony)
"""

import os, sys, time, socket, requests, whois, phonenumbers, dns.resolver
from colorama import Fore, Back, Style, init

init(autoreset=True)

YOUTUBE = "https://youtube.com/@hackers_colony_tech"

# Fancy print helpers
def banner():
    print(Back.BLUE + Fore.RED + Style.BRIGHT + "\n      HCO OSINT TOOL by Azhar      \n" + Style.RESET_ALL)

def countdown_redirect():
    print(Fore.RED + Style.BRIGHT + "\n🔒 Tool Locked – Subscribe to unlock!\n")
    for i in range(10, 0, -1):
        print(Fore.YELLOW + f"Redirecting to YouTube in {i}...", end="\r")
        time.sleep(1)
    print()
    os.system(f"xdg-open {YOUTUBE}")
    input(Fore.CYAN + "\n👉 Press ENTER after subscribing to continue...")

def menu():
    banner()
    print(Fore.GREEN + Style.BRIGHT + """
[1] Phone Number OSINT
[2] Email Breach Check (basic regex/domain)
[3] Domain WHOIS Lookup
[4] IP Lookup + Reverse DNS
[5] Username Check (GitHub, Reddit, Twitter)
[6] Website Header Grabber
[7] Subdomain Finder (common wordlist)
[8] Port Scanner (1–100 common ports)
[9] Image Metadata Extractor
[0] Exit
""")

def phone_lookup():
    number = input(Fore.CYAN + "Enter phone number with country code (+91...): ")
    try:
        parsed = phonenumbers.parse(number, None)
        valid = phonenumbers.is_valid_number(parsed)
        region = phonenumbers.region_code_for_number(parsed)
        carrier = phonenumbers.carrier.name_for_number(parsed, "en")
        print(Fore.YELLOW + f"\nNumber: {number}")
        print(Fore.GREEN + f"Valid: {valid}")
        print(Fore.CYAN + f"Region: {region}")
        print(Fore.MAGENTA + f"Carrier: {carrier}\n")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def email_check():
    email = input(Fore.CYAN + "Enter email: ")
    if "@" in email and "." in email:
        domain = email.split("@")[1]
        print(Fore.YELLOW + f"\nEmail looks valid. Domain: {domain}")
        try:
            dns.resolver.resolve(domain, "MX")
            print(Fore.GREEN + "✅ Domain has MX records (email service active)")
        except:
            print(Fore.RED + "❌ No MX records – might be invalid domain")
    else:
        print(Fore.RED + "Invalid email format")

def domain_lookup():
    domain = input(Fore.CYAN + "Enter domain (example.com): ")
    try:
        w = whois.whois(domain)
        for k, v in w.items():
            print(Fore.GREEN + f"{k}: {v}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def ip_lookup():
    ip = input(Fore.CYAN + "Enter IP address: ")
    try:
        host = socket.gethostbyaddr(ip)
        print(Fore.YELLOW + f"Reverse DNS: {host[0]}")
    except:
        print(Fore.RED + "No reverse DNS found")
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}").json()
        for k, v in r.items():
            print(Fore.GREEN + f"{k}: {v}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def username_check():
    user = input(Fore.CYAN + "Enter username: ")
    sites = {
        "GitHub": f"https://github.com/{user}",
        "Reddit": f"https://www.reddit.com/user/{user}",
        "Twitter": f"https://x.com/{user}"
    }
    for s, url in sites.items():
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                print(Fore.GREEN + f"✅ Found on {s}: {url}")
            else:
                print(Fore.RED + f"❌ Not on {s}")
        except:
            print(Fore.RED + f"Error checking {s}")

def header_grabber():
    site = input(Fore.CYAN + "Enter website (http/https): ")
    try:
        r = requests.get(site)
        print(Fore.GREEN + "\nHeaders:")
        for k, v in r.headers.items():
            print(Fore.YELLOW + f"{k}: {v}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def subdomain_finder():
    domain = input(Fore.CYAN + "Enter domain: ")
    wordlist = ["www", "mail", "ftp", "dev", "test", "admin"]
    print(Fore.YELLOW + "\nScanning common subdomains...")
    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            print(Fore.GREEN + f"✅ Found: {subdomain}")
        except:
            pass

def port_scanner():
    host = input(Fore.CYAN + "Enter host (IP/domain): ")
    print(Fore.YELLOW + "\nScanning ports 1–100...")
    for port in range(1, 101):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            if s.connect_ex((host, port)) == 0:
                print(Fore.GREEN + f"Open: {port}")
            s.close()
        except:
            pass

def image_metadata():
    from PIL import Image
    from PIL.ExifTags import TAGS
    path = input(Fore.CYAN + "Enter image path: ")
    try:
        img = Image.open(path)
        exif = img._getexif()
        if not exif:
            print(Fore.RED + "No EXIF metadata found")
            return
        for tag, val in exif.items():
            tagname = TAGS.get(tag, tag)
            print(Fore.GREEN + f"{tagname}: {val}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

# --- Main ---
if __name__ == "__main__":
    countdown_redirect()
    while True:
        menu()
        choice = input(Fore.CYAN + "Select option: ")
        if choice == "1": phone_lookup()
        elif choice == "2": email_check()
        elif choice == "3": domain_lookup()
        elif choice == "4": ip_lookup()
        elif choice == "5": username_check()
        elif choice == "6": header_grabber()
        elif choice == "7": subdomain_finder()
        elif choice == "8": port_scanner()
        elif choice == "9": image_metadata()
        elif choice == "0":
            print(Fore.MAGENTA + "Bye 👋")
            sys.exit()
        else:
            print(Fore.RED + "Invalid option")
        input(Fore.CYAN + "\nPress Enter to continue...")
