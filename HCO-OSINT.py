#!/usr/bin/env python3
"""
HCO OSINT Tool by Azhar
Free API Based OSINT Scanner (Termux version)
"""

import requests, socket, time, os, sys, webbrowser
from colorama import Fore, Style, init
init(autoreset=True)

YOUTUBE_URL = "https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya"

# ---------- Banner ----------
def banner():
    os.system("clear")
    print(Fore.CYAN + "═══════════════════════════════════════")
    print(Fore.RED + Style.BRIGHT + "     🚀 HCO OSINT TOOL by Azhar 🚀")
    print(Fore.CYAN + "═══════════════════════════════════════\n")

# ---------- Unlock System ----------
def unlock():
    banner()
    print(Fore.YELLOW + "🔒 This tool is locked!")
    print(Fore.GREEN + "👉 To unlock, SUBSCRIBE & click the BELL 🔔 on our YouTube channel\n")
    print(Fore.CYAN + "Redirecting in 8 seconds...\n")

    for i in range(8,0,-1):
        colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.CYAN, Fore.MAGENTA, Fore.BLUE]
        print(colors[i%len(colors)] + f"{i} ", end="\r")
        time.sleep(1)

    webbrowser.open(YOUTUBE_URL)  # open in YouTube app if installed
    print(Fore.GREEN + "\n✅ After subscribing, return here to use the tool!\n")
    input(Fore.CYAN + "Press Enter once you subscribed...")

# ---------- Modules ----------
def ip_lookup():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ")
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}").json()
        print(Fore.GREEN + "\n[+] IP Information:\n")
        for k, v in r.items():
            print(f"{Fore.YELLOW}{k.title():<15}: {Fore.WHITE}{v}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def domain_lookup():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ")
    try:
        ip = socket.gethostbyname(domain)
        print(Fore.GREEN + f"\nDomain : {domain}\nIP     : {ip}\n")
        r = requests.get(f"http://ip-api.com/json/{ip}").json()
        for k, v in r.items():
            print(f"{Fore.YELLOW}{k.title():<15}: {Fore.WHITE}{v}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def headers_lookup():
    url = input(Fore.CYAN + "\n[?] Enter Website URL (https://...): ")
    try:
        r = requests.get(url)
        print(Fore.GREEN + "\n[+] Response Headers:\n")
        for k, v in r.headers.items():
            print(f"{Fore.YELLOW}{k}: {Fore.WHITE}{v}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def phone_lookup():
    phone = input(Fore.CYAN + "\n[?] Enter Phone Number with country code (+91...): ")
    try:
        # Free demo lookup
        r = requests.get(f"https://numverify.com/php_helper_scripts/phone_api.php?number={phone}").json()
        print(Fore.GREEN + "\n[+] Phone Information:\n")
        for k, v in r.items():
            print(f"{Fore.YELLOW}{k.title():<15}: {Fore.WHITE}{v}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def email_lookup():
    email = input(Fore.CYAN + "\n[?] Enter Email Address: ")
    try:
        r = requests.get(f"https://isitarealemail.com/api/email/validate?email={email}")
        status = r.json().get("status")
        print(Fore.GREEN + f"\nEmail: {email}")
        print(Fore.YELLOW + "Status: " + Fore.WHITE + status)
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def username_lookup():
    username = input(Fore.CYAN + "\n[?] Enter Username: ")
    sites = ["https://github.com/", "https://twitter.com/", "https://instagram.com/"]
    print(Fore.GREEN + f"\n[+] Checking username '{username}' ...\n")
    for site in sites:
        url = site + username
        try:
            r = requests.get(url)
            if r.status_code == 200:
                print(Fore.GREEN + f"[FOUND] {url}")
            else:
                print(Fore.RED + f"[NOT FOUND] {url}")
        except:
            print(Fore.RED + f"[ERROR] {url}")

def dns_lookup():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/dnslookup/?q={domain}")
        print(Fore.GREEN + "\n[+] DNS Lookup:\n")
        print(Fore.WHITE + r.text)
    except:
        print(Fore.RED + "Error in DNS Lookup")

def whois_lookup():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/whois/?q={domain}")
        print(Fore.GREEN + "\n[+] WHOIS Data:\n")
        print(Fore.WHITE + r.text)
    except:
        print(Fore.RED + "Error in WHOIS")

def subdomain_scan():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        print(Fore.GREEN + "\n[+] Subdomains:\n")
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
    unlock()  # run unlock first
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
