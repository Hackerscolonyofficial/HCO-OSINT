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
import requests
import webbrowser
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Path to store device-wide unlock flag
UNLOCK_FILE = os.path.expanduser("~/.hco_osint_unlock")

# API Keys
SHODAN_API_KEY = "iph718pM0AvRkryYhYDWSXdEgcoa"
IPINFO_API_KEY = "d28f2d86535f4a"
WHOISXML_API_KEY = "at_yOcz6VLB6VJyKuDaAUDrI3F3fOi86"
ABSTRACT_API_KEY = "f97bc3bedb2944e8b16c02d76680fd44"

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

    # Open YouTube channel in app/browser
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
╔══════════════════════════════════════╗
║        🚀 HCO-OSINT TOOL 🚀          ║
║    By Azhar - Hackers Colony Team    ║
╚══════════════════════════════════════╝
""")

# ---------- IP Lookup Function ----------
def ip_lookup():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ")
    try:
        # Shodan API
        shodan_url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        shodan_response = requests.get(shodan_url).json()
        print(Fore.GREEN + "\n[+] Shodan Info:\n")
        print(Fore.YELLOW + "Organization: " + Fore.WHITE + shodan_response.get("org", "N/A"))
        print(Fore.YELLOW + "Location: " + Fore.WHITE + f"{shodan_response.get('city', 'N/A')}, {shodan_response.get('country_name', 'N/A')}")
        print(Fore.YELLOW + "ISP: " + Fore.WHITE + shodan_response.get("isp", "N/A"))
    except Exception as e:
        print(Fore.RED + f"Error fetching Shodan data: {e}")

    try:
        # IPinfo API
        ipinfo_url = f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}"
        ipinfo_response = requests.get(ipinfo_url).json()
        print(Fore.GREEN + "\n[+] IPinfo Details:\n")
        print(Fore.YELLOW + "Hostname: " + Fore.WHITE + ipinfo_response.get("hostname", "N/A"))
        print(Fore.YELLOW + "City: " + Fore.WHITE + ipinfo_response.get("city", "N/A"))
        print(Fore.YELLOW + "Region: " + Fore.WHITE + ipinfo_response.get("region", "N/A"))
        print(Fore.YELLOW + "Country: " + Fore.WHITE + ipinfo_response.get("country", "N/A"))
        print(Fore.YELLOW + "Location: " + Fore.WHITE + ipinfo_response.get("loc", "N/A"))
    except Exception as e:
        print(Fore.RED + f"Error fetching IPinfo data: {e}")

# ---------- WHOIS Lookup Function ----------
def whois_lookup():
    domain = input(Fore.CYAN + "\n[?] Enter Domain: ")
    try:
        # WhoisXML API
        whois_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOISXML_API_KEY}&domainName={domain}&outputFormat=JSON"
        whois_response = requests.get(whois_url).json()
        print(Fore.GREEN + "\n[+] WHOIS Information:\n")
        print(Fore.YELLOW + "Registrar: " + Fore.WHITE + whois_response['WhoisRecord'].get('registrarName', 'N/A'))
        print(Fore.YELLOW + "Created Date: " + Fore.WHITE + whois_response['WhoisRecord'].get('createdDate', 'N/A'))
        print(Fore.YELLOW + "Updated Date: " + Fore.WHITE + whois_response['WhoisRecord'].get('updatedDate', 'N/A'))
        print(Fore.YELLOW + "Expires Date: " + Fore.WHITE + whois_response['WhoisRecord'].get('expiresDate', 'N/A'))
    except Exception as e:
        print(Fore.RED + f"Error fetching WHOIS data: {e}")

# ---------- Abstract API Function ----------
def abstract_lookup():
    ip = input(Fore.CYAN + "\n[?] Enter IP Address: ")
    try:
        # Abstract API
        abstract_url = f"https://ipgeolocation.abstractapi.com/v1/?api_key={ABSTRACT_API_KEY}&ip_address={ip}"
        abstract_response = requests.get(abstract_url).json()
        print(Fore.GREEN + "\n[+] Abstract API Geolocation:\n")
        print(Fore.YELLOW + "Country: " + Fore.WHITE + abstract_response.get("country", "N/A"))
        print(Fore.YELLOW + "Region: " + Fore.WHITE + abstract_response.get("region", "N/A"))
        print(Fore.YELLOW + "City: " + Fore.WHITE + abstract_response.get("city", "N/A"))
        print(Fore.YELLOW + "Latitude: " + Fore.WHITE + str(abstract_response.get("latitude", "N/A")))
        print(Fore.YELLOW + "Longitude: " + Fore.WHITE + str(abstract_response.get("longitude", "N/A")))
    except Exception as e:
        print(Fore.RED + f"Error fetching Abstract API data: {e}")

# ---------- Menu ----------
def menu():
    banner()
    print(Fore.CYAN + Style.BRIGHT + """
[1]  IP Lookup
[2]  WHOIS Lookup
[3]  Abstract API Lookup
[0]  Exit
""")

# ---------- Main ----------
def main():
    unlock()  # Run device-wide unlock first
    while True:
        menu()
        choice = input(Fore.YELLOW + "[?] Select option: ")

        if choice == "1": ip_lookup()
        elif choice == "2": whois_lookup()
        elif choice == "3": abstract_lookup()
        elif choice == "0":
            print(Fore.GREEN + "\nExiting... Bye!\n")
            sys.exit()
        else:
            print(Fore.RED + "Invalid Choice!")

        input(Fore.CYAN + "\nPress Enter to continue...")

if __name__ == "__main__":
    main()
