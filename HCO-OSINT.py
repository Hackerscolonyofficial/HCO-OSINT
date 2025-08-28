#!/usr/bin/env python3
"""
HCO-OSINT.py — Advanced single-file OSINT toolkit
By Azhar (Hackers Colony)
Termux-ready with YouTube unlock flow
"""

import os, sys, time, json, re, socket, concurrent.futures
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests
from colorama import Fore, Style, init
import phonenumbers

init(autoreset=True)
REPORTS_DIR = Path("hco_reports")
REPORTS_DIR.mkdir(exist_ok=True)
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
RATE_DELAY = 0.6

# ---------------- Utilities ----------------
def nowstamp(): return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
def safe_filename(s): return re.sub(r'[^A-Za-z0-9._-]', '_', s)
def save_json(name,obj):
    p = REPORTS_DIR/f"{safe_filename(name)}-{nowstamp()}.json"
    p.write_text(json.dumps(obj,indent=2,ensure_ascii=False),encoding="utf-8")
    return p
def pretty_print(obj): print(json.dumps(obj,indent=2,ensure_ascii=False))
def clear(): os.system("clear")

# ---------------- Unlock flow (Termux) ----------------
def unlock_flow():
    clear()
    print(Fore.CYAN+"🔒 Tool locked. Subscribe to unlock.")
    for s in ["3","2","1"]:
        print(Fore.MAGENTA+Style.BRIGHT+s, end=" ", flush=True)
        time.sleep(0.7)
    print(Fore.GREEN+"\nOpening YouTube app...")
    YOUTUBE_URL="https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya"
    os.system(f'am start -a android.intent.action.VIEW -d "{YOUTUBE_URL}"')
    input(Fore.CYAN+"\nAfter subscribing, press ENTER to continue...")

def show_title():
    clear()
    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "=" * 60)
    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "              H C O   O S I N T
    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "=" * 60)
    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "           by Azhar (Hackers Colony)")
    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "=" * 60)
    print()

# ---------------- DNS Helper Functions ----------------
def simple_dns_lookup(domain, record_type):
    """Simple DNS lookup using socket and requests"""
    try:
        if record_type == "A":
            return [socket.gethostbyname(domain)]
        elif record_type == "MX":
            # Use external API for MX records
            try:
                response = requests.get(f"https://dns.google/resolve?name={domain}&type=MX", 
                                      headers={"User-Agent": USER_AGENT}, timeout=10)
                data = response.json()
                mx_records = []
                for answer in data.get("Answer", []):
                    if "MX" in answer.get("data", ""):
                        mx_records.append(answer["data"])
                return mx_records if mx_records else ["No MX records found"]
            except:
                return ["MX lookup failed"]
        else:
            return [f"{record_type} lookup not implemented"]
    except Exception as e:
        return [f"Error: {str(e)}"]

# ---------------- OSINT modules ----------------
def ip_info(target):
    out={"query":target,"timestamp":nowstamp()}
    try: 
        ip=socket.gethostbyname(target)
        out["resolved_ip"]=ip
    except: 
        out["resolved_ip"]=target
        ip = target
    
    # Get IP information from free API
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        out["ip_info"] = response.json()
    except Exception as e: 
        out["ip_info"]={"error":str(e)}
    
    return out

def whois_and_dns(domain):
    out={"query":domain,"timestamp":nowstamp()}
    
    # Try to use whois command
    try:
        result = os.popen(f"whois {domain}").read()
        out["whois"] = result[:2000] + "..." if len(result) > 2000 else result
    except Exception as e: 
        out["whois"]={"error":str(e)}
    
    # DNS lookup
    dns_out={}
    for rtype in ("A","MX"):
        try:
            result = simple_dns_lookup(domain, rtype)
            dns_out[rtype]=result
        except Exception as ex: 
            dns_out[rtype]={"error":str(ex)}
    out["dns"]=dns_out
    
    return out

def email_info(email):
    out={"query":email,"timestamp":nowstamp()}
    out["format_valid"]=bool(re.match(r"[^@]+@[^@]+\.[^@]+",email))
    
    if out["format_valid"]:
        domain=email.split("@")[-1]
        try:
            mx_records = simple_dns_lookup(domain, "MX")
            out["mx"]=mx_records
        except Exception as e: 
            out["mx"]={"error":str(e)}
        
        # Check if email is from common providers
        common_providers = ["gmail", "yahoo", "outlook", "hotmail", "protonmail"]
        out["common_provider"] = any(provider in domain for provider in common_providers)
        
        # Check for disposable emails
        disposable_domains = ["tempmail", "10minutemail", "guerrillamail", "mailinator", "dispostable"]
        out["is_disposable"] = any(disposable in domain for disposable in disposable_domains)
    else: 
        out["error"]="Invalid email format"
    
    return out

def phone_info(number):
    out={"query":number,"timestamp":nowstamp()}
    try:
        # Simple validation without external APIs
        cleaned = re.sub(r'[^0-9+]', '', number)
        out["cleaned_number"] = cleaned
        
        # Basic validation
        if cleaned.startswith('+'):
            out["international_format"] = True
            out["country_code"] = cleaned[1:3] if len(cleaned) > 3 else "Unknown"
        else:
            out["international_format"] = False
            
        out["length"] = len(cleaned)
        out["likely_valid"] = len(cleaned) >= 10
        
    except Exception as e: 
        out["error"]=str(e)
    return out

USERNAME_SITES=[
    ("Twitter","https://twitter.com/{}"),
    ("Instagram","https://www.instagram.com/{}"),
    ("GitHub","https://github.com/{}"),
    ("Reddit","https://www.reddit.com/user/{}"),
    ("YouTube","https://www.youtube.com/@{}"),
]

def _check_profile(site_name, pattern, uname):
    url=pattern.format(uname)
    try:
        response = requests.head(url, headers={"User-Agent": USER_AGENT}, 
                               timeout=8, allow_redirects=True)
        return {"site":site_name,"url":url,"status":response.status_code,
                "exists":response.status_code < 400}
    except: 
        return {"site":site_name,"url":url,"status":None,"exists":False}

def username_check(uname):
    out = {"query": uname, "timestamp": nowstamp()}
    results = []
    
    for site_name, pattern in USERNAME_SITES:
        result = _check_profile(site_name, pattern, uname)
        results.append(result)
        time.sleep(0.3)  # Rate limiting
    
    out["results"] = results
    return out

def crtsh_subdomains(domain):
    out={"query":domain,"timestamp":nowstamp()}
    try:
        response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", 
                              headers={"User-Agent": USER_AGENT}, timeout=15)
        if response.status_code == 200:
            data = response.json()
            subs = set()
            for item in data:
                name = item.get("name_value", "")
                if name:
                    subs.add(name.strip())
            out["subdomains"] = sorted(subs)[:20]  # Limit to first 20
        else: 
            out["error"] = f"API returned status {response.status_code}"
    except Exception as e: 
        out["error"] = str(e)
    return out

def expand_url(url):
    out={"original":url,"timestamp":nowstamp()}
    try:
        response = requests.get(url, headers={"User-Agent": USER_AGENT}, 
                              timeout=12, allow_redirects=True)
        out["final_url"] = response.url
        out["status_code"] = response.status_code
        out["redirects"] = len(response.history)
        
        # Get page title if available
        if "text/html" in response.headers.get("content-type", ""):
            try:
                title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                if title_match:
                    out["page_title"] = title_match.group(1)
            except:
                pass
                
    except Exception as e: 
        out["error"] = str(e)
    return out

def extract_exif(path):
    out = {"query": path, "timestamp": nowstamp()}
    if not os.path.exists(path): 
        out["error"] = "File not found"
        return out
    
    # Try to use exiftool command if available
    try:
        result = os.popen(f"exiftool {path}").read()
        out["metadata"] = result
    except Exception as e:
        out["error"] = f"Exif extraction failed: {str(e)}. Install exiftool for better results."
    
    return out

def show_menu():
    print()
    print(Fore.CYAN+"1) IP lookup")
    print(Fore.CYAN+"2) WHOIS & DNS lookup")
    print(Fore.CYAN+"3) Email check")
    print(Fore.CYAN+"4) Phone parse")
    print(Fore.CYAN+"5) Username checks")
    print(Fore.CYAN+"6) Subdomain discovery")
    print(Fore.CYAN+"7) URL expand & sitemap")
    print(Fore.CYAN+"8) EXIF metadata from image")
    print(Fore.YELLOW+"s) Save last result")
    print(Fore.RED+"q) Quit\n")

def interactive():
    last_result = None
    show_title()
    print(Fore.YELLOW+"⚠️  Use ethically. Do NOT target systems without permission.")
    
    while True:
        show_menu()
        choice = input(Fore.MAGENTA+"Choice: ").strip().lower()
        if choice == "1": 
            tgt = input("IP/host: ")
            last_result = ip_info(tgt)
            pretty_print(last_result)
        elif choice == "2": 
            dom = input("Domain: ")
            last_result = whois_and_dns(dom)
            pretty_print(last_result)
        elif choice == "3": 
            em = input("Email: ")
            last_result = email_info(em)
            pretty_print(last_result)
        elif choice == "4": 
            ph = input("Phone number: ")
            last_result = phone_info(ph)
            pretty_print(last_result)
        elif choice == "5": 
            uname = input("Username: ")
            last_result = username_check(uname)
            pretty_print(last_result)
        elif choice == "6": 
            dom = input("Domain: ")
            last_result = crtsh_subdomains(dom)
            pretty_print(last_result)
        elif choice == "7": 
            u = input("URL: ")
            last_result = expand_url(u)
            pretty_print(last_result)
        elif choice == "8":
            path = input("Image path: ")
            last_result = extract_exif(path)
            pretty_print(last_result)
        elif choice == "s":
            if last_result:
                fname = input("Filename (without extension): ") or "result"
                path = save_json(fname, last_result)
                print(Fore.GREEN+f"Saved to {path}")
            else:
                print(Fore.RED+"No result to save")
        elif choice == "q":
            print(Fore.GREEN+"Goodbye!")
            break
        else:
            print(Fore.RED+"Invalid choice")

# ---------------- Main execution ----------------
if __name__ == "__main__":
    try:
        unlock_flow()
        interactive()
    except KeyboardInterrupt:
        print(Fore.RED + "\nOperation cancelled by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"\nUnexpected error: {e}")
        sys.exit(1)
