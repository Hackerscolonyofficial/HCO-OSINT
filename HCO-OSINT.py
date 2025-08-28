#!/usr/bin/env python3
"""
HCO-OSINT.py — Advanced single-file OSINT toolkit
By Azhar (Hackers Colony)
Termux-ready with YouTube unlock flow
"""

import os, sys, time, json, re, socket, concurrent.futures
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import requests
from colorama import Fore, Style, init
import phonenumbers

# Try to import DNS-related modules with fallbacks
try:
    import dns.resolver
    DNS_AVAILABLE = True
except:
    DNS_AVAILABLE = False

try:
    import whois as pywhois
    WHOIS_AVAILABLE = True
except:
    WHOIS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except:
    BS4_AVAILABLE = False

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except:
    PIL_AVAILABLE = False

init(autoreset=True)
REPORTS_DIR = Path("hco_reports")
REPORTS_DIR.mkdir(exist_ok=True)
USER_AGENT = "HCO-OSINT/1.0 (Educational)"
RATE_DELAY = 0.6

# ---------------- Utilities ----------------
def nowstamp(): return datetime.utcnow().strftime("%Y%m%d-%H%M%S")
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
    for s in ["9","8?","7?","6.","5.","4.","3.","2.","1"]:
        print(Fore.MAGENTA+Style.BRIGHT+s, end=" ", flush=True)
        time.sleep(0.7)
    print(Fore.GREEN+"\nOpening YouTube app...")
    YOUTUBE_URL="https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya"
    os.system(f'am start -a android.intent.action.VIEW -d "{YOUTUBE_URL}"')
    input(Fore.CYAN+"\nAfter subscribing, press ENTER to continue...")
    show_big_title()

def show_big_title():
    clear()
    print(Fore.GREEN + Style.BRIGHT + """
  _    _  ____   ___    ____   ___   _   _ _____ _______ 
 | |  | |/ __ \ / _ \  / __ \ / _ \ | \ | |_   _|__   __|
 | |__| | |  | | | | | | |  | | | | |  \| | | |    | |   
 |  __  | |  | | | | | | |  | | | | | . ` | | |    | |   
 | |  | | |__| | |_| | | |__| | |_| | |\  |_| |_   | |   
 |_|  |_|\____/ \___/   \____/ \___/|_| \_|_____|  |_|   
    """)
    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + """
   ___  _____  ___   _   _ _______ 
  / _ \/  __ \/ _ \ | \ | |__   __|
 / /_\ \ /  \/ /_\ \|  \| |  | |   
 |  _  | |   |  _  || . ` |  | |   
 | | | | \__/\ | | || |\  |  | |   
 \_| |_/\____\_| |_/_| \_|  |_|   
    """)
    print(Fore.WHITE + "-" * 72)
    print(Fore.LIGHTYELLOW_EX + "by Azhar (Hackers Colony)")
    print(Fore.WHITE + "-" * 72)

# ---------------- DNS Helper Functions ----------------
def resolve_dns(domain, record_type):
    """Resolve DNS records with fallback to system DNS"""
    if not DNS_AVAILABLE:
        return {"error": "dnspython library not available"}
    
    try:
        # Try to use system DNS as fallback
        resolver = dns.resolver.Resolver()
        # Use multiple public DNS servers
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        answers = resolver.resolve(domain, record_type, lifetime=8)
        return [str(a).rstrip(".") for a in answers]
    except Exception as e:
        return {"error": str(e)}

# ---------------- Free API Functions ----------------
def get_ip_api_data(ip):
    """Get data from multiple IP APIs"""
    results = {}
    
    # IP-API.com
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        results['ip_api_com'] = response.json()
    except:
        results['ip_api_com'] = {"error": "API request failed"}
    
    # IPInfo.io (free tier)
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        results['ipinfo_io'] = response.json()
    except:
        results['ipinfo_io'] = {"error": "API request failed"}
    
    # IPAPI.co
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
        results['ipapi_co'] = response.json()
    except:
        results['ipapi_co'] = {"error": "API request failed"}
    
    return results

def get_email_breach_data(email):
    """Check if email appears in known breaches using HaveIBeenPwned API"""
    try:
        # Note: This API only checks if email is in breach database, doesn't return breach details
        response = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={"User-Agent": USER_AGENT, "hibp-api-key": ""},  # Add your API key if you have one
            timeout=15
        )
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"breach_status": "No breaches found"}
        else:
            return {"error": f"API returned status {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def get_phone_carrier_info(phone_number):
    """Get carrier information for phone number using NumVerify API (free tier)"""
    # Note: You need to sign up for a free API key at numverify.com
    API_KEY = ""  # Add your API key here
    if not API_KEY:
        return {"info": "Add NumVerify API key for carrier information"}
    
    try:
        response = requests.get(
            f"http://apilayer.net/api/validate?access_key={API_KEY}&number={phone_number}",
            timeout=10
        )
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def get_social_media_info(username):
    """Check username across multiple social media platforms"""
    platforms = {
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "Medium": f"https://medium.com/@{username}",
        "Vimeo": f"https://vimeo.com/{username}",
        "Flickr": f"https://www.flickr.com/people/{username}",
    }
    
    results = {}
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    
    for platform, url in platforms.items():
        try:
            response = session.head(url, allow_redirects=True, timeout=8)
            results[platform] = {
                "url": url,
                "exists": response.status_code < 400,
                "status_code": response.status_code
            }
            time.sleep(0.2)  # Rate limiting
        except:
            results[platform] = {
                "url": url,
                "exists": False,
                "error": "Request failed"
            }
    
    return results

def get_domain_info(domain):
    """Get comprehensive domain information from multiple sources"""
    results = {}
    
    # Security Headers API
    try:
        response = requests.get(f"https://securityheaders.com/?q={domain}&followRedirects=on", timeout=10)
        results['security_headers'] = {"info": "Check completed", "url": f"https://securityheaders.com/?q={domain}"}
    except:
        results['security_headers'] = {"error": "Check failed"}
    
    # SSL Labs API (quick check)
    try:
        response = requests.get(f"https://api.ssllabs.com/api/v3/analyze?host={domain}", timeout=15)
        results['ssl_labs'] = response.json()
    except:
        results['ssl_labs'] = {"error": "SSL check failed"}
    
    # Wayback Machine API
    try:
        response = requests.get(f"http://archive.org/wayback/available?url={domain}", timeout=10)
        results['wayback_machine'] = response.json()
    except:
        results['wayback_machine'] = {"error": "Wayback Machine check failed"}
    
    return results

def get_image_metadata_online(url):
    """Get online image metadata using reverse image search APIs"""
    results = {}
    
    # Google Reverse Image Search (link only)
    results['google_reverse'] = {"url": f"https://www.google.com/searchbyimage?image_url={url}"}
    
    # TinEye Reverse Image Search (link only)
    results['tineye_reverse'] = {"url": f"https://tineye.com/search?url={url}"}
    
    return results

# ---------------- OSINT modules ----------------
def ip_info(target):
    out = {"query": target, "timestamp": nowstamp()}
    try: 
        ip = socket.gethostbyname(target)
    except: 
        ip = target
    out["resolved_ip"] = ip
    
    # Get data from multiple IP APIs
    out["apis"] = get_ip_api_data(ip)
    
    # Additional IP information
    try:
        out["hostname"] = socket.gethostbyaddr(ip)[0]
    except:
        out["hostname"] = "Reverse lookup failed"
    
    # Check for common ports
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3389]
    port_scan = {}
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            port_scan[port] = "open" if result == 0 else "closed"
            sock.close()
        except:
            port_scan[port] = "check failed"
    out["common_ports"] = port_scan
    
    return out

def whois_and_dns(domain):
    out = {"query": domain, "timestamp": nowstamp()}
    
    # WHOIS lookup
    if WHOIS_AVAILABLE:
        try:
            w = pywhois.whois(domain)
            out["whois"] = {k: str(v) for k, v in w.items()}
        except Exception as e: 
            out["whois"] = {"error": str(e)}
    else:
        out["whois"] = {"error": "whois library not available"}
    
    # DNS lookup
    dns_out = {}
    for rtype in ("A", "NS", "MX", "TXT", "CNAME", "AAAA"):
        try:
            result = resolve_dns(domain, rtype)
            dns_out[rtype] = result
        except Exception as ex: 
            dns_out[rtype] = {"error": str(ex)}
    out["dns"] = dns_out
    
    # Get additional domain information
    out["domain_info"] = get_domain_info(domain)
    
    return out

def email_info(email):
    out = {"query": email, "timestamp": nowstamp()}
    out["format_valid"] = bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))
    domain = email.split("@")[-1] if "@" in email else None
    
    if domain:
        try:
            mx_records = resolve_dns(domain, "MX")
            out["mx"] = mx_records
        except Exception as e: 
            out["mx"] = {"error": str(e)}
        
        # Check for breaches
        out["breach_check"] = get_email_breach_data(email)
    else: 
        out["mx"] = {"note": "invalid email"}
    
    # Check disposable email domains
    disposable_domains = ["tempmail", "10minutemail", "guerrillamail", "mailinator", "dispostable"]
    out["is_disposable"] = any(disposable in domain for disposable in disposable_domains) if domain else False
    
    return out

def phone_info(number):
    out = {"query": number, "timestamp": nowstamp()}
    try:
        pn = phonenumbers.parse(number, None)
        out["international"] = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        out["national"] = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL)
        out["country_code"] = pn.country_code
        out["possible"] = phonenumbers.is_possible_number(pn)
        out["valid"] = phonenumbers.is_valid_number(pn)
        out["region"] = phonenumbers.region_code_for_number(pn)
        
        # Get carrier information
        out["carrier_info"] = get_phone_carrier_info(number)
    except Exception as e: 
        out["error"] = str(e)
    return out

def username_check(uname, sites=None, workers=12, delay=RATE_DELAY):
    out = {"query": uname, "timestamp": nowstamp()}
    
    # Check social media platforms
    out["social_media"] = get_social_media_info(uname)
    
    # Check namechk.com (simulated)
    out["namechk_simulation"] = {
        "info": "Simulating namechk.com check across multiple platforms",
        "platforms_checked": list(out["social_media"].keys())
    }
    
    return out

def crtsh_subdomains(domain):
    out = {"query": domain, "timestamp": nowstamp()}
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", headers={"User-Agent": USER_AGENT}, timeout=15)
        if r.status_code == 200:
            data = r.json()
            subs = set()
            for item in data:
                name = item.get("name_value", "")
                for part in name.split("\n"): 
                    subs.add(part.strip())
            out["subdomains"] = sorted(subs)
        else: 
            out["error"] = f"crt.sh status {r.status_code}"
    except Exception as e: 
        out["error"] = str(e)
    
    # Check other subdomain sources
    try:
        # AnubisDB API
        response = requests.get(f"https://jonlu.ca/anubis/subdomains/{domain}", timeout=10)
        if response.status_code == 200:
            out["anubis_db"] = response.json()
    except:
        out["anubis_db"] = {"error": "AnubisDB check failed"}
    
    return out

def expand_url(url):
    out = {"original": url, "timestamp": nowstamp()}
    try:
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=12, allow_redirects=True)
        out["final"] = r.url
        out["status_code"] = r.status_code
        out["history"] = [h.url for h in r.history]
        
        if BS4_AVAILABLE:
            parsed = urlparse(r.url)
            sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
            try:
                s = requests.get(sitemap_url, headers={"User-Agent": USER_AGENT}, timeout=8)
                if s.status_code == 200:
                    soup = BeautifulSoup(s.text, "xml")
                    urls = [u.text for u in soup.find_all("loc")]
                    out["sitemap_count"] = len(urls)
                    out["sitemap_sample"] = urls[:10]
                else: 
                    out["sitemap_status"] = s.status_code
            except: 
                out["sitemap_status"] = "error"
        else:
            out["sitemap_status"] = "BeautifulSoup not available"
        
        # URL analysis
        out["url_analysis"] = {
            "is_shortened": any(service in url for service in ["bit.ly", "goo.gl", "t.co", "tinyurl", "ow.ly"]),
            "final_domain": urlparse(r.url).netloc
        }
    except Exception as e: 
        out["error"] = str(e)
    return out

def extract_exif(path):
    if not PIL_AVAILABLE: 
        return {"error": "Pillow not installed"}
    if not os.path.exists(path): 
        return {"error": "file not found"}
    try:
        img = Image.open(path)
        exif = {}
        raw = img._getexif() or {}
        for tagid, value in raw.items(): 
            exif[TAGS.get(tagid, tagid)] = value
        
        result = {"file": path, "exif": exif, "timestamp": nowstamp()}
        
        # Add GPS info if available
        if "GPSInfo" in exif:
            result["gps_info"] = exif["GPSInfo"]
        
        # Add basic image info
        result["image_info"] = {
            "format": img.format,
            "size": img.size,
            "mode": img.mode
        }
        
        return result
    except Exception as e: 
        return {"error": str(e)}

def show_menu():
    print()
    print(Fore.CYAN + "1) IP lookup")
    print(Fore.CYAN + "2) WHOIS & DNS lookup")
    print(Fore.CYAN + "3) Email check")
    print(Fore.CYAN + "4) Phone parse")
    print(Fore.CYAN + "5) Username checks")
    print(Fore.CYAN + "6) Subdomain discovery")
    print(Fore.CYAN + "7) URL expand & sitemap")
    print(Fore.CYAN + "8) EXIF metadata from image")
    print(Fore.YELLOW + "s) Save last result")
    print(Fore.RED + "q) Quit\n")

def interactive():
    last_result = None
    show_big_title()
    print(Fore.YELLOW + "⚠️  Use ethically. Do NOT target systems without permission.")
    
    # Show available features
    if not DNS_AVAILABLE:
        print(Fore.RED + "⚠️  DNS features limited (dnspython not installed)")
    if not WHOIS_AVAILABLE:
        print(Fore.RED + "⚠️  WHOIS features limited (python-whois not installed)")
    if not BS4_AVAILABLE:
        print(Fore.RED + "⚠️  URL expansion features limited (BeautifulSoup not installed)")
    if not PIL_AVAILABLE:
        print(Fore.RED + "⚠️  EXIF features limited (Pillow not installed)")
    
    while True:
        show_menu()
        choice = input(Fore.MAGENTA + "Choice: ").strip().lower()
        if choice == "1": 
            tgt = input("IP/host: ")
            last_result = ip_info(tgt)
            pretty_print(last_result)
        elif choice == "2": 
            if not WHOIS_AVAILABLE:
                print(Fore.RED + "WHOIS functionality not available. Install python-whois")
                continue
            dom = input("Domain: ")
            last_result = whois_and_dns(dom)
            pretty_print(last_result)
        elif choice == "3": 
            em = input("Email: ")
            last_result = email_info(em)
            pretty_print(last_result)
        elif choice == "4": 
            ph = input("Phone (+country): ")
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
            if not PIL_AVAILABLE: 
                print(Fore.RED + "Pillow not installed")
                continue
            path = input("Image path: ")
            last_result = extract_exif(path)
            pretty_print(last_result)
        elif choice == "s":
            if last_result:
                fname = input("Filename (without extension): ") or "result"
                path = save_json(fname, last_result)
                print(Fore.GREEN + f"Saved to {path}")
            else:
                print(Fore.RED + "No result to save")
        elif choice == "q":
            print(Fore.GREEN + "Goodbye!")
            break
        else:
            print(Fore.RED + "Invalid choice")

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
