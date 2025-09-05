#!/usr/bin/env python3
"""
HCO-OSINT (Termux Pro) — Single-file
By Azhar | Hackers Colony

Features:
- Lock screen with countdown and real redirect to YouTube channel (uses termux-open-url if available)
- All output printed in Termux with colors (colorama)
- Email, Phone, Username footprint (multi-threaded), Domain WHOIS/DNS, IP whois (via system whois), SSL cert expiry, Image EXIF (local), File hashing, Password audit
- No paid APIs required. Uses HTTP/DNS/WHOIS/SSL system calls only.
- Graceful fallback if optional modules are missing.
"""
import os, sys, time, re, json, socket, ssl, threading, hashlib, subprocess, traceback
from datetime import datetime
from urllib.parse import urlparse

# --------- Optional third-party modules (graceful) ----------
try:
    import requests
except Exception:
    requests = None

try:
    import dns.resolver as dnsresolver
except Exception:
    dnsresolver = None

try:
    import whois as pywhois
except Exception:
    pywhois = None

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone as ptimezone
except Exception:
    phonenumbers = None

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
except Exception:
    Image = None

try:
    import exifread
except Exception:
    exifread = None

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
except Exception:
    # fallback to no-color
    class _C:
        def __getattr__(self, name): return ""
    Fore = Style = _C()

# --------- Config ---------
YOUTUBE_URL = "https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya"
LOGFILE = "hco-osint.log"
USERNAME_SITES = {
    "GitHub": "https://github.com/{u}",
    "Twitter": "https://twitter.com/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "Reddit": "https://www.reddit.com/user/{u}/",
    "TikTok": "https://www.tiktok.com/@{u}",
    "LinkedIn": "https://www.linkedin.com/in/{u}",
    "YouTube": "https://www.youtube.com/{u}",
    "Pinterest": "https://www.pinterest.com/{u}/",
    "StackOverflow": "https://stackoverflow.com/users/{u}",
    "Medium": "https://medium.com/@{u}",
    "Dev.to": "https://dev.to/{u}",
}

DISPOSABLE_DOMAINS = {"mailinator.com","10minutemail.com","maildrop.cc","yopmail.com","trashmail.com"}

# --------- Utilities ---------
def log(msg: str):
    try:
        with open(LOGFILE, "a") as f:
            f.write(f"{datetime.utcnow().isoformat()} {msg}\n")
    except Exception:
        pass

def clear():
    os.system("clear" if os.name != "nt" else "cls")

def safe_input(prompt=""):
    try:
        return input(prompt)
    except KeyboardInterrupt:
        print()
        sys.exit(0)

def termux_open_url(url: str) -> bool:
    """Try to open URL using termux-open-url, else webbrowser fallback."""
    try:
        if os.system("which termux-open-url >/dev/null 2>&1") == 0:
            os.system(f"termux-open-url '{url}' &")
            return True
    except Exception:
        pass
    try:
        import webbrowser
        webbrowser.open(url)
        return True
    except Exception:
        return False

def short(title):
    print(Fore.YELLOW + "="*60 + Style.RESET_ALL)
    print(Fore.CYAN + title + Style.RESET_ALL)
    print(Fore.YELLOW + "-"*60 + Style.RESET_ALL)

def maybe_install_notice(name):
    print(Fore.YELLOW + f"[i]Note: missing optional module: {name}. Some features limited.[/i]" + Style.RESET_ALL)

# --------- Lock screen + redirect ----------
def lock_and_redirect(countdown=10):
    clear()
    print(Fore.RED + "╔" + "═"*58 + "╗" + Style.RESET_ALL)
    print(Fore.RED + "║" + Style.RESET_ALL + "   " + Fore.GREEN + "HCO-OSINT (Termux Pro) — By Azhar | Hackers Colony" + Style.RESET_ALL)
    print(Fore.RED + "╚" + "═"*58 + "╝" + Style.RESET_ALL)
    print()
    print(Fore.YELLOW + "⚠️  This tool is locked. Subscribe to Hackers Colony Tech and click the bell to unlock." + Style.RESET_ALL)
    for i in range(countdown,0,-1):
        print(Fore.MAGENTA + f"\rRedirecting to YouTube in: {i} seconds...  " + Style.RESET_ALL, end="", flush=True)
        time.sleep(1)
    print()
    print(Fore.GREEN + "Opening YouTube channel now..." + Style.RESET_ALL)
    opened = termux_open_url(YOUTUBE_URL)
    if not opened:
        print(Fore.YELLOW + "[!] Could not open with termux-open-url; fallback to browser attempted." + Style.RESET_ALL)
    print(Fore.CYAN + "After subscribing, return here and press Enter to continue." + Style.RESET_ALL)
    safe_input("Press Enter when you return...")

# --------- Basic helpers for lookups ----------
def run_whois_cmd(target):
    """Use system 'whois' command if available. Returns raw output or None."""
    if os.system("which whois >/dev/null 2>&1") != 0:
        return None
    try:
        out = subprocess.check_output(["whois", target], stderr=subprocess.DEVNULL, timeout=12, universal_newlines=True)
        return out
    except Exception:
        return None

def parse_whois_text(text, keys=("Registrar","Creation Date","Registry Expiry Date","Name Server","OrgName","NetName","NetRange","OrgAbuseEmail")):
    info = {}
    if not text:
        return info
    for line in text.splitlines():
        line = line.strip()
        for k in keys:
            if line.lower().startswith(k.lower()):
                val = line.split(":",1)[1].strip() if ":" in line else ""
                info[k] = info.get(k, []) + [val]
    return info

# --------- FEATURES ----------

# 1) URL scan: basic HEAD/GET, title, meta (if requests+bs4)
def url_scan():
    short("URL Scan")
    url = safe_input("Enter URL (include http(s)://) >>> ").strip()
    if not url:
        print(Fore.RED + "Empty URL" + Style.RESET_ALL)
        return None
    if requests is None:
        print(Fore.YELLOW + "requests not installed - cannot perform HTTP scans. Install: pip install requests" + Style.RESET_ALL)
        return None
    try:
        r = requests.head(url, allow_redirects=True, timeout=8, headers={"User-Agent":"HCO-OSINT"})
    except Exception:
        try:
            r = requests.get(url, timeout=10, headers={"User-Agent":"HCO-OSINT"})
        except Exception as e:
            print(Fore.RED + f"HTTP request failed: {e}" + Style.RESET_ALL)
            return None
    final = getattr(r, "url", url)
    status = getattr(r, "status_code", "")
    headers = getattr(r, "headers", {}) or {}
    title = "-"
    meta_desc = "-"
    if requests and r is not None and getattr(r, "text", None):
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, "lxml")
            if soup.title: title = soup.title.string.strip()
            meta = soup.find("meta", attrs={"name":"description"}) or soup.find("meta", attrs={"property":"og:description"})
            if meta and meta.get("content"): meta_desc = meta.get("content").strip()
        except Exception:
            pass
    print(Fore.CYAN + f"Status: {status}" + Style.RESET_ALL)
    print(Fore.CYAN + f"Final URL: {final}" + Style.RESET_ALL)
    print(Fore.CYAN + f"Server Header: {headers.get('Server','-')}" + Style.RESET_ALL)
    print(Fore.CYAN + f"Content-Type: {headers.get('Content-Type','-')}" + Style.RESET_ALL)
    print(Fore.GREEN + f"Title: {title}" + Style.RESET_ALL)
    if meta_desc:
        print(Fore.GREEN + f"Meta: {meta_desc[:200]}{'...' if len(meta_desc)>200 else ''}" + Style.RESET_ALL)
    # SSL cert expiry if https
    parsed = urlparse(final)
    if parsed.scheme == "https":
        try:
            host = parsed.hostname
            ctx = ssl.create_default_context()
            with socket.create_connection((host,443), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get("notAfter")
                    print(Fore.YELLOW + f"SSL Expires: {not_after}" + Style.RESET_ALL)
        except Exception:
            print(Fore.YELLOW + "SSL check failed or not available" + Style.RESET_ALL)
    print()
    return {"type":"url","url":url,"status":status,"final":final,"title":title}

# 2) Domain WHOIS + DNS
def domain_lookup():
    short("Domain WHOIS & DNS")
    domain = safe_input("Enter domain (example.com) >>> ").strip()
    if not domain:
        print(Fore.RED + "Empty domain" + Style.RESET_ALL); return None
    # WHOIS via python-whois or system whois
    whois_data = {}
    if pywhois:
        try:
            w = pywhois.whois(domain)
            whois_data = dict(w)  # may be messy
        except Exception:
            whois_data = {}
    else:
        text = run_whois_cmd(domain)
        parsed = parse_whois_text(text)
        whois_data = parsed or {}
        if not text:
            maybe_install_notice("python-whois or system whois")
    print(Fore.GREEN + "WHOIS (sample):" + Style.RESET_ALL)
    for k,v in list(whois_data.items())[:8]:
        print(Fore.CYAN + f"{k}: {v}" + Style.RESET_ALL)
    # DNS records via dnspython if available
    if dnsresolver:
        for rr in ("A","AAAA","MX","NS","TXT"):
            try:
                answers = dnsresolver.resolve(domain, rr, lifetime=5)
                vals = []
                for r in answers:
                    s = str(r).strip()
                    if rr in ("MX","NS") and s.endswith("."): s = s[:-1]
                    vals.append(s)
                print(Fore.YELLOW + f"{rr} records: {', '.join(vals)}" + Style.RESET_ALL)
            except Exception:
                print(Fore.YELLOW + f"{rr} lookup failed or none" + Style.RESET_ALL)
    else:
        maybe_install_notice("dnspython")
    # HTTP title if possible
    if requests:
        try:
            resp = requests.get("https://"+domain, timeout=6, headers={"User-Agent":"HCO-OSINT"})
        except Exception:
            try:
                resp = requests.get("http://"+domain, timeout=6, headers={"User-Agent":"HCO-OSINT"})
            except Exception:
                resp = None
        if resp and getattr(resp,"text",None):
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "lxml")
                title = soup.title.string.strip() if soup.title else "-"
                print(Fore.GREEN + f"Site title: {title}" + Style.RESET_ALL)
            except Exception:
                pass
    return {"type":"domain","domain":domain,"whois":whois_data}

# 3) Email info (syntax, domain MX & gravatar)
def email_info():
    short("Email Analysis")
    email = safe_input("Enter email >>> ").strip()
    if not email:
        print(Fore.RED + "Empty" + Style.RESET_ALL); return None
    valid = re.match(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", email) is not None
    print(Fore.CYAN + f"Syntax valid: {valid}" + Style.RESET_ALL)
    if not valid:
        return {"email":email,"valid":False}
    domain = email.split("@",1)[1].lower()
    print(Fore.CYAN + f"Domain: {domain}" + Style.RESET_ALL)
    print(Fore.CYAN + f"Disposable: {domain in DISPOSABLE_DOMAINS}" + Style.RESET_ALL)
    # MX lookup
    if dnsresolver:
        try:
            ans = dnsresolver.resolve(domain, "MX", lifetime=6)
            mxs = sorted([str(a.exchange).rstrip('.') for a in ans])
            print(Fore.YELLOW + f"MX: {', '.join(mxs)}" + Style.RESET_ALL)
        except Exception:
            print(Fore.YELLOW + "MX lookup failed" + Style.RESET_ALL)
    else:
        maybe_install_notice("dnspython")
    # Gravatar quick check (no API)
    import hashlib as _h
    h = _h.md5(email.strip().lower().encode()).hexdigest()
    if requests:
        try:
            r = requests.head(f"https://www.gravatar.com/avatar/{h}?d=404", timeout=6)
            exists = (getattr(r,"status_code",None) == 200)
            print(Fore.GREEN + f"Gravatar exists: {exists}" + Style.RESET_ALL)
        except Exception:
            print(Fore.YELLOW + "Gravatar check failed" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "requests missing — skipping gravatar check" + Style.RESET_ALL)
    return {"type":"email","email":email,"domain":domain}

# 4) Phone analysis (phonenumbers)
def phone_info():
    short("Phone Number Analysis")
    num = safe_input("Enter number with country code (eg +911234567890) >>> ").strip()
    if not num:
        print(Fore.RED + "Empty" + Style.RESET_ALL); return None
    if not phonenumbers:
        maybe_install_notice("phonenumbers")
        return {"phone":num,"installed":False}
    try:
        p = phonenumbers.parse(num, None)
        valid = phonenumbers.is_valid_number(p)
        poss = phonenumbers.is_possible_number(p)
        ctry = geocoder.country_name_for_number(p, "en") if geocoder else "-"
        reg = geocoder.description_for_number(p, "en") if geocoder else "-"
        car = carrier.name_for_number(p, "en") if carrier else "-"
        e164 = phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164)
        print(Fore.CYAN + f"Valid: {valid}  Possible: {poss}" + Style.RESET_ALL)
        print(Fore.CYAN + f"Country: {ctry}  Region: {reg}  Carrier: {car}" + Style.RESET_ALL)
        print(Fore.CYAN + f"E164: {e164}" + Style.RESET_ALL)
        return {"type":"phone","phone":num,"valid":valid,"carrier":car,"country":ctry,"region":reg}
    except Exception as e:
        print(Fore.RED + f"Phone parse error: {e}" + Style.RESET_ALL)
        return {"phone":num,"error":str(e)}

# 5) Username footprint (multi-threaded HEAD requests)
def username_footprint():
    short("Username Footprint")
    username = safe_input("Enter username (no @) >>> ").strip()
    if not username:
        print(Fore.RED + "Empty" + Style.RESET_ALL); return None
    if requests is None:
        print(Fore.YELLOW + "requests not installed — cannot perform site checks" + Style.RESET_ALL)
        return None
    results = []
    threads = []
    lock = threading.Lock()
    def worker(site, pattern):
        url = pattern.format(u=username)
        try:
            r = requests.head(url, timeout=6, allow_redirects=True, headers={"User-Agent":"HCO-OSINT"})
            exists = getattr(r,"status_code",None) in (200,301,302,307,308)
            final = getattr(r,"url",url)
        except Exception:
            exists = False
            final = url
        with lock:
            results.append({"site":site,"url":url,"exists":exists,"final":final})
    for site,pattern in USERNAME_SITES.items():
        t = threading.Thread(target=worker, args=(site,pattern))
        threads.append(t); t.start()
    for t in threads: t.join(timeout=10)
    # print results
    for r in sorted(results, key=lambda x: x["exists"], reverse=True):
        status = Fore.GREEN + "Found" + Style.RESET_ALL if r["exists"] else Fore.RED + "Not Found" + Style.RESET_ALL
        print(f"{Fore.CYAN}{r['site']:<15}{Style.RESET_ALL} {status}  {r['final']}")
    return {"type":"username","username":username,"results":results}

# 6) IP lookup (system whois & reverse DNS) — avoids paid API
def ip_lookup():
    short("IP Lookup (system whois & reverse DNS)")
    ip = safe_input("Enter IP (leave empty to lookup your public IP) >>> ").strip()
    if not ip:
        # try public IP via simple socket to CONNECT to 1.1.1.1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("1.1.1.1",80))
            local_ip = s.getsockname()[0]
            s.close()
            ip = local_ip
            print(Fore.CYAN + f"Using your device IP: {ip}" + Style.RESET_ALL)
        except Exception:
            print(Fore.YELLOW + "Could not determine your IP automatically. Enter manually." + Style.RESET_ALL)
            ip = safe_input("IP >>> ").strip()
            if not ip:
                return None
    # reverse DNS
    try:
        rdns = socket.gethostbyaddr(ip)[0]
    except Exception:
        rdns = "-"
    print(Fore.CYAN + f"Reverse DNS: {rdns}" + Style.RESET_ALL)
    # system whois if available
    text = run_whois_cmd(ip)
    if text:
        parsed = parse_whois_text(text, keys=("OrgName","NetName","NetRange","OrgAbuseEmail","OriginAS","descr"))
        print(Fore.GREEN + "Whois (summary):" + Style.RESET_ALL)
        for k,v in parsed.items():
            print(Fore.YELLOW + f"{k}: {v}" + Style.RESET_ALL)
    else:
        maybe_install_notice("system whois")
    return {"type":"ip","ip":ip,"rdns":rdns}

# 7) Image EXIF (local file) — Pillow preferred, else exifread
def image_exif():
    short("Image EXIF")
    path = safe_input("Enter local image path (eg /sdcard/DCIM/Camera/img.jpg) >>> ").strip()
    if not path or not os.path.isfile(path):
        print(Fore.RED + "File not found" + Style.RESET_ALL); return None
    data = {}
    if Image:
        try:
            img = Image.open(path)
            info = img._getexif() or {}
            for tag, value in info.items():
                name = TAGS.get(tag, tag)
                data[name] = value
            print(Fore.GREEN + f"Read {len(data)} EXIF tags (Pillow)" + Style.RESET_ALL)
            for k,v in list(data.items())[:30]:
                print(Fore.CYAN + f"{k}: {v}" + Style.RESET_ALL)
            return {"type":"exif","path":path,"tags":data}
        except Exception as e:
            print(Fore.YELLOW + f"Pillow EXIF failed: {e}" + Style.RESET_ALL)
    if exifread:
        try:
            with open(path, "rb") as f:
                tags = exifread.process_file(f, details=False)
            print(Fore.GREEN + f"Read {len(tags)} EXIF tags (exifread)" + Style.RESET_ALL)
            for k,v in list(tags.items())[:30]:
                print(Fore.CYAN + f"{k}: {v}" + Style.RESET_ALL)
            return {"type":"exif","path":path,"tags":{k:str(v) for k,v in tags.items()}}
        except Exception as e:
            print(Fore.YELLOW + f"exifread failed: {e}" + Style.RESET_ALL)
    print(Fore.RED + "No EXIF reader available. Install pillow or exifread." + Style.RESET_ALL)
    return None

# 8) File hashing
def file_hash():
    short("File Hash (MD5, SHA1, SHA256)")
    path = safe_input("Enter local file path >>> ").strip()
    if not path or not os.path.isfile(path):
        print(Fore.RED + "File not found" + Style.RESET_ALL); return None
    h_md5 = hashlib.md5(); h_sha1 = hashlib.sha1(); h_sha256 = hashlib.sha256()
    with open(path,"rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk: break
            h_md5.update(chunk); h_sha1.update(chunk); h_sha256.update(chunk)
    print(Fore.CYAN + f"MD5: {h_md5.hexdigest()}" + Style.RESET_ALL)
    print(Fore.CYAN + f"SHA1: {h_sha1.hexdigest()}" + Style.RESET_ALL)
    print(Fore.CYAN + f"SHA256: {h_sha256.hexdigest()}" + Style.RESET_ALL)
    return {"type":"hash","file":path,"md5":h_md5.hexdigest(),"sha1":h_sha1.hexdigest(),"sha256":h_sha256.hexdigest()}

# 9) Password audit (heuristic)
def password_audit():
    short("Password Strength Audit")
    pwd = safe_input("Enter password (will echo) >>> ")
    if not pwd:
        print(Fore.RED + "Empty" + Style.RESET_ALL); return None
    length = len(pwd)
    classes = sum([
        any(c.islower() for c in pwd),
        any(c.isupper() for c in pwd),
        any(c.isdigit() for c in pwd),
        any(c in "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~" for c in pwd)
    ])
    score = length + classes*2
    verdict = "Very Weak"
    if score >= 20: verdict = "Very Strong"
    elif score >= 16: verdict = "Strong"
    elif score >= 12: verdict = "Fair"
    elif score >= 8: verdict = "Weak"
    print(Fore.GREEN + f"Verdict: {verdict}" + Style.RESET_ALL)
    print(Fore.CYAN + f"Length: {length}  Classes: {classes}  Score: {score}" + Style.RESET_ALL)
    return {"type":"password","verdict":verdict,"length":length,"classes":classes}

# 10) Save last result
def save_result(data):
    if not data:
        print(Fore.YELLOW + "No recent result to save" + Style.RESET_ALL); return
    fname = f"hco-osint-result-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
    try:
        with open(fname,"w") as f:
            json.dump(data, f, indent=2, default=str)
        print(Fore.GREEN + f"Saved: {fname}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Save failed: {e}" + Style.RESET_ALL)

# --------- Main Menu ----------
def menu():
    last = None
    while True:
        clear()
        print(Fore.RED + "╔" + "═"*58 + "╗" + Style.RESET_ALL)
        print(Fore.RED + "║" + Style.RESET_ALL + "   " + Fore.GREEN + "HCO-OSINT (Termux Pro) — By Azhar | Hackers Colony" + Style.RESET_ALL)
        print(Fore.RED + "╚" + "═"*58 + "╝" + Style.RESET_ALL)
        print()
        print(Fore.MAGENTA + "[1]" + Style.RESET_ALL + " URL scan")
        print(Fore.MAGENTA + "[2]" + Style.RESET_ALL + " Domain WHOIS & DNS")
        print(Fore.MAGENTA + "[3]" + Style.RESET_ALL + " Email analysis")
        print(Fore.MAGENTA + "[4]" + Style.RESET_ALL + " Username footprint")
        print(Fore.MAGENTA + "[5]" + Style.RESET_ALL + " IP lookup (whois & reverse DNS)")
        print(Fore.MAGENTA + "[6]" + Style.RESET_ALL + " Image EXIF (local)")
        print(Fore.MAGENTA + "[7]" + Style.RESET_ALL + " File hash")
        print(Fore.MAGENTA + "[8]" + Style.RESET_ALL + " Password audit")
        print(Fore.MAGENTA + "[9]" + Style.RESET_ALL + " Save last result to file")
        print(Fore.MAGENTA + "[0]" + Style.RESET_ALL + " Exit")
        choice = safe_input("Choice >>> ").strip()
        try:
            if choice == "1":
                last = url_scan()
            elif choice == "2":
                last = domain_lookup()
            elif choice == "3":
                last = email_info()
            elif choice == "4":
                last = username_footprint()
            elif choice == "5":
                last = ip_lookup()
            elif choice == "6":
                last = image_exif()
            elif choice == "7":
                last = file_hash()
            elif choice == "8":
                last = password_audit()
            elif choice == "9":
                save_result(last)
            elif choice == "0":
                print(Fore.GREEN + "Goodbye!" + Style.RESET_ALL); break
            else:
                print(Fore.YELLOW + "Invalid choice" + Style.RESET_ALL)
            safe_input("\nPress Enter to return to menu...")
        except KeyboardInterrupt:
            print(); break
        except Exception as e:
            print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
            log("menu_error: " + traceback.format_exc())
            safe_input("Press Enter to continue...")

# --------- Entry Point ----------
def main():
    clear()
    print(Fore.MAGENTA + "HCO-OSINT (Termux Pro) — By Azhar | Hackers Colony" + Style.RESET_ALL)
    print(Fore.YELLOW + "Use only with authorization and for educational purposes." + Style.RESET_ALL)
    safe_input("Press Enter to continue to lock screen...")
    lock_and_redirect(10)
    menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + Fore.RED + "Interrupted." + Style.RESET_ALL)
