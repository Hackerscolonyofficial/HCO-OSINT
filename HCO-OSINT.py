#!/usr/bin/env python3
"""
HCO-OSINT.py — Termux Pro (Single file)
By Azhar | Hackers Colony

Features (no paid APIs required):
- Lock screen with real YouTube redirect (tries am start -> termux-open-url -> xdg-open)
- Banner: RED text inside BLUE background (clean, bold)
- Single menu with pro OSINT tools shown live in Termux (no saving)
  IP info (reverse DNS, whois), Domain WHOIS/DNS, Port scan, Extract links,
  Username footprint (multi-site), Google dorks helper, Phone info (phonenumbers),
  Email checks (syntax, MX), Image EXIF (Pillow/exifread), File hashing, Password audit.
- Uses requests/dnspython/python-whois/phonenumbers/Pillow when available; fallbacks otherwise.
"""

import os, sys, time, socket, ssl, hashlib, threading, subprocess, traceback
from datetime import datetime
from urllib.parse import urlparse

# Optional libs (graceful fallback)
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
    from PIL.ExifTags import TAGS
except Exception:
    Image = None

try:
    import exifread
except Exception:
    exifread = None

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

# Color output (required)
try:
    from colorama import init as colorama_init, Fore, Back, Style
    colorama_init(autoreset=True)
except Exception:
    # Minimal fallback (no color)
    class _C:
        def __getattr__(self, name): return ""
    Fore = Back = Style = _C()

# CONFIG
YOUTUBE = "https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya"
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
    "Medium": "https://medium.com/@{u}"
}

# Utility helpers
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

def try_open_url(url: str):
    """
    Try to open url in Android YouTube app or default browser.
    Priority:
      1) am start (Android intent)
      2) termux-open-url (termux-api)
      3) xdg-open (desktop fallback)
      4) webbrowser fallback
    """
    # 1) am start (Android intent) - works on most Android devices
    try:
        os.system(f"am start -a android.intent.action.VIEW -d '{url}' >/dev/null 2>&1")
        return True
    except Exception:
        pass
    # 2) termux-open-url
    try:
        if os.system("which termux-open-url >/dev/null 2>&1") == 0:
            os.system(f"termux-open-url '{url}' >/dev/null 2>&1 &")
            return True
    except Exception:
        pass
    # 3) xdg-open
    try:
        if os.system("which xdg-open >/dev/null 2>&1") == 0:
            os.system(f"xdg-open '{url}' >/dev/null 2>&1 &")
            return True
    except Exception:
        pass
    # 4) python webbrowser
    try:
        import webbrowser
        webbrowser.open(url)
        return True
    except Exception:
        return False

def maybe_notice(name):
    print(Fore.YELLOW + f"[!] Optional module missing: {name} — feature may be limited." + Style.RESET_ALL)

# LOCK + REDIRECT
def lock_and_redirect(countdown=8):
    clear()
    # Banner area before unlock (simple, no ASCII)
    print(Back.BLUE + Fore.RED + Style.BRIGHT + " HCO OSINT TOOL BY AZHAR " + Style.RESET_ALL)
    print()
    print(Fore.YELLOW + "This tool is locked. Subscribe to Hackers Colony Tech and click the bell to unlock." + Style.RESET_ALL)
    print(Fore.MAGENTA + f"Redirecting to YouTube in {countdown} seconds..." + Style.RESET_ALL)
    for i in range(countdown, 0, -1):
        print(Fore.CYAN + f"  Redirect in {i} seconds...", end="\r")
        time.sleep(1)
    print()
    opened = try_open_url(YOUTUBE)
    if not opened:
        print(Fore.RED + "[!] Could not open YouTube automatically. Open this link manually:" + Style.RESET_ALL)
        print(Fore.YELLOW + YOUTUBE + Style.RESET_ALL)
    safe_input(Fore.GREEN + "\nPress ENTER after subscribing to continue..." + Style.RESET_ALL)
    clear()

# -------------------------
# OSINT Feature Implementations
# -------------------------

# 1) IP info (reverse DNS + system whois + optional HTTP geolocation if requests available)
def ip_info():
    short = lambda t: print(Fore.CYAN + f"\n-- {t} --" + Style.RESET_ALL)
    ip_or_host = safe_input(Fore.CYAN + "\nEnter IP or hostname: " + Style.RESET_ALL).strip()
    if not ip_or_host:
        print(Fore.YELLOW + "No input." + Style.RESET_ALL); return None
    # Resolve hostname -> IP if needed
    target_ip = ip_or_host
    try:
        if not re_match_ip(ip_or_host):
            target_ip = socket.gethostbyname(ip_or_host)
    except Exception:
        pass
    short("Network info")
    print(Fore.GREEN + f"Target: {ip_or_host}" + Style.RESET_ALL)
    print(Fore.GREEN + f"Resolved IP: {target_ip}" + Style.RESET_ALL)
    # Reverse DNS
    try:
        rdns = socket.gethostbyaddr(target_ip)[0]
        print(Fore.GREEN + f"Reverse DNS: {rdns}" + Style.RESET_ALL)
    except Exception:
        print(Fore.YELLOW + "Reverse DNS: N/A" + Style.RESET_ALL)
    # system whois
    whois_out = run_system_whois(target_ip)
    if whois_out:
        short("System whois (summary)")
        for k, v in list(whois_out.items())[:10]:
            print(Fore.YELLOW + f"{k}: {v}" + Style.RESET_ALL)
    else:
        maybe_notice("system whois/python-whois")
    # Optional: try free HTTP geolocation (if requests present)
    if requests:
        try:
            # use simple non-key endpoint (if allowed). If not desired, this step can be skipped.
            resp = requests.get(f"http://ip-api.com/json/{target_ip}", timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    print(Fore.CYAN + "\nGeo info (ip-api):" + Style.RESET_ALL)
                    print(Fore.GREEN + f"Country: {data.get('country')}  Region: {data.get('regionName')}  City: {data.get('city')}" + Style.RESET_ALL)
                    lat, lon = data.get("lat"), data.get("lon")
                    if lat and lon:
                        print(Fore.YELLOW + f"Map: https://www.google.com/maps?q={lat},{lon}" + Style.RESET_ALL)
        except Exception:
            pass
    return {"target": ip_or_host, "ip": target_ip}

# Helper: basic IP regex
def re_match_ip(s: str):
    import re
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s) is not None

# run system whois or python-whois fallback
def run_system_whois(target):
    # prefer python-whois if installed (structured)
    if pywhois:
        try:
            w = pywhois.whois(target)
            return dict(w)
        except Exception:
            pass
    # else system whois
    if os.system("which whois >/dev/null 2>&1") == 0:
        try:
            out = subprocess.check_output(["whois", target], universal_newlines=True, stderr=subprocess.DEVNULL, timeout=10)
            return parse_whois_text(out)
        except Exception:
            return None
    return None

def parse_whois_text(text):
    info = {}
    try:
        for line in text.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip()
                if k and v:
                    info.setdefault(k, []).append(v)
    except Exception:
        pass
    return info

# 2) Domain WHOIS + DNS + HTTP title
def domain_info():
    short = lambda t: print(Fore.CYAN + f"\n-- {t} --" + Style.RESET_ALL)
    domain = safe_input(Fore.CYAN + "\nEnter domain (example.com): " + Style.RESET_ALL).strip()
    if not domain:
        print(Fore.YELLOW + "No domain." + Style.RESET_ALL); return None
    short("WHOIS")
    who = run_system_whois(domain)
    if who:
        for k, v in list(who.items())[:12]:
            print(Fore.YELLOW + f"{k}: {v}" + Style.RESET_ALL)
    else:
        maybe_notice("whois")
    short("DNS records")
    if dnsresolver:
        for rr in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                ans = dnsresolver.resolve(domain, rr, lifetime=5)
                vals = [str(r).rstrip('.') for r in ans]
                print(Fore.GREEN + f"{rr}: {', '.join(vals)}" + Style.RESET_ALL)
            except Exception:
                print(Fore.YELLOW + f"{rr}: none or lookup failed" + Style.RESET_ALL)
    else:
        maybe_notice("dnspython")
    # HTTP Title
    if requests:
        for proto in ("https://", "http://"):
            try:
                r = requests.get(proto + domain, headers={"User-Agent":"HCO-OSINT"}, timeout=6)
                if r and r.status_code < 400:
                    if BeautifulSoup:
                        try:
                            soup = BeautifulSoup(r.text, "lxml")
                            title = soup.title.string.strip() if soup.title else "-"
                            print(Fore.CYAN + f"Site title: {title}" + Style.RESET_ALL)
                        except Exception:
                            pass
                    break
            except Exception:
                continue
    return {"domain": domain}

# 3) Port scan (small, polite)
def port_scan():
    host = safe_input(Fore.CYAN + "\nEnter host (IP/domain): " + Style.RESET_ALL).strip()
    if not host:
        print(Fore.YELLOW + "No host." + Style.RESET_ALL); return None
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        print(Fore.RED + "Resolve failed." + Style.RESET_ALL); return None
    common_ports = [21,22,23,25,53,80,110,143,443,3306,3389,8080,8443]
    print(Fore.GREEN + f"Scanning {host} ({ip}) - {len(common_ports)} common ports (fast scan)" + Style.RESET_ALL)
    open_ports = []
    for p in common_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.6)
            res = s.connect_ex((ip, p))
            s.close()
            if res == 0:
                print(Fore.GREEN + f"[OPEN] {p}" + Style.RESET_ALL)
                open_ports.append(p)
            else:
                print(Fore.YELLOW + f"[closed] {p}" + Style.RESET_ALL, end="\r")
        except Exception:
            pass
    if not open_ports:
        print(Fore.CYAN + "\nNo common open ports found (or filtered)." + Style.RESET_ALL)
    return {"host": host, "ip": ip, "open_ports": open_ports}

# 4) Extract links from webpage
def extract_links():
    url = safe_input(Fore.CYAN + "\nEnter URL (include http:// or https://): " + Style.RESET_ALL).strip()
    if not url:
        print(Fore.YELLOW + "No URL." + Style.RESET_ALL); return None
    if requests is None or BeautifulSoup is None:
        maybe_notice("requests/bs4")
        return None
    try:
        r = requests.get(url, headers={"User-Agent":"HCO-OSINT"}, timeout=8)
        soup = BeautifulSoup(r.text, "lxml")
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith("javascript:") or href.startswith("#"): continue
            links.append(href)
        print(Fore.GREEN + f"Found {len(links)} links:" + Style.RESET_ALL)
        for l in links:
            print(Fore.YELLOW + l + Style.RESET_ALL)
        return {"url": url, "links": links}
    except Exception as e:
        print(Fore.RED + f"Failed to fetch page: {e}" + Style.RESET_ALL)
        log("extract_links_error: " + traceback.format_exc())
        return None

# 5) Username footprint (multi-threaded HEAD checks)
def username_footprint():
    name = safe_input(Fore.CYAN + "\nEnter username/handle (no @): " + Style.RESET_ALL).strip()
    if not name:
        print(Fore.YELLOW + "No username." + Style.RESET_ALL); return None
    if requests is None:
        maybe_notice("requests")
        return None
    print(Fore.GREEN + f"Checking username across {len(USERNAME_SITES)} sites..." + Style.RESET_ALL)
    results = []
    lock = threading.Lock()
    def worker(site, pattern):
        url = pattern.format(u=name)
        try:
            r = requests.head(url, allow_redirects=True, timeout=6, headers={"User-Agent":"HCO-OSINT"})
            status = getattr(r, "status_code", None)
            exists = status in (200,301,302,307,308)
            final = getattr(r, "url", url)
        except Exception:
            exists = False; final = url; status = None
        with lock:
            results.append((site, final, exists, status))
    threads = []
    for site, pattern in USERNAME_SITES.items():
        t = threading.Thread(target=worker, args=(site, pattern))
        t.start(); threads.append(t)
    for t in threads: t.join(timeout=8)
    # Display results
    for site, final, exists, status in sorted(results, key=lambda x: x[2], reverse=True):
        tag = Fore.GREEN + "FOUND" + Style.RESET_ALL if exists else Fore.RED + "NOT" + Style.RESET_ALL
        print(Fore.CYAN + f"{site:12}" + Style.RESET_ALL + f" {tag}  {Fore.YELLOW}{final}{Style.RESET_ALL}  {Fore.MAGENTA}{status}{Style.RESET_ALL}")
    return {"username": name, "results": results}

# 6) Google dorks helper
def google_dorks():
    target = safe_input(Fore.CYAN + "\nEnter target domain/keyword: " + Style.RESET_ALL).strip()
    if not target:
        print(Fore.YELLOW + "No target." + Style.RESET_ALL); return None
    dorks = [
        f"site:{target} filetype:pdf",
        f"site:{target} inurl:login",
        f"site:{target} intitle:index.of",
        f"site:{target} (password|passwd|credential)",
        f"site:{target} ext:sql OR ext:db OR ext:bak OR ext:log"
    ]
    print(Fore.GREEN + "Google dorks (open in browser to use):" + Style.RESET_ALL)
    for d in dorks:
        print(Fore.YELLOW + f"https://www.google.com/search?q={d}" + Style.RESET_ALL)
    return {"target": target, "dorks": dorks}

# 7) Phone lookup (phonenumbers)
def phone_lookup():
    num = safe_input(Fore.CYAN + "\nEnter phone number with country code (e.g. +14155552671): " + Style.RESET_ALL).strip()
    if not num:
        print(Fore.YELLOW + "No number." + Style.RESET_ALL); return None
    if phonenumbers is None:
        maybe_notice("phonenumbers")
        return None
    try:
        p = phonenumbers.parse(num, None)
        valid = phonenumbers.is_valid_number(p)
        possible = phonenumbers.is_possible_number(p)
        region = geocoder.description_for_number(p, "en") if geocoder else "-"
        carr = carrier.name_for_number(p, "en") if carrier else "-"
        tz = ptimezone.time_zones_for_number(p) if ptimezone else []
        print(Fore.GREEN + f"Valid: {valid}  Possible: {possible}" + Style.RESET_ALL)
        print(Fore.CYAN + f"Region: {region}" + Style.RESET_ALL)
        print(Fore.CYAN + f"Carrier: {carr}" + Style.RESET_ALL)
        print(Fore.CYAN + f"Timezones: {tz}" + Style.RESET_ALL)
        print(Fore.YELLOW + f"Search links: https://www.google.com/search?q={num}" + Style.RESET_ALL)
        print(Fore.YELLOW + f"Truecaller: https://www.truecaller.com/search/global/{num}" + Style.RESET_ALL)
        return {"phone": num, "valid": valid, "region": region, "carrier": carr}
    except Exception as e:
        print(Fore.RED + f"Phone parse failed: {e}" + Style.RESET_ALL)
        return None

# 8) Email checks (syntax + MX + domain whois)
def email_lookup():
    email = safe_input(Fore.CYAN + "\nEnter email address: " + Style.RESET_ALL).strip()
    if not email:
        print(Fore.YELLOW + "No email." + Style.RESET_ALL); return None
    # basic syntax
    import re
    valid = re.match(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", email) is not None
    print(Fore.GREEN + f"Syntax valid: {valid}" + Style.RESET_ALL)
    domain = email.split("@")[-1] if "@" in email else ""
    if domain:
        print(Fore.CYAN + f"Domain: {domain}" + Style.RESET_ALL)
        if dnsresolver:
            try:
                ans = dnsresolver.resolve(domain, "MX", lifetime=6)
                mxs = [str(r.exchange).rstrip('.') for r in ans]
                print(Fore.GREEN + "MX: " + Fore.YELLOW + ", ".join(mxs) + Style.RESET_ALL)
            except Exception:
                print(Fore.YELLOW + "MX lookup failed or none." + Style.RESET_ALL)
        else:
            maybe_notice("dnspython")
        # domain whois
        w = run_system_whois(domain)
        if w:
            print(Fore.CYAN + "\nDomain WHOIS (summary):" + Style.RESET_ALL)
            for k,v in list(w.items())[:8]:
                print(Fore.YELLOW + f"{k}: {v}" + Style.RESET_ALL)
    # quick OSINT links
    print(Fore.YELLOW + f"HIBP (manual): https://haveibeenpwned.com/account/{email}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"Google: https://www.google.com/search?q={email}" + Style.RESET_ALL)
    return {"email": email, "syntax_valid": valid}

# 9) Image EXIF (Pillow preferred, fallback to exifread)
def image_exif():
    path = safe_input(Fore.CYAN + "\nEnter local image path: " + Style.RESET_ALL).strip()
    if not path or not os.path.isfile(path):
        print(Fore.RED + "File not found." + Style.RESET_ALL); return None
    data = {}
    if Image:
        try:
            img = Image.open(path)
            info = img._getexif() or {}
            for tag, val in info.items():
                name = TAGS.get(tag, str(tag))
                data[name] = val
            print(Fore.GREEN + f"EXIF tags: {len(data)}" + Style.RESET_ALL)
            for k,v in list(data.items())[:30]:
                print(Fore.YELLOW + f"{k}: {v}" + Style.RESET_ALL)
            return {"path": path, "exif": data}
        except Exception:
            pass
    if exifread:
        try:
            with open(path, "rb") as f:
                tags = exifread.process_file(f, details=False)
            print(Fore.GREEN + f"EXIF tags: {len(tags)}" + Style.RESET_ALL)
            for k,v in list(tags.items())[:30]:
                print(Fore.YELLOW + f"{k}: {v}" + Style.RESET_ALL)
            return {"path": path, "exif": {k:str(v) for k,v in tags.items()}}
        except Exception:
            pass
    maybe_notice("Pillow/exifread")
    return None

# 10) File hash (md5/sha1/sha256)
def file_hash():
    path = safe_input(Fore.CYAN + "\nEnter file path: " + Style.RESET_ALL).strip()
    if not path or not os.path.isfile(path):
        print(Fore.RED + "File not found." + Style.RESET_ALL); return None
    h_md5 = hashlib.md5(); h_sha1 = hashlib.sha1(); h_sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk: break
            h_md5.update(chunk); h_sha1.update(chunk); h_sha256.update(chunk)
    print(Fore.GREEN + f"MD5: {h_md5.hexdigest()}" + Style.RESET_ALL)
    print(Fore.GREEN + f"SHA1: {h_sha1.hexdigest()}" + Style.RESET_ALL)
    print(Fore.GREEN + f"SHA256: {h_sha256.hexdigest()}" + Style.RESET_ALL)
    return {"file": path, "md5": h_md5.hexdigest()}

# 11) Password audit (heuristic)
def password_audit():
    pwd = safe_input(Fore.CYAN + "\nEnter password to evaluate (will echo): " + Style.RESET_ALL)
    if not pwd:
        print(Fore.YELLOW + "Empty password." + Style.RESET_ALL); return None
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
    return {"password_verdict": verdict, "score": score}

# -------------------------
# Menu
# -------------------------
def menu():
    while True:
        # Banner (red text inside blue background)
        print(Back.BLUE + Fore.RED + Style.BRIGHT + "\n HCO OSINT TOOL BY AZHAR " + Style.RESET_ALL)
        print(Fore.CYAN + "Advanced Information Gathering — results display in Termux only" + Style.RESET_ALL)
        print(Fore.YELLOW + "\nSelect an option (results shown in Termux):" + Style.RESET_ALL)
        print(Fore.MAGENTA + " 1) IP Info (reverse DNS, whois, optional geo)")
        print(" 2) Domain WHOIS & DNS")
        print(" 3) Port scan (common ports)")
        print(" 4) Extract links from website")
        print(" 5) Username footprint (many sites)")
        print(" 6) Google dorks helper")
        print(" 7) Phone number lookup (phonenumbers)")
        print(" 8) Email checks (syntax, MX, domain WHOIS)")
        print(" 9) Image EXIF (local)")
        print("10) File hashing (MD5/SHA1/SHA256)")
        print("11) Password audit (heuristic)")
        print(" 0) Exit" + Style.RESET_ALL)
        choice = safe_input(Fore.CYAN + "\nChoice >>> " + Style.RESET_ALL).strip()
        try:
            if choice == "1": ip_info()
            elif choice == "2": domain_info()
            elif choice == "3": port_scan()
            elif choice == "4": extract_links()
            elif choice == "5": username_footprint()
            elif choice == "6": google_dorks()
            elif choice == "7": phone_lookup()
            elif choice == "8": email_lookup()
            elif choice == "9": image_exif()
            elif choice == "10": file_hash()
            elif choice == "11": password_audit()
            elif choice == "0":
                print(Fore.GREEN + "\nGoodbye — stay ethical." + Style.RESET_ALL)
                break
            else:
                print(Fore.YELLOW + "Invalid choice." + Style.RESET_ALL)
        except KeyboardInterrupt:
            print(); break
        except Exception as e:
            print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
            log("menu_error: " + traceback.format_exc())
        safe_input(Fore.CYAN + "\nPress Enter to return to menu..." + Style.RESET_ALL)
        clear()

# -------------------------
# Entrypoint
# -------------------------
def main():
    try:
        lock_and_redirect(8)
        clear()
        # Once returned, show clean heading
        print(Back.BLUE + Fore.RED + Style.BRIGHT + " HCO OSINT TOOL BY AZHAR " + Style.RESET_ALL)
        print(Fore.CYAN + "An information gathering tool — By Azhar" + Style.RESET_ALL)
        print(Fore.YELLOW + "\nDisclaimer: Use for educational/authorized purposes only." + Style.RESET_ALL)
        safe_input(Fore.GREEN + "\nPress Enter to open the menu..." + Style.RESET_ALL)
        clear()
        menu()
    except KeyboardInterrupt:
        print(Fore.RED + "\nInterrupted." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
