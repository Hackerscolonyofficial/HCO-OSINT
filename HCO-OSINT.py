#!/usr/bin/env python3
# HCO-OSINT.py — Single-file advanced OSINT (no API keys required)
# By Azhar (Hackers Colony)
# Educational / lawful uses only. Keep saved reports private.

import os, sys, time, json, webbrowser, socket, re, argparse, csv, subprocess
from pathlib import Path
from datetime import datetime
import concurrent.futures

# External packages (install if missing)
try:
    import requests
    from colorama import Fore, Style, init
    import phonenumbers
    import dns.resolver
except Exception as e:
    print("Missing dependency:", e)
    print("Install: pip install requests colorama phonenumbers dnspython pillow faker")
    sys.exit(1)

# Optional packages
PIL_AVAILABLE = False
try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

FAKER_AVAILABLE = False
try:
    from faker import Faker
    FAKER_AVAILABLE = True
    fake = Faker()
except Exception:
    FAKER_AVAILABLE = False

init(autoreset=True)

# --------------- Config ---------------
YOUTUBE_URL = "https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya"
REPORTS_DIR = Path("hco_reports")
REPORTS_DIR.mkdir(exist_ok=True)
USERNAME_CSV_LAST = Path("last_username_results.csv")
HEADERS = {"User-Agent": "HCO-OSINT/1.0 (Educational)"}

# A big list of username sites (~70+ patterns). Extendable.
USERNAME_SITES = [
    ("Twitter", "https://twitter.com/{}"),
    ("Instagram", "https://www.instagram.com/{}"),
    ("GitHub", "https://github.com/{}"),
    ("Reddit", "https://www.reddit.com/user/{}"),
    ("YouTube", "https://www.youtube.com/@{}"),
    ("TikTok", "https://www.tiktok.com/@{}"),
    ("LinkedIn", "https://www.linkedin.com/in/{}"),
    ("StackOverflow", "https://stackoverflow.com/users/{}"),
    ("Pinterest", "https://www.pinterest.com/{}"),
    ("Steam", "https://steamcommunity.com/id/{}"),
    ("Twitch", "https://www.twitch.tv/{}"),
    ("Snapchat", "https://www.snapchat.com/add/{}"),
    ("Medium", "https://medium.com/@{}"),
    ("Imgur", "https://imgur.com/user/{}"),
    ("Keybase", "https://keybase.io/{}"),
    ("Disqus", "https://disqus.com/{}"),
    ("Dribbble", "https://dribbble.com/{}"),
    ("Behance", "https://www.behance.net/{}"),
    ("Flickr", "https://www.flickr.com/people/{}"),
    ("Vimeo", "https://vimeo.com/{}"),
    ("Telegram", "https://t.me/{}"),
    ("Mastodon", "https://mastodon.social/@{}"),
    ("Tumblr", "https://{}.tumblr.com"),
    ("WordPress", "https://{}.wordpress.com"),
    ("Blogger", "https://{}.blogspot.com"),
    ("SoundCloud", "https://soundcloud.com/{}"),
    ("Goodreads", "https://www.goodreads.com/{}"),
    ("Kaggle", "https://www.kaggle.com/{}"),
    ("CodePen", "https://codepen.io/{}"),
    ("Bitbucket", "https://bitbucket.org/{}"),
    ("Glitch", "https://{}.glitch.me"),
    ("Patreon", "https://www.patreon.com/{}"),
    ("Slideshare", "https://www.slideshare.net/{}"),
    ("ProductHunt", "https://www.producthunt.com/@{}"),
    ("Flipboard", "https://flipboard.com/@{}"),
    ("Bandcamp", "https://{}.bandcamp.com"),
    ("Rumble", "https://rumble.com/user/{}"),
    ("Etsy", "https://www.etsy.com/people/{}"),
    ("KhanAcademy", "https://www.khanacademy.org/profile/{}"),
    ("OpenSea", "https://opensea.io/{}"),
    ("Patreon", "https://www.patreon.com/{}"),
    ("Heroku", "https://dashboard.heroku.com/account/{}"),
    ("Gravatar", "https://en.gravatar.com/{}"),
    ("SoundCloud2", "https://soundcloud.com/{}"),
    ("About.me", "https://about.me/{}"),
    ("AngelList", "https://angel.co/{}"),
    ("DEV", "https://dev.to/{}"),
    ("Hashnode", "https://hashnode.com/@{}"),
    ("Triberr", "https://triberr.com/user/{}"),
    ("Bitchute", "https://www.bitchute.com/channel/{}"),
    ("XDA", "https://forum.xda-developers.com/member.php?u={}"),
    ("Scribd", "https://www.scribd.com/{}"),
    ("ResearchGate", "https://www.researchgate.net/profile/{}"),
    ("Academic", "https://scholar.google.com/citations?user={}"),
    ("OpenLibrary", "https://openlibrary.org/people/{}"),
    ("Wikidot", "https://{}.wikidot.com"),
    ("LiveJournal", "https://{}.livejournal.com"),
    ("Slashdot", "https://slashdot.org/~{}"),
    ("Coroflot", "https://www.coroflot.com/{}"),
    ("Houzz", "https://www.houzz.com/user/{}"),
    ("Moz", "https://moz.com/community/users/{}"),
    # ... you can add more later
]

# ---------------- Helpers ----------------
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def nowstamp():
    return datetime.utcnow().strftime("%Y%m%d-%H%M%S")

def safe_filename(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]', '_', name)

def save_json(name: str, obj) -> Path:
    fname = REPORTS_DIR / f"{safe_filename(name)}-{nowstamp()}.json"
    fname.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    return fname

def save_text(name: str, obj) -> Path:
    fname = REPORTS_DIR / f"{safe_filename(name)}-{nowstamp()}.txt"
    fname.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    return fname

def save_html(name: str, obj) -> Path:
    fname = REPORTS_DIR / f"{safe_filename(name)}-{nowstamp()}.html"
    html = "<html><meta charset='utf-8'><body style='font-family: monospace'><h1>HCO-OSINT Report</h1><pre>{}</pre></body></html>".format(
        json.dumps(obj, indent=2, ensure_ascii=False))
    fname.write_text(html, encoding="utf-8")
    return fname

def pretty_print(obj):
    print(json.dumps(obj, indent=2, ensure_ascii=False))

def safe_get_json(url, params=None, headers=None, timeout=12):
    try:
        r = requests.get(url, params=params, headers=headers or HEADERS, timeout=timeout)
        try:
            return r.json()
        except:
            return {"text": r.text[:1500], "status_code": r.status_code}
    except Exception as e:
        return {"error": str(e)}

def safe_get_text(url, timeout=12):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        return r.status_code, r.text, r.headers
    except Exception as e:
        return None, None, {"error": str(e)}

# ---------------- Unlock flow (exact style) ----------------
def unlock_flow():
    clear()
    # exact style: show message then countdown like "9.8?7?6.5.4.3.2.1"
    print(Fore.CYAN + Style.BRIGHT + "\n🔒 This tool is locked. Subscribe to our channel to unlock.")
    # present trend like 9.8?7?6...
    seq = ["9", "8?", "7?", "6.", "5.", "4.", "3.", "2.", "1"]
    print(Fore.YELLOW + "Redirecting you in: ", end="")
    for s in seq:
        sys.stdout.write(Fore.MAGENTA + Style.BRIGHT + f"{s} ")
        sys.stdout.flush()
        time.sleep(0.9)
    print(Fore.GREEN + "\n\nOpening YouTube...")
    try:
        webbrowser.open(YOUTUBE_URL)
    except Exception:
        print(Fore.RED + "Could not open the browser automatically. Open this link manually:")
        print(YOUTUBE_URL)
    input(Fore.CYAN + "\nAfter subscribing, press ENTER to continue...")

def neon_banner():
    clear()
    # large-looking neon red banner (no ASCII art, just spaced and centered)
    title = "HCO OSINT"
    subtitle = "by Azhar (Hackers Colony)"
    width = 70
    print("\n" + Fore.RED + Style.BRIGHT + title.center(width) + "\n")
    print(Fore.RED + Style.BRIGHT + subtitle.center(width) + "\n")
    print(Fore.WHITE + "-"*width + "\n")

# ---------------- Phone ----------------
def phone_parse(number: str):
    out = {"query": number}
    try:
        pn = phonenumbers.parse(number, None)
        out["international"] = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        out["national"] = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL)
        out["country_code"] = pn.country_code
        out["possible"] = phonenumbers.is_possible_number(pn)
        out["valid"] = phonenumbers.is_valid_number(pn)
        out["region"] = phonenumbers.region_code_for_number(pn)
    except Exception as e:
        out["error"] = str(e)
    out["hints"] = {"google_exact": f'"{number}"', "plus_variation": f'"+{number}"'}
    return out

# ---------------- IP (uses ip-api free) ----------------
def ip_lookup(ip: str):
    out = {"query": ip}
    try:
        geo = safe_get_json(f"http://ip-api.com/json/{ip}")
        out["geo"] = geo
    except Exception as e:
        out["geo"] = {"error": str(e)}
    try:
        rev = socket.gethostbyaddr(ip)
        out["reverse_dns"] = {"hostname": rev[0], "aliases": rev[1]}
    except Exception as e:
        out["reverse_dns"] = {"error": str(e)}
    # map link
    latlon = None
    geo = out.get("geo", {})
    if isinstance(geo, dict):
        lat = geo.get("lat") or geo.get("latitude")
        lon = geo.get("lon") or geo.get("longitude")
        if lat and lon:
            latlon = f"{lat},{lon}"
        elif geo.get("loc"):
            latlon = geo.get("loc")
    if latlon:
        out["map_link"] = f"https://www.google.com/maps/search/{latlon}"
    return out

# ---------------- Domain / WHOIS / DNS ----------------
def domain_whois(domain: str):
    try:
        if shutil_which("whois"):
            return subprocess_check_output(["whois", domain], timeout=12)
        else:
            return whois_socket_query(domain)
    except Exception as e:
        return str(e)

def dns_records(domain: str):
    out = {}
    for rtype in ("A","NS","MX","TXT","SOA"):
        try:
            ans = dns.resolver.resolve(domain, rtype, lifetime=8)
            out[rtype] = [str(a).rstrip(".") for a in ans]
        except Exception as e:
            out[rtype] = {"error": str(e)}
    return out

# ---------------- Username concurrent checks (70+) ----------------
def _check_username(session, site_name, pattern, uname):
    url = pattern.format(uname)
    try:
        r = session.head(url, allow_redirects=True, timeout=10)
        return {"site": site_name, "url": url, "status": r.status_code, "exists": r.status_code < 400}
    except Exception:
        try:
            r = session.get(url, allow_redirects=True, timeout=12)
            return {"site": site_name, "url": url, "status": r.status_code, "exists": r.status_code < 400}
        except Exception as e:
            return {"site": site_name, "url": url, "status": None, "exists": False, "error": str(e)}

def username_search(uname: str, sites=USERNAME_SITES, workers=40):
    session = requests.Session()
    session.headers.update(HEADERS)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_check_username, session, s[0], s[1], uname) for s in sites]
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    # save csv
    with open(USERNAME_CSV_LAST, "w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        writer.writerow(["site","url","status","exists","error"])
        for r in results:
            writer.writerow([r.get("site"), r.get("url"), r.get("status"), r.get("exists"), r.get("error","")])
    return {"query": uname, "results": results, "csv": str(USERNAME_CSV_LAST), "timestamp": nowstamp()}

# ---------------- EXIF ----------------
def exif_extract(path: str):
    if not PIL_AVAILABLE:
        return {"error": "Pillow not installed (pip install pillow)"}
    if not os.path.exists(path):
        return {"error": "file not found"}
    try:
        img = Image.open(path)
        info = {}
        exifdata = img._getexif() or {}
        for tag_id, value in exifdata.items():
            tag = TAGS.get(tag_id, tag_id)
            info[tag] = value
        return {"file": path, "exif": info}
    except Exception as e:
        return {"error": str(e)}

# ---------------- URL expander ----------------
def expand_url(url: str):
    try:
        r = requests.get(url, headers=HEADERS, timeout=12, allow_redirects=True)
        return {"final_url": r.url, "status_code": r.status_code, "history": [h.url for h in r.history]}
    except Exception as e:
        return {"error": str(e)}

# ---------------- Google dork generator ----------------
def google_dorks(target: str):
    return {
        "site_search": f"site:{target}",
        "filetype_pdf": f"site:{target} filetype:pdf",
        "intitle_sensitive": f'intitle:"index of" {target}',
        "email_search": f'"@{target}"',
    }

# ---------------- Fake data generator (if faker available) ----------------
def fake_identity():
    if not FAKER_AVAILABLE:
        return {"error": "faker not installed (pip install faker)"}
    return {
        "name": fake.name(),
        "email": fake.email(),
        "phone": fake.phone_number(),
        "address": fake.address(),
        "company": fake.company()
    }

# ---------------- Port scanner (explicit permission) ----------------
COMMON_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,514,587,993,995,1723,3306,3389,5900,6379,6667,8000,8080,8443,9000]

def scan_ports(ip: str, ports=None, timeout=1.0, workers=50):
    ports = ports or COMMON_PORTS
    results = []
    def _check(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, p))
            try:
                s.settimeout(1.0)
                s.sendall(b"\r\n")
                banner = s.recv(1024).decode(errors="ignore").strip()
            except:
                banner = ""
            s.close()
            return (p, True, banner)
        except:
            try: s.close()
            except: pass
            return (p, False, "")
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_check, p) for p in ports]
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    results.sort()
    return results

def pretty_ports(results):
    print(Fore.CYAN + "{:<8} {:<8} {}".format("PORT","STATE","BANNER"))
    for p, open_, banner in results:
        state = Fore.GREEN + "OPEN" if open_ else Fore.RED + "CLOSED"
        b = (banner[:120] + "...") if banner and len(banner) > 120 else banner
        print("{:<8} {:<8} {}".format(str(p), state + Fore.WHITE, b))

# ---------------- Whois helpers ----------------
def shutil_which(cmd):
    from shutil import which
    return which(cmd) is not None

def subprocess_check_output(cmd, timeout=10):
    try:
        res = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout)
        return res.decode(errors="ignore")
    except Exception as e:
        return str(e)

def whois_socket_query(query, server="whois.iana.org", port=43, timeout=10):
    try:
        s = socket.create_connection((server, port), timeout=timeout)
        s.sendall((query + "\r\n").encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
        s.close()
        return data.decode(errors="ignore")
    except Exception as e:
        return str(e)

# ---------------- Interactive CLI ----------------
def interactive_menu():
    # show disclaimer
    clear()
    print(Fore.YELLOW + "⚠️  Use this tool ethically and legally. Do not scan or scrape systems without permission.")
    input(Fore.CYAN + "Press ENTER to continue to unlock flow...")
    unlock_flow()
    neon_banner()
    while True:
        print(Fore.CYAN + "Menu:")
        print(Fore.GREEN + " 1) Phone lookup (parse + hints)")
        print(Fore.GREEN + " 2) IP lookup (geo + reverse DNS + map)")
        print(Fore.GREEN + " 3) Domain (whois + DNS)")
        print(Fore.GREEN + " 4) Email (MX + hints)")
        print(Fore.GREEN + " 5) Username search (concurrent ~70 sites)")
        print(Fore.GREEN + " 6) Port scan & banners (permission required)")
        print(Fore.GREEN + " 7) Profile image downloader (from profile URL)")
        print(Fore.GREEN + " 8) EXIF metadata (image file)")
        print(Fore.GREEN + " 9) URL expander (follow redirects)")
        print(Fore.GREEN + " a) Google dork suggestions")
        print(Fore.GREEN + " b) Fake identity generator (optional)")
        print(Fore.YELLOW + " s) Save last results (JSON/TXT/HTML)")
        print(Fore.RED + " 0) Exit")
        choice = input(Fore.MAGENTA + "\nChoice: ").strip().lower()
        clear()
        if choice == "1":
            num = input(Fore.YELLOW + "Phone (with +country): ").strip()
            if not num: continue
            out = phone_parse(num)
            neon_banner(); print(Fore.CYAN + "Phone result:"); pretty_print(out)
            if input(Fore.MAGENTA + "\nSave? (y/n): ").strip().lower() == "y":
                print(save_json("phone-"+re.sub(r'[^0-9]','',num)))
        elif choice == "2":
            ip = input(Fore.YELLOW + "IP address: ").strip()
            if not ip: continue
            out = ip_lookup(ip)
            neon_banner(); print(Fore.CYAN + "IP result:"); pretty_print(out)
            if out.get("map_link") and input(Fore.MAGENTA + "\nOpen map? (y/n): ").strip().lower() == "y":
                webbrowser.open(out["map_link"])
            if input(Fore.MAGENTA + "\nSave? (y/n): ").strip().lower() == "y":
                print(save_json("ip-"+ip))
        elif choice == "3":
            domain = input(Fore.YELLOW + "Domain: ").strip()
            if not domain: continue
            who = domain_whois(domain)
            dnsr = dns_records(domain)
            neon_banner(); print(Fore.CYAN + "WHOIS (first 3000 chars):"); print(str(who)[:3000])
            print(Fore.CYAN + "\nDNS records:"); pretty_print(dnsr)
            if input(Fore.MAGENTA + "\nSave? (y/n): ").strip().lower() == "y":
                print(save_json("domain-"+re.sub(r'[^a-z0-9]','_',domain)))
        elif choice == "4":
            email = input(Fore.YELLOW + "Email: ").strip()
            if not email: continue
            out = {"query": email}
            domain = email.split("@")[-1] if "@" in email else None
            if domain:
                try:
                    answers = dns.resolver.resolve(domain, "MX", lifetime=8)
                    out["mx"] = [str(r.exchange).rstrip(".") for r in answers]
                except Exception as e:
                    out["mx"] = {"error": str(e)}
            else:
                out["mx"] = {"note": "invalid email"}
            neon_banner(); print(Fore.CYAN + "Email result:"); pretty_print(out)
            if input(Fore.MAGENTA + "\nSave? (y/n): ").strip().lower() == "y":
                print(save_json("email-"+re.sub(r'[^a-z0-9]','_',email.lower())))
        elif choice == "5":
            uname = input(Fore.YELLOW + "Username (no @): ").strip()
            if not uname: continue
            neon_banner(); print(Fore.CYAN + f"Searching for '{uname}' across {len(USERNAME_SITES)} sites (concurrent)...")
            out = username_search(uname)
            pretty_print({"summary": f"checked {len(out['results'])} sites", "csv": out["csv"]})
            if input(Fore.MAGENTA + "\nSave full JSON? (y/n): ").strip().lower() == "y":
                print(save_json("username-"+uname))
        elif choice == "6":
            target = input(Fore.YELLOW + "Target IP/host (only targets you own or have permission for): ").strip()
            if not target: continue
            confirm = input(Fore.RED + "Do you have permission to scan this target? (yes/no): ").strip().lower()
            if confirm not in ("yes","y"):
                print(Fore.YELLOW + "Scan aborted.")
                time.sleep(1); continue
            try:
                ip = socket.gethostbyname(target)
            except:
                ip = target
            neon_banner(); print(Fore.CYAN + f"Scanning common ports on {ip} ...")
            res = scan_ports(ip)
            pretty_ports(res)
            if input(Fore.MAGENTA + "\nSave scan? (y/n): ").strip().lower() == "y":
                print(save_json("portscan-"+ip))
        elif choice == "7":
            url = input(Fore.YELLOW + "Profile URL: ").strip()
        
