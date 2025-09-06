#!/usr/bin/env python3
"""
HCO-OSINT (Advanced, no paid APIs)
By Azhar (Hackers Colony)
- Uses free public endpoints + local libraries only
- Saves results to ./results/<timestamp>_target.json
"""

import os
import sys
import time
import json
import socket
import ssl
import subprocess
import platform
import requests
import re
from datetime import datetime
from pprint import pprint

# 3rd-party
try:
    import dns.resolver
except Exception:
    dns = None

try:
    import phonenumbers
except Exception:
    phonenumbers = None

try:
    import whois as pywhois
except Exception:
    pywhois = None

try:
    from tabulate import tabulate
except Exception:
    tabulate = None

from colorama import Fore, Style, init
init(autoreset=True)

# Config
UNLOCK_FILE = os.path.expanduser("~/.hco_osint_unlock")
YOUTUBE = "https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya"
RESULTS_DIR = os.path.join(os.getcwd(), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

# Common port list (top + risky)
COMMON_PORTS = [
    21,22,23,25,53,67,68,80,110,111,123,135,139,143,161,194,389,443,445,465,587,631,
    993,995,1433,1521,2049,2082,2083,2086,2087,2095,2096,3306,3389,47001,5060,5432,5900,6379,8000,8080,8443
]

# Disposable email domains (small list, can be extended)
DISPOSABLE_DOMAINS = {
    "mailinator.com","10minutemail.com","guerrillamail.com","yopmail.com","trashmail.com","dispostable.com"
}

# Utility helpers
def clear():
    os.system("clear" if os.name == "posix" else "cls")

def ts():
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")

def safe_get(url, **kwargs):
    try:
        return requests.get(url, timeout=12, **kwargs)
    except Exception as e:
        return None

def info(k, v, width=20):
    print(Fore.YELLOW + f"{k:<{width}}: " + Fore.WHITE + f"{v}")

def risk(msg):
    print(Fore.RED + Style.BRIGHT + "⚠ " + msg)

def ok(msg):
    print(Fore.GREEN + "✔ " + msg)

# Unlock / YouTube (Termux-friendly)
def unlock():
    if os.environ.get("SKIP_UNLOCK") == "1":
        return
    if os.path.exists(UNLOCK_FILE):
        return
    clear()
    print(Fore.MAGENTA + Style.BRIGHT + "════════════════════════════════════════")
    print(Fore.MAGENTA + Style.BRIGHT + "         🔒 HCO-OSINT TOOL LOCKED 🔒     ")
    print(Fore.CYAN + "Subscribe to Hackers Colony Tech and click the bell 🔔 to unlock.")
    print(Fore.MAGENTA + Style.BRIGHT + "════════════════════════════════════════\n")
    for i in range(8, 0, -1):
        print(Fore.YELLOW + f"Opening YouTube in {i} seconds...", end="\r")
        time.sleep(1)
    if "Android" in platform.platform() or os.path.exists("/data/data/com.termux"):
        os.system(f'am start -a android.intent.action.VIEW -d "{YOUTUBE}" >/dev/null 2>&1')
    else:
        try:
            import webbrowser
            webbrowser.open(YOUTUBE)
        except:
            print(Fore.YELLOW + "Open this link manually: " + YOUTUBE)
    input(Fore.GREEN + "\nPress Enter after subscribing to continue...")
    with open(UNLOCK_FILE, "w") as f:
        f.write("unlocked")

# Save results
def save_results(target, kind, data):
    filename = os.path.join(RESULTS_DIR, f"{ts()}_{kind}_{re.sub(r'[^a-zA-Z0-9_.-]','_',target)}.json")
    try:
        with open(filename, "w") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        ok(f"Results saved: {filename}")
    except Exception as e:
        risk(f"Failed to save results: {e}")

# IP & Geo lookup using ip-api (no key)
def ip_lookup_workflow():
    print(Fore.CYAN + Style.BRIGHT + "\n== IP Lookup (geo + ASN + ping) ==")
    ip = input(Fore.YELLOW + "[?] Enter IP or host: ").strip()
    if not ip:
        print(Fore.RED + "No input.")
        return
    # Try resolve hostname if given
    try:
        resolved_ip = socket.gethostbyname(ip)
    except Exception:
        resolved_ip = ip
    info("Target", ip)
    info("Resolved IP", resolved_ip)
    # ip-api free JSON
    r = safe_get(f"http://ip-api.com/json/{resolved_ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query")
    results = {"target": ip, "resolved_ip": resolved_ip}
    if r and r.status_code == 200:
        j = r.json()
        if j.get("status") == "success":
            info("Country", j.get("country"))
            info("Region", j.get("regionName"))
            info("City", j.get("city"))
            info("ZIP", j.get("zip"))
            info("Lat/Lon", f"{j.get('lat')},{j.get('lon')}")
            info("Timezone", j.get("timezone"))
            info("ISP", j.get("isp"))
            info("Org/ASN", j.get("as"))
            results.update(j)
            # Google maps link
            loc = j.get("lat"), j.get("lon")
            if all(loc):
                gm = f"https://www.google.com/maps/search/{loc[0]},{loc[1]}"
                info("Google Maps", gm)
                results["google_maps"] = gm
        else:
            risk(f"geo lookup failed: {j.get('message')}")
    else:
        risk("ip-api unreachable or rate-limited.")
    # ping latency (system)
    try:
        ping_cmd = ["ping","-c","3",resolved_ip] if os.name != "nt" else ["ping","-n","3",resolved_ip]
        out = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        if out.returncode == 0:
            # extract avg RTT from ping output
            m = re.search(r"avg.* = .*?/([\d.]+)/", out.stdout)  # not reliable across platforms
            # better parse linux summary
            m2 = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", out.stdout)
            info("Ping Output", out.stdout.splitlines()[-1] if out.stdout else "n/a")
            results["ping_raw"] = out.stdout
        else:
            info("Ping", "failed or blocked")
    except Exception as e:
        info("Ping", f"error: {e}")
    save_results(ip, "ip_lookup", results)

# DNS lookups (A, AAAA, MX, NS, TXT, SOA) via dnspython
def dns_lookup_workflow():
    print(Fore.CYAN + Style.BRIGHT + "\n== DNS Lookup ==")
    dom = input(Fore.YELLOW + "[?] Enter domain: ").strip()
    if not dom:
        print(Fore.RED + "No domain.")
        return
    results = {"domain": dom, "records": {}}
    if dns is None:
        risk("dnspython not installed - please pip install dnspython. Falling back to hackertarget if available.")
        r = safe_get(f"https://api.hackertarget.com/dnslookup/?q={dom}")
        if r:
            print(Fore.GREEN + r.text)
            results["raw"] = r.text
            save_results(dom, "dns_lookup", results)
        return
    resolver = dns.resolver.Resolver()
    types = ["A","AAAA","MX","NS","TXT","SOA"]
    for t in types:
        try:
            answers = resolver.resolve(dom, t, lifetime=8)
            vals = []
            for a in answers:
                vals.append(str(a).strip())
            results["records"][t] = vals
            print(Fore.GREEN + f"\n{t} records:")
            for v in vals:
                print(Fore.WHITE + f" - {v}")
        except Exception as e:
            # no records or error
            # print(Fore.YELLOW + f"{t}: none or error ({e})")
            results["records"][t] = []
    # quick SPF/DMARC detection
    txts = " ".join(results["records"].get("TXT", []))
    if "v=spf1" in txts.lower():
        ok("SPF record present")
    else:
        risk("No SPF record found")
    if any("_dmarc" in t.lower() for t in results["records"].get("TXT", []) or []):
        ok("DMARC present")
    else:
        # Many providers publish DMARC as _dmarc.domain TXT; do a direct query
        try:
            answers = resolver.resolve("_dmarc." + dom, "TXT", lifetime=6)
            if answers:
                ok("DMARC record found (via _dmarc query)")
                results["dmarc"] = [str(a) for a in answers]
        except Exception:
            risk("No DMARC record found")
    save_results(dom, "dns", results)

# SSL certificate info via socket + ssl
def ssl_info_workflow():
    print(Fore.CYAN + Style.BRIGHT + "\n== SSL Certificate Info ==")
    host = input(Fore.YELLOW + "[?] Enter hostname (no https): ").strip()
    if not host:
        return
    port = 443
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # cert is dict - format dates
                info("Subject", cert.get("subject"))
                info("Issuer", cert.get("issuer"))
                info("Valid from", cert.get("notBefore"))
                info("Valid to", cert.get("notAfter"))
                alt = cert.get("subjectAltName", [])
                sans = [v for t,v in alt if t.lower()=="dns"]
                info("SANs", ", ".join(sans))
                # show raw
                # pprint(cert)
                save_results(host, "ssl_cert", cert)
    except Exception as e:
        risk(f"SSL retrieval failed: {e}")

# HTTP headers + security scan
def headers_workflow():
    print(Fore.CYAN + Style.BRIGHT + "\n== HTTP Headers and Security Headers ==")
    url = input(Fore.YELLOW + "[?] Enter URL (http/https): ").strip()
    if not url:
        return
    if not url.startswith("http"):
        url = "http://" + url
    try:
        r = requests.head(url, allow_redirects=True, timeout=10)
    except Exception as e:
        risk(f"Request failed: {e}")
        return
    if r is None:
        risk("No response")
        return
    info("Final URL", r.url)
    for k,v in r.headers.items():
        print(Fore.YELLOW + f"{k}: " + Fore.WHITE + f"{v}")
    # security checks
    sec_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection", "Referrer-Policy"]
    missing = [h for h in sec_headers if h not in r.headers]
    for m in missing:
        risk(f"Missing security header: {m}")
    save_results(url, "http_headers", {"url": r.url, "headers": dict(r.headers)})

# Phone lookup using phonenumbers
def phone_workflow():
    print(Fore.CYAN + Style.BRIGHT + "\n== Phone Lookup ==")
    if phonenumbers is None:
        risk("phonenumbers lib missing. Install with: pip install phonenumbers")
        return
    num = input(Fore.YELLOW + "[?] Enter phone (with +countrycode): ").strip()
    try:
        p = phonenumbers.parse(num, None)
        valid = phonenumbers.is_valid_number(p)
        info("Formatted", phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
        info("Valid", valid)
        from phonenumbers import carrier, geocoder, timezone
        info("Region", geocoder.description_for_number(p, "en"))
        info("Carrier", carrier.name_for_number(p, "en"))
        info("Timezone", timezone.time_zones_for_number(p))
        save_results(num, "phone", {"valid": valid})
    except Exception as e:
        risk(f"Phone parse error: {e}")

# Email checks (MX, SPF, DMARC, disposable)
def email_workflow():
    print(Fore.CYAN + Style.BRIGHT + "\n== Email Lookup (MX/SPF/DMARC/Disposable) ==")
    email = input(Fore.YELLOW + "[?] Enter email: ").strip()
    if "@" not in email:
        risk("Invalid email format.")
        return
    domain = email.split("@")[-1]
    info("Domain", domain)
    result = {"email": email, "domain": domain, "mx": [], "txt": []}
    # DNS MX via dns.resolver if available
    if dns is None:
        print(Fore.YELLOW + "dnspython not installed; using hackertarget DNS fallback.")
        r = safe_get(f"https://api.hackertarget.com/dnslookup/?q={domain}")
        if r:
            print(Fore.WHITE + r.text)
            result["raw"] = r.text
            if "MX" in r.text:
                ok("MX info present (raw).")
    else:
        try:
            mx = dns.resolver.resolve(domain, 'MX', lifetime=8)
            mxs = [str(r.exchange).rstrip('.') + " " + str(r.preference) for r in mx]
            result["mx"] = mxs
            print(Fore.GREEN + "MX Records:")
            for m in mxs:
                print(Fore.WHITE + " - " + m)
        except Exception as e:
            risk(f"MX lookup error: {e}")
    # TXT/SPF/DMARC
    try:
        if dns:
            txts = dns.resolver.resolve(domain, 'TXT', lifetime=8)
            txts_v = [b''.join(r.strings).decode(errors='ignore') if hasattr(r,'strings') else str(r) for r in txts]
            result["txt"] = txts_v
            for t in txts_v:
                print(Fore.WHITE + "TXT: " + t)
            if any("v=spf1" in t.lower() for t in txts_v):
                ok("SPF present")
            else:
                risk("No SPF found in TXT records")
            # DMARC
            try:
                d = dns.resolver.resolve("_dmarc." + domain, 'TXT', lifetime=6)
                dvals = [b''.join(r.strings).decode(errors='ignore') for r in d]
                result["dmarc"] = dvals
                ok("DMARC present")
            except Exception:
                risk("No DMARC record found")
        else:
            print(Fore.YELLOW + "Skipping TXT/SPF/DMARC (no dnspython).")
    except Exception as e:
        risk(f"TXT records retrieval error: {e}")
    # disposable
    if domain.lower() in DISPOSABLE_DOMAINS:
        risk("Domain is a known disposable email provider")
    save_results(email, "email", result)

# Username probe across common sites
def username_workflow():
    print(Fore.CYAN + Style.BRIGHT + "\n== Username Lookup (common sites) ==")
    uname = input(Fore.YELLOW + "[?] Enter username: ").strip()
    if not uname:
        return
    sites = [
        "https://github.com/{}",
        "https://twitter.com/{}",
        "https://www.instagram.com/{}",
        "https://www.reddit.com/user/{}",
        "https://www.tiktok.com/@{}",
        "https://www.pinterest.com/{}",
        "https://www.youtube.com/@{}",
        "https://www.facebook.com/{}",
        "https://www.linkedin.com/in/{}",
        "https://steamcommunity.com/id/{}",
        "https://medium.com/@{}"
    ]
    found = []
    for s in sites:
        url = s.format(uname)
        try:
            r = safe_get(url)
            time.sleep(0.4)
            if r and r.status_code == 200:
                found.append({"site": s.split("//")[1].split("/")[0], "url": url})
                print(Fore.GREEN + f"[FOUND] {url}")
            else:
                print(Fore.WHITE + f"[notfound] {url} ({getattr(r,'status_code', 'err')})")
        except Exception as e:
            print(Fore.YELLOW + f"[error] {url} - {e}")
    save_results(uname, "username", {"found": found})

# WHOIS
def whois_workflow():
    print(Fore.CYAN + Style.BRIGHT + "\n== WHOIS Lookup ==")
    dom = input(Fore.YELLOW + "[?] Enter domain: ").strip()
    if not dom:
        return
    if pywhois:
        try:
            w = pywhois.whois(dom)
            # Normalize output
            info("Domain", dom)
            info("Registrar", getattr(w, "registrar", "N/A"))
            info("Creation date", getattr(w, "creation_date", "N/A"))
            info("Expiration date", getattr(w, "expiration_date", "N/A"))
            info("Name servers", getattr(w, "name_servers", "N/A"))
            data = {k: getattr(w, k, None) for k in ["domain_name","registrar","creation_date","expiration_date","name_servers","status","emails"]}
            save_results(dom, "whois", data)
            return
        except Exception as e:
            print(Fore.YELLOW + f"python-whois failed: {e}")
    # fallback to whois command / hackertarget
    try:
        proc = subprocess.run(["whois", dom], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=12)
        if proc.returncode == 0 and proc.stdout:
            print(Fore.WHITE + proc.stdout)
            save_results(dom, "whois_raw", {"whois": proc.stdout})
            return
    except Exception:
        pass
    r = safe_get(f"https://api.hackertarget.com/whois/?q={dom}")
    if r:
        print(Fore.WHITE + r.text)
        save_results(dom, "whois_api", {"raw": r.text})
    else:
        risk("WHOIS query failed.")

# Subdomain enumeration via crt.sh
def subdomain_workflow():
    print(Fore.CYAN + Style.BRIGHT + "\n== Subdomain Enumeration (crt.sh) ==")
    dom = input(Fore.YELLOW + "[?] Enter domain (example.com): ").strip()
    if not dom:
        return
    url = f"https://crt.sh/?q=%25.{dom}&output=json"
    r = safe_get(url)
    if not r:
        risk("crt.sh returned no data or blocked.")
        return
    try:
        j = r.json()
        subs = set()
        for rec in j:
            name = rec.get("name_value","")
            for l in name.splitlines():
                if "*" not in l:
                    subs.add(l.strip())
        subs = sorted(subs)
        ok(f"Found {len(subs)} unique subdomains (crt.sh)")
        for s in subs[:200]:
            print(Fore.WHITE + s)
        save_results(dom, "subdomains", {"count": len(subs), "subs": subs})
    except Exception as e:
        risk(f"Parsing crt.sh output failed: {e}")

# Reverse IP (hackertarget fallback + simple HTTP host check)
def reverse_ip_workflow():
    print(Fore.CYAN + Style.BRIGHT + "\n== Reverse IP Lookup ==")
    ip = input(Fore.YELLOW + "[?] Enter IP: ").strip()
    if not ip:
        return
    r = safe_get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
    if r and r.status_code == 200:
        print(Fore.WHITE + r.text)
        save_results(ip, "reverse_ip", {"raw": r.text})
    else:
        risk("Reverse IP lookup failed or rate-limited.")

# Traceroute (via system mtr/traceroute or hackertarget)
def traceroute_workflow():
    print(Fore.CYAN + Style.BRIGHT + "\n== Traceroute ==")
    host = input(Fore.YELLOW + "[?] Enter host/ip: ").strip()
    if not host:
        return
    # try system traceroute/mtr if present
    try:
        if shutil_which("mtr"):
            proc = subprocess.run(["mtr","-rwz","-c","10", host], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=40)
            print(Fore.WHITE + proc.stdout)
            save_results(host, "traceroute_mtr", {"raw": proc.stdout})
            return
        elif shutil_which("traceroute"):
            proc = subprocess.run(["traceroute", host], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=40)
            print(Fore.WHITE + proc.stdout)
            save_results(host, "traceroute", {"raw": proc.stdout})
            return
    except Exception:
        pass
    # fallback to hackertarget mtr api
    r = safe_get(f"https://api.hackertarget.com/mtr/?q={host}")
    if r:
        print(Fore.WHITE + r.text)
        save_results(host, "traceroute_api", {"raw": r.text})
    else:
        risk("Traceroute failed.")

# Port scanner (socket-based)
def portscan_workflow():
    print(Fore.CYAN + Style.BRIGHT + "\n== Port Scanner (socket) ==")
    host = input(Fore.YELLOW + "[?] Enter host or IP: ").strip()
    if not host:
        return
    try:
        addr = socket.gethostbyname(host)
    except Exception as e:
        risk(f"DNS resolve failed: {e}")
        return
    print(Fore.WHITE + f"Scanning {host} ({addr}) - common ports")
    open_ports = []
    for p in COMMON_PORTS:
        try:
            s = socket.socket()
            s.settimeout(0.9)
            res = s.connect_ex((addr, p))
            if res == 0:
                open_ports.append(p)
                print(Fore.GREEN + f"Open: {p}")
            s.close()
        except Exception:
            pass
    if open_ports:
        save_results(host, "portscan", {"open_ports": open_ports})
        for p in open_ports:
            if p in (21,22,23,445,3389,3306,1433):
                risk(f"Port {p} open - common risky service")
    else:
        ok("No common ports open (or host filtered).")
    # fallback: hackertarget nmap if user wants cloud scan
    ask = input(Fore.YELLOW + "Run remote nmap via hackertarget.com? (Y/n): ").strip().lower()
    if ask in ("y","yes",""):
        r = safe_get(f"https://api.hackertarget.com/nmap/?q={host}")
        if r:
            print(Fore.WHITE + r.text)
            save_results(host, "portscan_remote", {"raw": r.text})
        else:
            risk("Remote nmap failed or rate-limited.")

# small helper to check if command exists
def shutil_which(cmd):
    from shutil import which
    return which(cmd) is not None

# Main menu dispatcher
def main_menu():
    clear()
    print(Fore.CYAN + Style.BRIGHT + "╔════════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT + "║        HCO-OSINT (Advanced)           ║")
    print(Fore.CYAN + Style.BRIGHT + "║          By Azhar (Hackers Colony)    ║")
    print(Fore.CYAN + Style.BRIGHT + "╚════════════════════════════════════════╝\n")
    print(Fore.CYAN + "[1] IP Lookup (geo/ping)")
    print(Fore.CYAN + "[2] DNS Lookup (A/AAAA/MX/NS/TXT/SOA)")
    print(Fore.CYAN + "[3] SSL Cert Info")
    print(Fore.CYAN + "[4] HTTP Headers & Security")
    print(Fore.CYAN + "[5] Phone Lookup (phonenumbers)")
    print(Fore.CYAN + "[6] Email Checks (MX/SPF/DMARC/disposable)")
    print(Fore.CYAN + "[7] Username Probe (multi-site)")
    print(Fore.CYAN + "[8] WHOIS")
    print(Fore.CYAN + "[9] Subdomain Enum (crt.sh)")
    print(Fore.CYAN + "[10] Reverse IP Lookup")
    print(Fore.CYAN + "[11] Traceroute")
    print(Fore.CYAN + "[12] Port Scan")
    print(Fore.CYAN + "[0] Exit\n")

def main():
    unlock()
    while True:
        main_menu()
        choice = input(Fore.YELLOW + "[?] Select option: ").strip()
        if choice == "1":
            ip_lookup_workflow()
        elif choice == "2":
            dns_lookup_workflow()
        elif choice == "3":
            ssl_info_workflow()
        elif choice == "4":
            headers_workflow()
        elif choice == "5":
            phone_workflow()
        elif choice == "6":
            email_workflow()
        elif choice == "7":
            username_workflow()
        elif choice == "8":
            whois_workflow()
        elif choice == "9":
            subdomain_workflow()
        elif choice == "10":
            reverse_ip_workflow()
        elif choice == "11":
            traceroute_workflow()
        elif choice == "12":
            portscan_workflow()
        elif choice == "0":
            print(Fore.GREEN + "Exiting. Stay safe.")
            sys.exit(0)
        else:
            print(Fore.RED + "Invalid choice.")
        input(Fore.CYAN + "\nPress Enter to return to menu...")

if __name__ == "__main__":
    main()
