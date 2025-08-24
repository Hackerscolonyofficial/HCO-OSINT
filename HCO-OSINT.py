#!/usr/bin/env python3
"""
HCO-OSINT — Pro Edition (Termux-ready)
By Azhar (Hackers Colony) — 2025

Full-featured, no-API-key OSINT toolkit:
1) Phone Lookup (phonenumbers if available)
2) IP Enrichment (ip-api.com, reverse DNS, ASN, TLS probe)
3) DNS Records (A, AAAA, MX, TXT, NS) + SPF/DMARC checks
4) Website Intelligence (headers, title, security headers, TLS details)
5) My Public IP (IPv4/IPv6 + enrichment)
6) Email OSINT (MX, Gravatar, disposable domain check)
7) Username OSINT (probes many platforms)
8) Subdomain Finder (crt.sh + small wordlist bruteforce)
Preconfigured lab targets included.

No ASCII art. Fancy tables using `rich`.
Dependencies: requests, rich (optional: phonenumbers, dnspython)
"""

import sys
import os
import time
import socket
import ssl
import json
import hashlib
import concurrent.futures
import subprocess
from urllib.parse import quote_plus
from urllib.request import urlopen, Request
from html import unescape

# --- Optional libs (import if available) ---
try:
    import requests
except Exception:
    requests = None

try:
    from rich import print as rprint
    from rich.table import Table
    from rich.panel import Panel
    from rich.console import Console
    from rich.prompt import Prompt
    from rich.progress import track
except Exception:
    rprint = print
    Console = None
    Table = None
    Panel = None
    Prompt = None

try:
    import phonenumbers
    from phonenumbers import geocoder as pn_geocoder, carrier as pn_carrier, timezone as pn_tz
except Exception:
    phonenumbers = None

try:
    import dns.resolver
except Exception:
    dns = None

# --- Config ---
YOUTUBE_URL = "https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya"
COUNTDOWN = 8
PORT_PROBE_TIMEOUT = 0.9
MAX_USERNAME_THREADS = 30
MAX_PORT_THREADS = 120
CRTSH_JSON = "https://crt.sh/?q={q}&output=json"
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query,timezone"
IPIFY = "https://api.ipify.org?format=json"
GRAVATAR = "https://www.gravatar.com/avatar/{h}?d=404"
DISPOSABLE_DOMAINS = {
    "mailinator.com","trashmail.com","10minutemail.com","guerrillamail.com",
    "yopmail.com","temporary-mail.net","tempmail.com","maildrop.cc"
}
# Preconfigured lab targets (safe examples / teaching)
PRECONFIGURED = {
    "Localhost": "127.0.0.1",
    "Google DNS": "8.8.8.8",
    "Cloudflare DNS": "1.1.1.1",
    "Example Website": "example.com"
}

# --- Console helper ---
def ensure_rich():
    if Console is None:
        print("\n[!] Missing dependency: rich")
        print("   Install with: pip install rich requests")
        print("   Continuing with plain output (no tables).\n")

def console_print_panel(title, content):
    if Console:
        console = Console()
        console.print(Panel(content, title=title, expand=False))
    else:
        print(f"\n== {title} ==\n{content}\n")

def build_table(columns):
    if Table:
        t = Table(show_header=True, header_style="bold magenta")
        for col in columns:
            t.add_column(col)
        return t
    return None

# --- Helpers for fetching ---
def fetch_json(url, timeout=10):
    headers = {"User-Agent":"HCO-OSINT/1.0"}
    try:
        if requests:
            r = requests.get(url, headers=headers, timeout=timeout)
            return r.status_code, r.json()
        else:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=timeout) as resp:
                return resp.getcode(), json.loads(resp.read().decode("utf-8", errors="ignore"))
    except Exception:
        return None, None

def fetch_text(url, timeout=10):
    headers = {"User-Agent":"HCO-OSINT/1.0"}
    try:
        if requests:
            r = requests.get(url, headers=headers, timeout=timeout)
            return r.status_code, r.text, r.headers
        else:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=timeout) as resp:
                return resp.getcode(), resp.read().decode("utf-8", errors="ignore"), dict(resp.getheaders())
    except Exception:
        return None, None, None

def try_open_url(url):
    # Termux-friendly opening
    try:
        import shutil
        if shutil.which("termux-open-url"):
            os.system(f"termux-open-url '{url}' >/dev/null 2>&1 &")
            return True
        if shutil.which("am"):
            os.system(f"am start -a android.intent.action.VIEW -d '{url}' >/dev/null 2>&1 &")
            return True
        if shutil.which("xdg-open"):
            os.system(f"xdg-open '{url}' >/dev/null 2>&1 &")
            return True
    except Exception:
        pass
    try:
        import webbrowser
        webbrowser.open(url)
        return True
    except Exception:
        return False

# --- Unlock flow (yellow countdown, open YouTube) ---
def unlock_flow():
    ensure_rich()
    # Yellow bold countdown: use rich coloring or ANSI
    for i in range(COUNTDOWN, 0, -1):
        if Console:
            Console().print(f"[bold yellow]Redirecting in {i}...[/bold yellow]", end="\r")
        else:
            print(f"Redirecting in {i}...", end="\r")
        time.sleep(1)
    print()  # newline
    opened = try_open_url(YOUTUBE_URL)
    if not opened:
        print("Open this link manually:", YOUTUBE_URL)
    input("\nPress Enter after subscribing/visiting to continue...")
    # show centered green text inside red background panel (no ascii)
    content = "[bold green]HCO-OSINT by Azhar[/bold green]"
    console_print_panel("Unlocked", content)

# ---------------- Feature 1: Phone Lookup (advanced) ----------------
def phone_lookup():
    num = Prompt.ask("Phone number (include country code, e.g. +919xxxx)") if Prompt else input("Phone number (with country code): ")
    if not num:
        rprint("[yellow]No number provided.[/yellow]") if rprint else print("No number provided.")
        return
    if phonenumbers:
        try:
            p = phonenumbers.parse(num)
            is_valid = phonenumbers.is_valid_number(p)
            formatted = phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            region = pn_geocoder.description_for_number(p, "en")
            carr = pn_carrier.name_for_number(p, "en")
            tz = pn_tz.time_zones_for_number(p)
            table = build_table(["Field","Value"])
            if table:
                table.add_row("Number", formatted)
                table.add_row("Valid", str(is_valid))
                table.add_row("Region", region or "unknown")
                table.add_row("Carrier", carr or "unknown")
                table.add_row("Timezones", ", ".join(tz) if tz else "unknown")
                Console().print(table)
            else:
                print("Number:", formatted)
                print("Valid:", is_valid)
                print("Region:", region)
                print("Carrier:", carr)
                print("Timezones:", tz)
        except Exception as e:
            rprint(f"[red]Could not parse number: {e}[/red]")
    else:
        rprint("[yellow]phonenumbers not installed. Install: pip install phonenumbers[/yellow]")
        rprint(f"[green]Provided:{RESET} {num}")

# ---------------- Feature 2: IP Enrichment ----------------
def ip_enrichment():
    target = Prompt.ask("IP or domain (leave empty for your public IP)") if Prompt else input("IP or domain (leave empty for your public IP): ")
    if not target:
        code, j = fetch_json(IPIFY, timeout=6)
        if j and "ip" in j:
            target = j["ip"]
    if not target:
        rprint("[red]Could not determine IP.[/red]")
        return
    # if domain, resolve
    resolved_ip = target
    try:
        resolved_ip = socket.gethostbyname(target)
    except Exception:
        pass
    rprint(f"[bold cyan]Enriching:[/bold cyan] {target} -> {resolved_ip}")
    status, data = fetch_json(IP_API_URL.format(ip=quote_plus(resolved_ip)), timeout=6)
    if status == 200 and data and data.get("status") == "success":
        table = build_table(["Field","Value"])
        if table:
            table.add_row("Query", data.get("query",""))
            table.add_row("Country", f"{data.get('country')} ({data.get('timezone')})")
            table.add_row("Region/City", f"{data.get('regionName')}/{data.get('city')} {data.get('zip')}")
            table.add_row("Lat/Lon", f"{data.get('lat')},{data.get('lon')}")
            table.add_row("ISP", data.get("isp",""))
            table.add_row("Org", data.get("org",""))
            table.add_row("ASN", data.get("as",""))
            Console().print(table)
        else:
            print("IP:", data.get("query"))
            print("Country:", data.get("country"))
            print("City:", data.get("city"))
            print("ISP:", data.get("isp"))
    else:
        rprint("[yellow]ip-api lookup failed or blocked.[/yellow]")
    # reverse DNS
    try:
        rev = socket.gethostbyaddr(resolved_ip)[0]
        rprint(f"[green]Reverse DNS:[/green] {rev}")
    except Exception:
        rprint("[yellow]Reverse DNS: none[/yellow]")
    # TLS cert probe on 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((resolved_ip, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=resolved_ip) as ssock:
                cert = ssock.getpeercert()
                subj = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                table = build_table(["Field","Value"])
                if table:
                    table.add_row("Cert CN", subj.get("commonName",""))
                    table.add_row("Issuer CN", issuer.get("commonName",""))
                    table.add_row("Valid from", cert.get("notBefore",""))
                    table.add_row("Valid until", cert.get("notAfter",""))
                    Console().print(table)
                else:
                    print("Cert CN:", subj.get("commonName"))
                    print("Issuer:", issuer.get("commonName"))
    except Exception:
        rprint("[yellow]TLS probe: no certificate or timed out[/yellow]")

# ---------------- Feature 3: DNS Records ----------------
def dns_records():
    domain = Prompt.ask("Domain (example.com)") if Prompt else input("Domain: ")
    if not domain:
        rprint("[red]No domain entered.[/red]"); return
    rprint(f"[bold cyan]DNS Records for {domain}[/bold cyan]")
    # Try dnspython if available
    answers = {}
    if dns:
        resolver = dns.resolver.Resolver()
        for typ in ["A","AAAA","MX","NS","TXT","SOA"]:
            try:
                res = resolver.resolve(domain, typ, lifetime=5)
                answers[typ] = [r.to_text() for r in res]
            except Exception:
                answers[typ] = []
    else:
        # fallback to system `nslookup` for core records
        for typ in ["A","MX","NS","TXT"]:
            try:
                out = subprocess.check_output(["nslookup","-type="+typ,domain], stderr=subprocess.DEVNULL, text=True, timeout=6)
                answers[typ] = [line.strip() for line in out.splitlines() if line.strip()]
            except Exception:
                answers[typ] = []
    # Print table
    table = build_table(["Record","Values"])
    if table:
        for k,v in answers.items():
            vals = "\n".join(v) if v else "<none>"
            table.add_row(k, vals)
        Console().print(table)
    else:
        for k,v in answers.items():
            print(k, "=", v)

    # SPF / DMARC quick check (TXT)
    txts = answers.get("TXT", []) or []
    spf = [t for t in txts if "v=spf1" in t.lower()]
    dmarc = []
    try:
        # query _dmarc
        if dns:
            res = dns.resolver.resolve("_dmarc."+domain, "TXT", lifetime=5)
            dmarc = [r.to_text() for r in res]
        else:
            out = subprocess.check_output(["nslookup","-type=TXT","_dmarc."+domain], stderr=subprocess.DEVNULL, text=True, timeout=6)
            dmarc = [line.strip() for line in out.splitlines() if line.strip()]
    except Exception:
        dmarc = []
    rprint(f"[green]SPF records found:[/green] {len(spf)}; [green]DMARC:[/green] {len(dmarc)}")

# ---------------- Feature 4: Website Intelligence ----------------
def website_intel():
    url = Prompt.ask("Full URL (https://...)") if Prompt else input("Full URL (include https://): ")
    if not url:
        rprint("[red]No URL.[/red]"); return
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url
    status, text, headers = fetch_text(url, timeout=10)
    if status is None:
        rprint("[red]Failed to fetch site.[/red]"); return
    # Basic header display
    table = build_table(["Field","Value"])
    if table:
        table.add_row("Status", str(status))
        server = headers.get("Server") if headers else None
        table.add_row("Server header", server or "<none>")
        powered = headers.get("X-Powered-By") if headers else None
        table.add_row("X-Powered-By", powered or "<none>")
        Console().print(table)
    else:
        print("Status:", status)
        print("Server:", server)
    # Title extraction
    title = "<no title>"
    if text:
        import re
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE|re.DOTALL)
        if m:
            title = unescape(m.group(1).strip())
    rprint(f"[green]Title:[/green] {title}")
    # Security header check
    sec_headers = ["Content-Security-Policy","Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options","Referrer-Policy"]
    missing = [h for h in sec_headers if not headers or (h not in headers and h.lower() not in {k.lower() for k in headers.keys()})]
    if missing:
        rprint(f"[yellow]Missing security headers:[/yellow] {', '.join(missing)}")
    else:
        rprint(f"[green]Basic security headers present[/green]")
    # TLS cert if https
    if url.startswith("https://"):
        host = url.split("://",1)[1].split("/",1)[0].split(":")[0]
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    subj = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    table = build_table(["TLS Field","Value"])
                    if table:
                        table.add_row("Subject CN", subj.get("commonName",""))
                        table.add_row("Issuer", issuer.get("commonName",""))
                        table.add_row("Not Before", cert.get("notBefore",""))
                        table.add_row("Not After", cert.get("notAfter",""))
                        Console().print(table)
        except Exception:
            rprint("[yellow]TLS probe failed or no TLS[/yellow]")

# ---------------- Feature 5: My Public IP (detailed) ----------------
def my_public_ip():
    code, j = fetch_json(IPIFY, timeout=6)
    if not j or "ip" not in j:
        rprint("[red]Could not get public IP.[/red]"); return
    ip = j["ip"]
    rprint(f"[bold cyan]Your public IP: {ip}[/bold cyan]")
    # Enrich via ip-api
    status, data = fetch_json(IP_API_URL.format(ip=quote_plus(ip)), timeout=6)
    if status == 200 and data and data.get("status") == "success":
        table = build_table(["Field","Value"])
        if table:
            table.add_row("IP", data.get("query",""))
            table.add_row("ISP", data.get("isp",""))
            table.add_row("Org", data.get("org",""))
            table.add_row("ASN", data.get("as",""))
            table.add_row("Country", data.get("country"))
            table.add_row("City", f"{data.get('regionName')}/{data.get('city')}")
            table.add_row("Lat/Lon", f"{data.get('lat')},{data.get('lon')}")
            Console().print(table)
    else:
        rprint("[yellow]ip-api lookup failed[/yellow]")

# ---------------- Feature 6: Email OSINT ----------------
def email_osint():
    email = Prompt.ask("Email address") if Prompt else input("Email address: ")
    if not email:
        rprint("[red]No email.[/red]"); return
    rprint(f"[bold cyan]Email: {email}[/bold cyan]")
    # MX lookup
    try:
        mxs = []
        if dns:
            ans = dns.resolver.resolve(email.split("@")[1], "MX", lifetime=6)
            mxs = [r.exchange.to_text() for r in ans]
        else:
            out = subprocess.check_output(["nslookup","-type=MX", email.split("@")[1]], stderr=subprocess.DEVNULL, text=True, timeout=6)
            mxs = [line.strip() for line in out.splitlines() if line.strip()]
        if mxs:
            rprint(f"[green]MX records:[/green] {', '.join(mxs)}")
        else:
            rprint("[yellow]No MX records found[/yellow]")
    except Exception:
        rprint("[yellow]MX lookup failed[/yellow]")
    # Gravatar check
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    grav_url = GRAVATAR.format(h=h)
    status, _, _ = fetch_text(grav_url, timeout=6)
    if status == 200:
        rprint(f"[green]Gravatar found:[/green] {grav_url}")
    else:
        rprint("[yellow]No Gravatar[/yellow]")
    # Disposable check
    domain = email.split("@")[-1].lower()
    if domain in DISPOSABLE_DOMAINS:
        rprint("[red]Disposable email domain detected[/red]")
    else:
        rprint("[green]Domain appears non-disposable[/green]")
    # HIBP web scrape (best-effort) – only show message, do not rely on API
    rprint("[cyan]Note: For full breach checks use HIBP with API key. This tool does not call HIBP API.[/cyan]")

# ---------------- Feature 7: Username enumeration ----------------
COMMON_SITES = [
    ("GitHub","https://github.com/{}"),
    ("GitLab","https://gitlab.com/{}"),
    ("Twitter/X","https://twitter.com/{}"),
    ("Instagram","https://www.instagram.com/{}"),
    ("Reddit","https://www.reddit.com/user/{}"),
    ("Pinterest","https://www.pinterest.com/{}"),
    ("Twitch","https://www.twitch.tv/{}"),
    ("Medium","https://medium.com/@{}"),
    ("StackOverflow","https://stackoverflow.com/users/{}"),
    ("YouTube","https://www.youtube.com/@{}"),
    ("Facebook","https://www.facebook.com/{}"),
    ("LinkedIn","https://www.linkedin.com/in/{}"),
    ("WordPress","https://{}.wordpress.com/"),
]

def username_enum():
    user = Prompt.ask("Username to check") if Prompt else input("Username: ")
    if not user:
        rprint("[red]No username provided.[/red]"); return
    rprint(f"[bold cyan]Enumerating username: {user}[/bold cyan]")
    results = []
    def probe(tpl):
        name, urltpl = tpl
        url = urltpl.format(user)
        try:
            if requests:
                r = requests.head(url, allow_redirects=True, timeout=6, headers={"User-Agent":"HCO-OSINT/1.0"})
                if r.status_code == 200:
                    return (name, url, True, r.status_code)
                if r.status_code in (301,302,302,401,403):
                    return (name, url, True, r.status_code)
                return (name, url, False, r.status_code)
            else:
                req = Request(url, headers={"User-Agent":"HCO-OSINT/1.0"})
                resp = urlopen(req, timeout=6)
                return (name, url, True, resp.getcode())
        except Exception as e:
            s = str(e)
            if "HTTP Error 404" in s:
                return (name, url, False, 404)
            return (name, url, False, None)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_USERNAME_THREADS) as ex:
        futures = [ex.submit(probe, tpl) for tpl in COMMON_SITES]
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    table = build_table(["Platform","Found","URL/Notes"])
    if table:
        for name, url, found, code in sorted(results, key=lambda x: (not x[2], x[0].lower())):
            table.add_
