#!/usr/bin/env python3
"""
HCO-OSINT.py — Advanced single-file OSINT toolkit (no API keys required)
By Azhar (Hackers Colony)
"""

import os, sys, time, json, re, socket, concurrent.futures
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import requests
from colorama import Fore, Style, init
import phonenumbers
import dns.resolver
import whois as pywhois
from bs4 import BeautifulSoup

# Optional Pillow for EXIF
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
def clear(): os.system("cls" if os.name=="nt" else "clear")

# ---------------- Unlock flow ----------------
YOUTUBE_URL="https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya"
def unlock_flow():
    clear()
    print(Fore.CYAN+"🔒 Tool locked. Subscribe to unlock.")
    for s in ["9","8?","7?","6.","5.","4.","3.","2.","1"]:
        print(Fore.MAGENTA+Style.BRIGHT+s,end=" ",flush=True)
        time.sleep(0.7)
    print(Fore.GREEN+"\nOpening YouTube...")
    try: import webbrowser; webbrowser.open(YOUTUBE_URL)
    except: print(Fore.RED+"Open manually:",YOUTUBE_URL)
    input(Fore.CYAN+"\nAfter subscribing, press ENTER to continue...")

def show_title():
    clear()
    print(Fore.RED+"HCO OSINT")
    print(Fore.RED+"by Azhar (Hackers Colony)")
    print(Fore.WHITE+"-"*72)

# ---------------- OSINT modules ----------------
def ip_info(target):
    out={"query":target,"timestamp":nowstamp()}
    try: ip=socket.gethostbyname(target)
    except: ip=target
    out["resolved_ip"]=ip
    try:
        r=requests.get(f"http://ip-api.com/json/{ip}",headers={"User-Agent":USER_AGENT},timeout=10)
        out["ip_api"]=r.json()
    except Exception as e: out["ip_api"]={"error":str(e)}
    return out

def whois_and_dns(domain):
    out={"query":domain,"timestamp":nowstamp()}
    try:
        w=pywhois.whois(domain)
        out["whois"]={k:str(v) for k,v in w.items()}
    except Exception as e: out["whois"]={"error":str(e)}
    try:
        dns_out={}
        for rtype in ("A","NS","MX","TXT","SOA"):
            try:
                answers=dns.resolver.resolve(domain,rtype,lifetime=8)
                dns_out[rtype]=[str(a).rstrip(".") for a in answers]
            except Exception as ex: dns_out[rtype]={"error":str(ex)}
        out["dns"]=dns_out
    except Exception as e: out["dns_error"]=str(e)
    return out

def email_info(email):
    out={"query":email,"timestamp":nowstamp()}
    out["format_valid"]=bool(re.match(r"[^@]+@[^@]+\.[^@]+",email))
    domain=email.split("@")[-1] if "@" in email else None
    if domain:
        try:
            ans=dns.resolver.resolve(domain,"MX",lifetime=8)
            out["mx"]=[str(r.exchange).rstrip(".") for r in ans]
        except Exception as e: out["mx"]={"error":str(e)}
    else: out["mx"]={"note":"invalid email"}
    return out

def phone_info(number):
    out={"query":number,"timestamp":nowstamp()}
    try:
        pn=phonenumbers.parse(number,None)
        out["international"]=phonenumbers.format_number(pn,phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        out["national"]=phonenumbers.format_number(pn,phonenumbers.PhoneNumberFormat.NATIONAL)
        out["country_code"]=pn.country_code
        out["possible"]=phonenumbers.is_possible_number(pn)
        out["valid"]=phonenumbers.is_valid_number(pn)
        out["region"]=phonenumbers.region_code_for_number(pn)
    except Exception as e: out["error"]=str(e)
    return out

# ---------------- Username checker (demo) ----------------
USERNAME_SITES=[
("Twitter","https://twitter.com/{}"),
("Instagram","https://www.instagram.com/{}"),
("GitHub","https://github.com/{}"),
("Reddit","https://www.reddit.com/user/{}"),
("YouTube","https://www.youtube.com/@{}"),
("TikTok","https://www.tiktok.com/@{}"),
("LinkedIn","https://www.linkedin.com/in/{}"),
]

def _check_profile(session,site_name,pattern,uname):
    url=pattern.format(uname)
    try:
        r=session.head(url,allow_redirects=True,timeout=8)
        exists=r.status_code<400
        return {"site":site_name,"url":url,"status":r.status_code,"exists":exists}
    except: return {"site":site_name,"url":url,"status":None,"exists":False}

def username_check(uname,sites=None,workers=12,delay=RATE_DELAY):
    sites=sites or USERNAME_SITES
    session=requests.Session()
    session.headers.update({"User-Agent":USER_AGENT})
    results=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures=[ex.submit(_check_profile,session,s[0],s[1],uname) for s in sites]
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result()); time.sleep(delay)
    return {"query":uname,"results":results,"timestamp":nowstamp()}

# ---------------- Subdomains ----------------
def crtsh_subdomains(domain):
    out={"query":domain,"timestamp":nowstamp()}
    try:
        r=requests.get(f"https://crt.sh/?q=%25.{domain}&output=json",headers={"User-Agent":USER_AGENT},timeout=15)
        if r.status_code==200:
            data=r.json();subs=set()
            for item in data:
                name=item.get("name_value","")
                for part in name.split("\n"): subs.add(part.strip())
            out["subdomains"]=sorted(subs)
        else: out["error"]=f"crt.sh status {r.status_code}"
    except Exception as e: out["error"]=str(e)
    return out

# ---------------- URL & sitemap ----------------
def expand_url(url):
    out={"original":url,"timestamp":nowstamp()}
    try:
        r=requests.get(url,headers={"User-Agent":USER_AGENT},timeout=12,allow_redirects=True)
        out["final"]=r.url; out["status_code"]=r.status_code
        out["history"]=[h.url for h in r.history]
        parsed=urlparse(r.url); sitemap_url=f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
        try:
            s=requests.get(sitemap_url,headers={"User-Agent":USER_AGENT},timeout=8)
            if s.status_code==200:
                soup=BeautifulSoup(s.text,"xml")
                urls=[u.text for u in soup.find_all("loc")]
                out["sitemap_count"]=len(urls); out["sitemap_sample"]=urls[:10]
            else: out["sitemap_status"]=s.status_code
        except: out["sitemap_status"]="error"
    except Exception as e: out["error"]=str(e)
    return out

# ---------------- EXIF ----------------
def extract_exif(path):
    if not PIL_AVAILABLE: return {"error":"Pillow not installed"}
    if not os.path.exists(path): return {"error":"file not found"}
    try:
        img=Image.open(path); exif={}
        raw=img._getexif() or {}
        for tagid,value in raw.items(): exif[TAGS.get(tagid,tagid)]=value
        return {"file":path,"exif":exif,"timestamp":nowstamp()}
    except Exception as e: return {"error":str(e)}

# ---------------- CLI ----------------
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
    last_result=None
    show_title()
    print(Fore.YELLOW+"⚠️  Use ethically. Do NOT target systems without permission.")
    while True:
        show_menu(); choice=input(Fore.MAGENTA+"Choice: ").strip().lower()
        if choice=="1": tgt=input("IP/host: "); last_result=ip_info(tgt); pretty_print(last_result)
        elif choice=="2": dom=input("Domain: "); last_result=whois_and_dns(dom); pretty_print(last_result)
        elif choice=="3": em=input("Email: "); last_result=email_info(em); pretty_print(last_result)
        elif choice=="4": ph=input("Phone (+country): "); last_result=phone_info(ph); pretty_print(last_result)
        elif choice=="5": uname=input("Username: "); last_result=username_check(uname); pretty_print(last_result)
        elif choice=="6": dom=input("Domain: "); last_result=crtsh_subdomains(dom); pretty_print(last_result)
        elif choice=="7": u=input("URL: "); last_result=expand_url(u); pretty_print(last_result)
        elif choice=="8": p=input("Image path: "); last_result=extract_exif(p); pretty_print(last_result)
        elif choice=="s":
            if not last_result: print(Fore.YELLOW+"No result to save"); continue
            base=input("Base filename: ").strip() or "hco_report"
            p=save_json(base,last_result); print(Fore.GREEN+f"Saved JSON: {p}")
        elif choice=="q": print(Fore.GREEN+"Exiting."); break
        else: print(Fore.RED+"Invalid choice")

# ---------------- Main ----------------
if __name__ == "__main__":
    try:
        unlock_flow()
        interactive()
    except KeyboardInterrupt:
        print("\n"+Fore.RED+"Interrupted. Exiting.")
