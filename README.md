# HCO-OSINT  

> **Advanced OSINT Framework for Termux & Linux**  
> Code by **Azhar (Hackers Colony Official)**  

![Hackers Colony](https://img.shields.io/badge/Hackers-Colony-red?style=for-the-badge)  
![YouTube](https://img.shields.io/badge/Subscribe-YouTube-red?style=for-the-badge&logo=youtube)  
![Telegram](https://img.shields.io/badge/Join-Telegram-blue?style=for-the-badge&logo=telegram)  
![Discord](https://img.shields.io/badge/Join-Discord-purple?style=for-the-badge&logo=discord)  

---

## 📌 Features
HCO-OSINT provides **8 advanced OSINT modules** without requiring any paid API keys:  

1. **Phone Number Lookup** – carrier, region, validity, type  
2. **IP Lookup** – ISP, ASN, country, city, reverse DNS  
3. **Email Lookup** – MX records, leaks check, validation  
4. **Username Lookup** – search across popular social platforms  
5. **Domain Lookup** – registrar, DNS, subdomains, SSL info  
6. **WiFi & Geo OSINT** – check BSSID/SSID info from open sources  
7. **Device Fingerprint** – extract headers, OS, browser details  
8. **Shodan Scan (No API)** – open ports, services & banners (direct search without requiring API key)  

---

## 🔓 Unlock System
This tool is **not free**.  
When you run it:  

1. Countdown starts: `8,7,6,5,4,3,2,1`  
2. You will be redirected to Hackers Colony YouTube channel  
3. After subscribing, press **Enter** to continue  
4. You’ll see:  
   ```
   ██████████████████████████████████
   HCO-OSINT by Azhar
   ██████████████████████████████████
   ```
   (Displayed in **bold neon green text inside a red box**, no ASCII art)  

---

## ⚡ Installation (Termux / Linux)
Copy & paste the full setup:  

```bash
# Clone repo
git clone https://github.com/HackersColonyOfficial/HCO-OSINT.git
cd HCO-OSINT

# Auto dependency install
chmod +x install.sh
./install.sh

# Run tool
python HCO-OSINT.py
```

---

## 📜 install.sh (Auto Installer)
```bash
#!/bin/bash
echo "[*] Installing dependencies..."
pkg update -y && pkg upgrade -y
pkg install -y python git curl
pip install --upgrade pip
pip install requests beautifulsoup4 dnspython tabulate colorama shodan

echo "[*] Installation complete! Run with: python HCO-OSINT.py"
```

---

## 📸 Screenshot
(Coming soon after first release demo)

---

## ⚠️ Disclaimer
This project is for **educational & awareness purposes only**.  
We are **not responsible** for misuse or illegal activities.  

---

## 🌐 Official Channels
- 🌍 [Website](https://hackerscolonyofficial.blogspot.com/?m=1)  
- 📺 [YouTube](https://youtube.com/@hackers_colony_tech?si=pvdCWZggTIuGb0ya)  
- 💬 [Telegram](https://t.me/hackersColony)  
- 🎮 [Discord](https://discord.gg/Xpq9nCGD)  
- 📷 [Instagram](https://www.instagram.com/hackers_colony_official)  

---

### 💡 Quote
> *"The quieter you become, the more you are able to hear."*  
> — Hackers Colony Official

© 2025 Azhar (Hackers Colony). All rights reserved.
This tool is proprietary — do not copy, share, or redistribute without permission.
