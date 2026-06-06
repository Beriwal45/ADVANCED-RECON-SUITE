#!/bin/bash
# ============================================================
# Advanced Recon Suite - Complete Dependency Installer
# Tested on Kali Linux (also works on Debian/Ubuntu)
# ============================================================

set -e  # Exit on error

echo "[+] Updating package lists..."
sudo apt update -y

# ------------------------------------------------------------
# 1. Install system tools (from Kali repos)
# ------------------------------------------------------------
echo "[+] Installing system tools: whois, dnsutils (dig), nikto, nmap, whatweb, arjun..."
sudo apt install -y whois dnsutils nikto nmap whatweb arjun

# ------------------------------------------------------------
# 2. Install Python dependencies (via pip3)
# ------------------------------------------------------------
echo "[+] Installing Python packages..."
pip3 install --upgrade pip

pip3 install requests>=2.31.0
pip3 install urllib3>=2.0.0
pip3 install rich>=13.7.0
pip3 install python-whois>=0.8.0
pip3 install wappalyzer>=0.2.2
pip3 install beautifulsoup4
pip3 install lxml
pip3 install dicttoxml>=1.7.4   # Optional but recommended

# ------------------------------------------------------------
# 3. Install bbot (not always in Kali repos, use pip3)
# ------------------------------------------------------------
echo "[+] Installing bbot (passive recon)..."
pip3 install bbot>=1.1.0

# ------------------------------------------------------------
# 4. Optional: Selenium (needs browser, uncomment if required)
# ------------------------------------------------------------
# echo "[+] Installing selenium (optional)..."
# pip3 install selenium

# ------------------------------------------------------------
# 5. Verify installations
# ------------------------------------------------------------
echo ""
echo "[✓] Verification:"
echo "=========================="
whois -v 2>&1 | head -1 || echo "whois: OK"
dig -v | head -1 || echo "dig: OK"
nikto -Version 2>&1 | head -1 || echo "nikto: OK"
nmap --version | head -1 || echo "nmap: OK"
whatweb --version 2>&1 | head -1 || echo "whatweb: OK"
arjun --version 2>&1 | head -1 || echo "arjun: OK"
bbot --version 2>&1 | head -1 || echo "bbot: OK"
python3 -c "import requests, urllib3, rich, whois, Wappalyzer, bs4, lxml, dicttoxml" && echo "Python modules: OK"

echo ""
echo "[✔] All dependencies installed successfully!"
echo "Run your tool: python3 tool.py -u https://example.com"
