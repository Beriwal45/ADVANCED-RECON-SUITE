# 🛡️ Advanced Recon Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Ubuntu-lightgrey)](https://www.kali.org/)

**Advanced Recon Suite** is a professional-grade, all-in-one reconnaissance tool for web applications and APIs. It seamlessly integrates passive and active information gathering techniques, leveraging both Python libraries and industry-standard external tools to deliver a comprehensive security assessment.

Built with a beautiful Rich-powered terminal UI, it provides an organized, color-coded dashboard that aggregates results from multiple modules, helping you identify potential security misconfigurations and vulnerabilities efficiently.


## ✨ Key Features

| Category | Modules |
| :--- | :--- |
| **🔍 Discovery** | Subdomain Enumeration (Passive + DNS Brute), DNS Enumeration (A, AAAA, MX, NS, TXT, CAA) |
| **⚙️ Fingerprinting** | Technology Detection (Wappalyzer + WhatWeb), Cloud Provider Detection (AWS, Azure, GCP, Cloudflare), WAF Detection, SSL/TLS Analysis |
| **🛡️ Security Analysis** | Security Headers Check (HSTS, CSP, X-Frame-Options, etc.), IP Disclosure Check |
| **📜 Information Gathering** | WHOIS Lookup (python-whois + system whois fallback), Sensitive Data Discovery (API keys, Tokens, JWT) |
| **🔬 Active Scanning** | Nikto Vulnerability Scanner, Nmap Port Scanner, Arjun Parameter Fuzzing, BBOT Passive Recon |

## 📦 Installation

### System Requirements
- Kali Linux (recommended) or any Debian-based Linux distribution.
- Python 3.8 or higher.
- An active internet connection for external API calls (e.g., crt.sh).

### Automated Installation (Recommended)
We provide a bash script that handles all system dependencies and Python packages.

```bash
git clone https://github.com/Beriwal45/ADVANCED-RECON-SUITE.git
cd ADVANCED-RECON-SUITE
chmod +x install_tool.sh
./install_tool.sh
