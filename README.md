<img width="1792" height="1029" alt="image" src="https://github.com/user-attachments/assets/2d61edf6-6d0a-469a-9f02-246954b92cf8" />
<img width="1761" height="1030" alt="image" src="https://github.com/user-attachments/assets/f4c85c31-ef25-4416-bd0b-8ac38d31c9db" />
<img width="1771" height="1029" alt="image" src="https://github.com/user-attachments/assets/4c95ecab-1290-49f3-ab4f-4652d01d4bfc" />
<img width="1783" height="1024" alt="image" src="https://github.com/user-attachments/assets/9a34f301-8239-41e6-827b-19198d74c146" />
<img width="1735" height="1026" alt="image" src="https://github.com/user-attachments/assets/3d297cdd-aaf2-42f9-b055-7cf1187012e7" />
<img width="1759" height="1030" alt="image" src="https://github.com/user-attachments/assets/353e3ab8-b69a-40a1-aa70-c2c19b9842c4" />

# 🕵️ PANDORA OSINT PIT - Professional Investigation Tool

**Version 1.0.0 | Team: PANDORA**

A comprehensive **Open Source Intelligence (OSINT)** tool designed for professional investigators, security researchers, and cybersecurity professionals. Combines **30+ powerful investigation tools** into one unified interface with both **Graphical (GUI)** and **Command Line (CLI)** modes.

---

## ⚠️ LEGAL DISCLAIMER

**THIS TOOL IS PROVIDED FOR EDUCATIONAL AND LEGITIMATE INVESTIGATION PURPOSES ONLY.**

By using this software, you acknowledge and agree that:

1. **You are solely responsible** for complying with all applicable local, state, national, and international laws regarding your use of this tool.
2. **The creator/developer assumes NO liability** for any misuse, damage, or legal consequences arising from the use of this software.
3. **Do NOT use this tool** for:
   - Unauthorized access to systems or data
   - Harassment, stalking, or invasion of privacy
   - Any illegal or unethical activities
   - Violating terms of service of any platform
4. **Always obtain proper authorization** before investigating any target.
5. This tool should only be used for:
   - Authorized security assessments
   - Digital forensics investigations
   - Academic research
   - Your own systems and data

**USE AT YOUR OWN RISK. THE DEVELOPER DISCLAIMS ALL WARRANTIES AND LIABILITY.**

---

## ✨ Key Features

### 🌐 Web & Domain Investigation
| Tool | Description |
|------|-------------|
| **WHOIS Lookup** | Retrieves domain registration details (registrar, dates, name servers, registrant info) |
| **DNS Records** | Queries A, AAAA, MX, NS, TXT, SOA, CNAME, CAA records |
| **IP Geolocation** | Locates IP address on map (country, city, ISP, coordinates, ASN) |
| **Reverse IP Lookup** | Finds all domains hosted on the same IP address (via YouGetSignal) |
| **SSL Certificate Check** | Analyzes SSL/TLS certificate (issuer, validity, SAN, OCSP) |
| **HTTP Headers Analysis** | Inspects response headers and security header compliance (HSTS, CSP, X-Frame-Options) |
| **Technology Detection** | Identifies web technologies (CMS, frameworks, analytics, CDN) |
| **Wayback Machine History** | Retrieves historical snapshots from the Internet Archive |
| **Google Dorking** | Generates advanced Google search queries (admin panels, exposed files, SQL errors, etc.) |

### 👤 People & Social Media OSINT
| Tool | Description |
|------|-------------|
| **Username Search** | Searches 30+ social platforms (GitHub, Twitter/X, Instagram, Reddit, LinkedIn, TikTok, Telegram, Discord, Twitch, Steam, etc.) |
| **Email OSINT** | Validates email format, checks MX records, detects disposable domains, fetches Gravatar, checks Have I Been Pwned breaches |
| **Phone Number Lookup** | Identifies carrier, location, line type (mobile/voip/landline), country, timezone using libphonenumber |
| **Email Format Guesser** | Generates common email format patterns from first/last name + domain |

### 🔌 Network & Security Tools
| Tool | Description |
|------|-------------|
| **Port Scanner** | TCP connect scan of common ports (55) or top 100 ports with service/banner detection |
| **Ping** | ICMP echo request with RTT statistics (works on Windows, Linux, macOS) |
| **Traceroute** | Route tracing to identify network path and hop latency |
| **URL Expander** | Unshortens shortened URLs and shows full redirect chain |
| **Hash Generator** | Computes hashes (MD5, SHA1, SHA224/256/384/512, BLAKE2b/2s) |
| **Hash Identifier** | Identifies hash type based on length and character pattern |
| **QR Code Generator** | Creates QR codes from text/URL input (saves as PNG) |
| **Shodan Query** | Queries Shodan API for host information or search (requires API key) |

### 📊 Data Analysis
| Tool | Description |
|------|-------------|
| **IOC Extraction** | Automatically extracts Indicators of Compromise from text: IPs, domains, URLs, emails, phone numbers, MAC addresses, crypto addresses (Bitcoin/Ethereum) |
| **CIDR Calculator** | Calculates network range, netmask, broadcast, usable hosts from CIDR notation |
| **User-Agent Generator** | Generates realistic browser user-agent strings (Chrome, Firefox, Edge, Safari) |
| **Text Analysis** | Word/sentence count, character stats, frequent words, readability metrics |
| **Reverse Image Search** | Generates search URLs for Google Images, TinEye, Yandex, Bing, SauceNAO |
| **IP WHOIS (RDAP)** | Queries RIPE RDAP database for IP ownership and organization info |
| **Website Online Check** | Checks if a website is reachable with response time |

### 📁 Export & Reporting
| Format | Description |
|--------|-------------|
| **HTML** | Professional styled report with syntax highlighting |
| **PDF** | Portable document format report |
| **JSON** | Machine-readable data export |
| **CSV** | Spreadsheet-compatible export |
| **TXT** | Plain text report |

---

## 🚀 Installation

### Prerequisites
- **Python 3.8+** installed on your system
- Internet connection for API calls

### Step 1: Clone or Download
```bash
git clone Pandora-OSINT-PIT---Professional-Investigation-Tool/pandora-osint
cd pandora-osint
```
Or download and extract the ZIP file.

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: (Optional) Install Enhanced Features
```bash
pip install rich ttkbootstrap shodan
pip install playwright && playwright install chromium
```

> **Note:** `rich` improves CLI output. `ttkbootstrap` gives the GUI a modern dark theme. `playwright` enables website screenshots. `shodan` enables Shodan queries.

---

## 🎮 Usage

### Graphical Interface (Recommended)
```bash
python main.py
```
Opens a user-friendly GUI window with 6 tabs for all investigation tools.

### Command Line Interface
```bash
python main.py --cli
```
Opens an interactive terminal with the `PANDORA>` prompt.

### CLI Commands
```
GENERAL:
  help                    Show this help menu
  clear                   Clear the screen
  quit / exit             Exit the program

WEB INVESTIGATION:
  whois <domain>          WHOIS lookup (e.g., whois google.com)
  dns <domain>            DNS records (e.g., dns google.com)
  geoip <ip/domain>       IP geolocation (e.g., geoip 8.8.8.8)
  revip <ip/domain>       Reverse IP lookup
  ssl <domain>            SSL certificate check
  headers <url>           HTTP headers analysis
  wayback <domain>        Wayback Machine history
  tech <url>              Technology stack detection
  dork [type] <target>    Google dork generator

PEOPLE OSINT:
  username <username>     Search username across social platforms
  email <email>           Email investigation (breach check)
  phone <number> [region] Phone number lookup
  emailguess <f> <l> <d>  Guess email formats

NETWORK TOOLS:
  portscan <target>       Scan common ports (add 'full' for top 100)
  ping <target>           Ping a host
  traceroute <target>     Trace route to host
  urlexpand <url>         Expand shortened URL
  hash [algo] <text>      Generate hash (default: sha256)
  hashid <hash>           Identify hash type
  qr <data>               Generate QR code

DATA ANALYSIS:
  iocs <text>             Extract IOCs from text
  cidr <cidr>             IP range calculator (e.g., cidr 192.168.1.0/24)
  online <url>            Check if website is online
```

### Examples
```bash
# GUI mode
python main.py

# CLI mode
python main.py --cli

# In CLI:
PANDORA> whois example.com
PANDORA> dns google.com
PANDORA> geoip 8.8.8.8
PANDORA> username johndoe
PANDORA> email user@example.com
PANDORA> portscan scanme.nmap.org
PANDORA> hash sha256 HelloWorld
PANDORA> help
```

## 📂 Project Structure
```
pandora-osint/
├── main.py                  # Entry point (GUI + CLI)
├── requirements.txt         # Dependencies
├── README.md                # This file
├── PLAN.md                  # Architecture plan
├── modules/
│   ├── web_osint.py         # Domain/IP/Website investigation
│   ├── people_osint.py      # People/Email/Phone/Username OSINT
│   ├── network_tools.py     # Port scan, ping, traceroute, hash, QR
│   ├── data_analysis.py     # IOC extraction, CIDR, analysis
│   └── reporting.py         # Export to HTML, PDF, JSON, CSV, TXT
├── ui/
│   ├── app.py               # Main GUI application
│   ├── tabs.py              # Tab implementations
│   └── widgets.py           # Custom GUI widgets
├── utils/
│   ├── helpers.py           # Utility functions
│   └── config.py            # Configuration management
└── reports/                 # Generated reports output
```

---

## 🛡️ Ethical Use Guidelines

This tool is designed for:
- ✅ **Security professionals** conducting authorized penetration tests
- ✅ **Law enforcement** with proper legal authorization
- ✅ **Journalists** investigating public interest stories
- ✅ **Researchers** studying OSINT methodologies
- ✅ **Individuals** investigating their own digital footprint

This tool is **NOT** for:
- ❌ Stalking, harassment, or doxxing
- ❌ Unauthorized access to systems
- ❌ Violating any terms of service
- ❌ Any illegal activities

**Remember:** With great power comes great responsibility. Always stay legal, ethical, and professional.

---

## 📝 License

This project is provided for educational and professional use only. No warranty is expressed or implied. The user assumes all responsibility for compliance with applicable laws.

---

*Built with ❤️ by Team PANDORA*
