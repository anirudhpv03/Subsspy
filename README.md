# 🔍 Subspy

> A lightweight passive subdomain enumeration tool built for Security Researchers, Bug Bounty Hunters, and Penetration Testers.

![Python](https://img.shields.io/badge/Python-3.7+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-blue?style=for-the-badge)
![Contributions](https://img.shields.io/badge/Contributions-Welcome-brightgreen?style=for-the-badge)

---

## 📖 Overview

**Subspy** is a passive reconnaissance tool that discovers subdomains using publicly available intelligence sources without performing active scanning or brute forcing.

It aggregates results from multiple APIs and certificate transparency logs, resolves discovered hosts, probes for live web services, and exports the results in structured formats.

Designed for:

- 🛡️ Bug Bounty Hunters
- 🔍 Penetration Testers
- 🕵️ Security Researchers
- 🎓 Students Learning Reconnaissance

---

# ✨ Features

- 🔎 Fully Passive Subdomain Enumeration
- 🌐 Collects data from multiple public sources
- ⚡ Fast concurrent DNS resolution
- 🚀 HTTP/HTTPS probing
- 🎨 Rich CLI interface with progress bars
- 📊 Beautiful terminal tables
- 💾 JSON and TXT export
- 🧵 Multi-threaded architecture
- 🛑 Graceful timeout/error handling
- ⌨️ Ctrl+C interruption support
- 🐞 Debug mode

---

# 📡 Data Sources

Subspy gathers subdomains from:

- crt.sh
- CertSpotter
- AlienVault OTX
- RapidDNS
- HackerTarget
- Wayback Machine CDX API
- Subfinder *(optional)*
- Assetfinder *(optional)*

---

# ⚙️ Installation

## Clone Repository

```bash
git clone https://github.com/yourusername/subspy.git

cd subspy
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

Or install manually

```bash
pip install requests httpx dnspython beautifulsoup4 rich
```

---

# Optional Tools

Installing these significantly improves coverage.

### Install Subfinder

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Install Assetfinder

```bash
go install github.com/tomnomnom/assetfinder@latest
```

Ensure both binaries are available in your **PATH**.

---

# 🚀 Usage

## Basic Scan

```bash
python3 subspy.py -d example.com
```

or

```bash
python3 subspy.py --domain example.com
```

---

## Debug Mode

```bash
python3 subspy.py -d example.com --debug
```

---

# 📌 Command Line Options

| Option | Description |
|----------|-------------|
| `-d` | Target domain |
| `--domain` | Target domain |
| `--debug` | Enable verbose logging |

---

# 🔄 Workflow

```
            Target Domain
                   │
                   ▼
        Passive Enumeration
                   │
                   ▼
      Merge & Remove Duplicates
                   │
                   ▼
          DNS Resolution
                   │
                   ▼
         HTTP/HTTPS Probing
                   │
                   ▼
      JSON + TXT Report Export
```

---

# 📊 Sample Output

```
Target : example.com

✔ Querying crt.sh
✔ Querying CertSpotter
✔ Querying AlienVault
✔ Querying RapidDNS
✔ Querying Wayback

Resolving Hosts...

Probing Live Services...

┌────────────────────────────┬──────────────┬────────┬──────────────┐
│ Subdomain                  │ IP           │ Status │ Server       │
├────────────────────────────┼──────────────┼────────┼──────────────┤
│ api.example.com            │ 1.2.3.4      │ 200    │ nginx        │
│ mail.example.com           │ 1.2.3.5      │ 302    │ cloudflare   │
│ dev.example.com            │ 1.2.3.6      │ DEAD   │ -            │
└────────────────────────────┴──────────────┴────────┴──────────────┘
```

---

# 📁 Output

Subspy automatically saves results in two formats.

## JSON

```json
[
    {
        "subdomain": "api.example.com",
        "ip": "1.2.3.4",
        "status": 200,
        "server": "nginx",
        "title": "API Service",
        "url": "https://api.example.com"
    }
]
```

---

## TXT

Human-readable report containing:

- Enumeration Results
- DNS Information
- HTTP Status
- Summary Statistics

---

# 📈 Summary Statistics

After every scan, Subspy displays:

- Total Sources Queried
- Unique Subdomains Found
- DNS Resolved Hosts
- Live Hosts
- Execution Time

---

# 🏗 Architecture

Subspy consists of three independent phases.

## Phase 1 — Passive Enumeration

- Query all public sources
- Collect subdomains
- Remove duplicates

---

## Phase 2 — DNS Resolution

- Resolve IPv4 addresses
- Resolve CNAME records
- Ignore invalid hosts

---

## Phase 3 — HTTP Probing

- HTTPS first
- HTTP fallback
- Extract:

  - Status Code
  - Server Header
  - Page Title

---

# 📂 Project Structure

```
subspy/
│
├── subspy.py
├── README.md
├── requirements.txt
└── examples/
```

---

# 🧰 Dependencies

| Package | Purpose |
|-----------|----------|
| requests | API requests |
| httpx | HTTP probing |
| dnspython | DNS resolution |
| beautifulsoup4 | HTML parsing |
| rich | Terminal UI |

---

# ⚡ Performance

Typical performance:

| Metric | Value |
|---------|-------|
| DNS Threads | 20 |
| HTTP Threads | 20 |
| Runtime | 10–30 seconds |
| Memory Usage | ~50–100 MB |

---

# 🐞 Troubleshooting

### Subfinder Missing

```
WARNING: Subfinder not installed
```

The tool continues running without it.

---

### DNS Timeout

```
dns.resolver.Timeout
```

Timeouts are handled gracefully. Some hosts may simply be skipped.

---

### SSL Verification Error

```
SSL: CERTIFICATE_VERIFY_FAILED
```

Update your Python certificate bundle or system certificates.

---

# 🛡 Ethical Use

Subspy is intended **only** for:

- Authorized Security Assessments
- Bug Bounty Programs
- Educational Research
- Reconnaissance on Assets You Own

Never use this tool against systems without proper authorization.

---

# 🤝 Contributing

Contributions are always welcome.

Please ensure:

- PEP-8 compliance
- Type hints
- Clear documentation
- Proper error handling
- Tested features

---

# 📜 License

This project is licensed under the **MIT License**.

See the **LICENSE** file for details.

---

# ⚠️ Disclaimer

This tool is provided for **educational and authorized security testing purposes only**.

The author assumes **no responsibility** for misuse or damage caused by this software. Users are solely responsible for ensuring they have permission before testing any target.

---

# ⭐ Support

If you found this project useful:

- ⭐ Star the repository
- 🍴 Fork it
- 🛠️ Contribute improvements
- 🐛 Report issues

---

<div align="center">

### Built with ❤️ for the Cybersecurity Community

**Happy Hunting! 🛡️**

</div>
