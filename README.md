<p align="center">
  <img src="https://img.shields.io/badge/python-3.x-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/platform-Linux-orange?logo=linux&logoColor=white" />
  <img src="https://img.shields.io/badge/Nmap-required-informational?logo=nmap" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
</p>

# ITAIS — Intrusion Triggered Attacker Intelligence Scanner

**ITAIS** is a real-time Linux intrusion detection and attacker profiling tool. It monitors SSH authentication logs for brute-force attempts, automatically extracts the attacker's IP address, and launches a comprehensive intelligence-gathering pipeline — including RDAP/Whois, geolocation, aggressive Nmap port scanning, and threat reputation checks via AbuseIPDB and VirusTotal.

> Designed for penetration testers, SOC analysts, and security researchers running Linux-based honeypots or production servers.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Standalone Intelligence Module](#standalone-intelligence-module)
- [Project Structure](#project-structure)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## How It Works

1. **Monitor** — ITAIS tails the SSH journal (`journalctl -u ssh -f`) in real-time.
2. **Detect** — Regex pattern matching identifies `Failed password`, `Invalid user`, and `authentication failure` events.
3. **Extract** — The attacker's IP address (IPv4 or IPv6) is extracted from the log line.
4. **Deduplicate** — Each IP is scanned only once per session to avoid redundant processing.
5. **Profile** — A full intelligence pipeline is triggered against the attacker IP:
   - **Whois / RDAP** — ASN, network name, CIDR block, organization
   - **Geolocation** — City, region, country, ISP, coordinates (via ipinfo.io)
   - **Nmap Scan** — Aggressive port scan with OS detection (`nmap -A -T4`)
   - **AbuseIPDB** — Abuse confidence score, total reports, usage type
   - **VirusTotal** — Malicious/suspicious detections, reputation score

---

## Features

| Capability | Description |
|---|---|
| **Real-Time SSH Monitoring** | Tails `journalctl` for live SSH authentication events |
| **Brute-Force Detection** | Pattern-matches failed login attempts, invalid users, and auth failures |
| **IPv4 & IPv6 Support** | Handles both address families for Nmap and lookups |
| **RDAP/Whois Intelligence** | ASN, organization, network block via `ipwhois` |
| **GeoIP Enrichment** | City, region, country, ISP via ipinfo.io |
| **Aggressive Nmap Scan** | OS detection, service versions, script scanning (`-A -T4`) |
| **AbuseIPDB Integration** | Abuse confidence score and historical report count |
| **VirusTotal Integration** | Last analysis stats (malicious, suspicious, harmless, undetected) |
| **Localhost Filtering** | Automatically skips `127.0.0.1` and `::1` |
| **Standalone Intel Module** | `ip_intel.py` can be used independently for any IP investigation |

---

## Architecture

```
┌──────────────────────────────────┐
│      SSH Authentication Logs     │
│   (journalctl -u ssh -f)        │
└──────────┬───────────────────────┘
           │  Real-time stream
           ▼
┌──────────────────────────────────┐
│         itais.py                 │
│  ┌─────────────────────────┐    │
│  │  Regex Pattern Matcher  │    │
│  │  (Failed password /     │    │
│  │   Invalid user /        │    │
│  │   auth failure)         │    │
│  └──────────┬──────────────┘    │
│             │ Attacker IP       │
│             ▼                   │
│  ┌─────────────────────────┐    │
│  │   Deduplication Cache   │    │
│  │   (scanned_ips set)     │    │
│  └──────────┬──────────────┘    │
│             │ New IP            │
│             ▼                   │
│  ┌─────────────────────────┐    │
│  │  Intelligence Pipeline  │    │
│  │  ├── Whois / RDAP       │    │
│  │  ├── Geolocation (API)  │    │
│  │  ├── Nmap Scan          │    │
│  │  ├── AbuseIPDB (API)    │    │
│  │  └── VirusTotal (API)   │    │
│  └─────────────────────────┘    │
└──────────────────────────────────┘
           │
           ▼
    Console Output / Report
```

---

## Installation

### Prerequisites

- **Linux** (Kali, Ubuntu, Debian, or any systemd-based distro)
- **Python 3.6+**
- **Nmap** (`sudo apt install nmap`)
- **Root privileges** (required for `journalctl` and SYN scans)

### Steps

```bash
# Clone the repository
git clone https://github.com/Shivanshtripathi03/itais-project.git
cd itais-project

# Install Python dependencies
pip install -r requirements.txt

# Verify Nmap is installed
nmap --version
```

---

## Usage

### Live SSH Monitoring Mode

```bash
sudo python3 itais.py
```

This starts monitoring SSH logs in real-time. When a brute-force attempt is detected, the attacker's IP is automatically scanned and profiled.

### Standalone IP Investigation

```bash
sudo python3 ip_intel.py <target_ip>
```

Example:

```bash
sudo python3 ip_intel.py 45.33.32.156
```

This generates a full 5-step intelligence report for any given IP address without requiring SSH log monitoring.

---

## Configuration

### API Keys (Optional but Recommended)

Add your API keys directly in the Python files or set them as environment variables:

**In `itais.py`:**
```python
ABUSEIPDB_API_KEY = "your_key_here"
```

**In `ip_intel.py`:**
```python
ABUSEIPDB_API_KEY = "your_key_here"
VIRUSTOTAL_API_KEY = "your_key_here"
```

| API | Free Tier | Sign Up |
|---|---|---|
| AbuseIPDB | 1,000 checks/day | [abuseipdb.com](https://www.abuseipdb.com/) |
| VirusTotal | 4 lookups/min | [virustotal.com](https://www.virustotal.com/) |
| ipinfo.io | 50,000 requests/mo | [ipinfo.io](https://ipinfo.io/) (no key needed for basic) |

> If keys are not set, those specific checks will be skipped gracefully — the rest of the pipeline continues to function.

---

## Standalone Intelligence Module

`ip_intel.py` is a fully self-contained IP intelligence tool that can be used independently of the SSH monitoring system. It generates a structured 5-step report:

```
============================================================
  ITAIS Intelligence Report for: 45.33.32.156
============================================================

[1/5] Whois / RDAP Lookup...
      asn: 63949
      asn_description: Linode, LLC
      network_name: LINODE-US
      ...

[2/5] Geolocation Lookup...
      city: Fremont
      region: California
      country: US
      ...

[3/5] AbuseIPDB Check...
      abuse_confidence_score: 0
      total_reports: 3
      ...

[4/5] VirusTotal Check...
      malicious: 1
      suspicious: 0
      ...

[5/5] Nmap Port Scan...
      PORT    STATE SERVICE
      22/tcp  open  ssh
      80/tcp  open  http
      ...

============================================================
  Report complete.
============================================================
```

---

## Project Structure

```
itais-project/
├── itais.py              # Main SSH monitor — detects brute-force & profiles attackers
├── ip_intel.py           # Standalone IP intelligence module (Whois, GeoIP, Nmap, VT, Abuse)
├── requirements.txt      # Python dependencies
├── .gitignore
├── LICENSE               # MIT License
└── README.md
```

---

## Disclaimer

> **⚠️ This tool is intended strictly for educational purposes, authorized security testing, and defensive operations on systems you own or have explicit permission to test.** Unauthorized scanning of IP addresses or systems is illegal. The authors assume no liability for misuse.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>Built with ❤️ by <a href="https://github.com/Shivanshtripathi03">Shivansh Tripathi</a></b>
</p>
