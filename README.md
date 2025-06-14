# ITAIS – Intrusion Triggered Attacker Intelligence Scanner

A Python-based tool to detect SSH brute-force attacks on a Linux system and automatically gather intelligence on the attacker.

## Features

- Monitors SSH login attempts from `/var/log/auth.log`
- Detects brute-force patterns
- Extracts attacker IP
- Runs aggressive Nmap scan
- Fetches GeoIP info using ipinfo.io
- (Optional) Checks IP against AbuseIPDB

## Usage

```bash
sudo python3 itais.py

```

## Requirements

- Kali Linux (or any Debian-based distro)
- Python 3
- Nmap
- Python `requests` module (`pip install requests`)

## Optional

- AbuseIPDB API key for enhanced threat intelligence (free tier available)

## Disclaimer

This tool is for **educational and authorized security testing** only. Do not use it on systems without permission.
