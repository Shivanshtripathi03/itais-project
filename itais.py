import subprocess
import re
import requests
from datetime import datetime
from ipwhois import IPWhois
import requests
import subprocess

LOG_PATH = "/var/log/auth.log"  # unused now but can be used for tail -F method
ABUSEIPDB_API_KEY = ""  # Optional API Key
scanned_ips = set()
def whois_lookup(ip):
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        return result.get("network", {}).get("name", "Unknown Org")
    except Exception as e:
        return f"Whois lookup failed: {e}"

def geolocate_ip(ip):
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json")
        data = res.json()
        return f"{data.get('city', '')}, {data.get('region', '')}, {data.get('country', '')}"
    except Exception as e:
        return f"Geo lookup failed: {e}"

def nmap_scan(ip):
    try:
        cmd = f"nmap -A -T4 {ip}" if ":" not in ip else f"nmap -6 -A -T4 {ip}"
        return subprocess.getoutput(cmd)
    except Exception as e:
        return f"Nmap scan failed: {e}"

def check_abuseipdb(ip):
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        )
        data = response.json()
        return data.get("data", {}).get("abuseConfidenceScore", "No data")
    except Exception as e:
        return f"AbuseIPDB lookup failed: {e}"
def scan_ip(ip):
    print(f"\n[+] Scanning IP: {ip}")

    # Skip localhost
    if ip in ["127.0.0.1", "::1"]:
        print("[!] Skipping scan: Localhost IP")
        return

    print("[+] Whois Info:", whois_lookup(ip))
    print("[+] Geolocation:", geolocate_ip(ip))
    print("[+] Nmap Scan:\n", nmap_scan(ip))
    print("[+] AbuseIPDB:", check_abuseipdb(ip))


def monitor_log():
    print("[*] Monitoring SSH logs via journalctl for brute-force attempts...\n")
    fail_pattern = re.compile(r'Failed password for.*from ([\d.:a-fA-F]+)')

    process = subprocess.Popen(
        ['journalctl', '-u', 'ssh', '-f'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    for line in iter(process.stdout.readline, b''):
        try:
            line = line.decode("utf-8")
            print("[DEBUG] Line:", line.strip())

            if any(kw in line for kw in ["Failed password", "Invalid user", "authentication failure"]):
                match = fail_pattern.search(line)
                if match:
                    ip = match.group(1)
                    if ip not in scanned_ips:
                        scanned_ips.add(ip)
                        print(f"[!] Brute-force attempt detected from IP: {ip}")
                        scan_ip(ip)
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    monitor_log()
