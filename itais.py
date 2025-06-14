import subprocess
import re
import requests
from datetime import datetime

LOG_PATH = "/var/log/auth.log"  # unused now but can be used for tail -F method
ABUSEIPDB_API_KEY = ""  # Optional API Key
scanned_ips = set()

def scan_ip(ip):
    print(f"\n[+] Scanning IP: {ip}")

    # Skip localhost or already scanned
    if ip in ["127.0.0.1", "::1"]:
        print("[!] Skipping scan: Localhost IP")
        return

    print("\n[>] Fetching Geo Info...")
    geo = requests.get(f"http://ipinfo.io/{ip}/json").json()
    print(geo)

    if geo.get("bogon"):
        print("[!] Skipping scan: Bogon/Private IP")
        return

    print("\n[>] Running Nmap Scan...")
    if ":" in ip:
        nmap_result = subprocess.getoutput(f"nmap -6 -A -T4 {ip}")
    else:
        nmap_result = subprocess.getoutput(f"nmap -A -T4 {ip}")
    print(nmap_result)

    if ABUSEIPDB_API_KEY:
        print("\n[>] Checking AbuseIPDB...")
        abuse = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        ).json()
        print(abuse)

    # Optional: Block IP
    print(f"[!] Blocking IP {ip} using iptables...")
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

    # Log to file
    with open("detection.log", "a") as log:
        log.write(f"[{datetime.now()}] Blocked brute-force attempt from {ip}\n")


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
