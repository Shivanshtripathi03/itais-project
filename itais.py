import subprocess
import re
import requests

LOG_PATH = "/var/log/auth.log"
ABUSEIPDB_API_KEY = ""  # Optional API Key

def scan_ip(ip):
    print(f"\n[+] Scanning IP: {ip}")

    print("\n[>] Running Nmap Scan...")
    nmap_result = subprocess.getoutput(f"nmap -A -T4 {ip}")
    print(nmap_result)

    print("\n[>] Fetching Geo Info...")
    geo = requests.get(f"http://ipinfo.io/{ip}/json").json()
    print(geo)

    if ABUSEIPDB_API_KEY:
        print("\n[>] Checking AbuseIPDB...")
        abuse = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        ).json()
        print(abuse)

def monitor_log():
    print("[*] Monitoring SSH logs for brute-force attempts...\n")
    with subprocess.Popen(['tail', '-F', LOG_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        for line in proc.stdout:
            try:
                line = line.decode("utf-8")
                if "Failed password" in line:
                    match = re.search(r'from ([\d.]+)', line)
                    if match:
                        attacker_ip = match.group(1)
                        print(f"\n[!] Detected failed login from {attacker_ip}")
                        scan_ip(attacker_ip)
            except Exception as e:
                print("Error:", e)

if __name__ == "__main__":
    monitor_log()

