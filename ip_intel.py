import requests
import subprocess
import json
import sys

ABUSEIPDB_API_KEY = ""  # Set your AbuseIPDB key here or via environment variable
VIRUSTOTAL_API_KEY = ""  # Set your VirusTotal key here or via environment variable


def whois_lookup(ip: str) -> dict:
    """Perform RDAP/Whois lookup on an IP address using ipwhois."""
    try:
        from ipwhois import IPWhois
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        return {
            "asn": result.get("asn", "N/A"),
            "asn_description": result.get("asn_description", "N/A"),
            "network_name": result.get("network", {}).get("name", "N/A"),
            "network_cidr": result.get("asn_cidr", "N/A"),
            "country": result.get("asn_country_code", "N/A"),
        }
    except ImportError:
        print("[!] ipwhois not installed. Install with: pip install ipwhois")
        return {}
    except Exception as e:
        print(f"[!] Whois lookup failed for {ip}: {e}")
        return {}


def geolocation_lookup(ip: str) -> dict:
    """Fetch geolocation data for an IP via ipinfo.io."""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {
                "ip": data.get("ip", ip),
                "city": data.get("city", "Unknown"),
                "region": data.get("region", "Unknown"),
                "country": data.get("country", "Unknown"),
                "org": data.get("org", "Unknown"),
                "location": data.get("loc", "Unknown"),
                "timezone": data.get("timezone", "Unknown"),
            }
        else:
            print(f"[!] ipinfo.io returned status {response.status_code}")
    except Exception as e:
        print(f"[!] Geolocation lookup failed for {ip}: {e}")
    return {}


def scan_ports(ip: str) -> str:
    """Run an Nmap SYN scan against the target IP and return output."""
    try:
        cmd = ["nmap", "-sS", "-Pn", "-T4", ip]
        if ":" in ip:
            cmd = ["nmap", "-6", "-sS", "-Pn", "-T4", ip]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout if result.returncode == 0 else result.stderr
    except FileNotFoundError:
        return "[!] Nmap not found. Install with: sudo apt install nmap"
    except subprocess.TimeoutExpired:
        return "[!] Nmap scan timed out after 120 seconds."
    except Exception as e:
        return f"[!] Nmap scan failed: {e}"


def check_abuseipdb(ip: str) -> dict:
    """Check an IP against the AbuseIPDB API v2."""
    if not ABUSEIPDB_API_KEY:
        return {"error": "No AbuseIPDB API key configured."}

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=10,
        )
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "is_whitelisted": data.get("isWhitelisted", False),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", "Unknown"),
                "country_code": data.get("countryCode", "Unknown"),
                "usage_type": data.get("usageType", "Unknown"),
            }
        else:
            return {"error": f"AbuseIPDB returned status {response.status_code}"}
    except Exception as e:
        return {"error": f"AbuseIPDB lookup failed: {e}"}


def check_virustotal(ip: str) -> dict:
    """Check an IP against the VirusTotal API v3."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "No VirusTotal API key configured."}

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10,
        )
        if response.status_code == 200:
            attrs = response.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "as_owner": attrs.get("as_owner", "Unknown"),
                "country": attrs.get("country", "Unknown"),
                "reputation": attrs.get("reputation", 0),
            }
        else:
            return {"error": f"VirusTotal returned status {response.status_code}"}
    except Exception as e:
        return {"error": f"VirusTotal lookup failed: {e}"}


def full_intel_report(ip: str):
    """Generate a complete intelligence report for a given IP address."""
    print(f"\n{'='*60}")
    print(f"  ITAIS Intelligence Report for: {ip}")
    print(f"{'='*60}\n")

    print("[1/5] Whois / RDAP Lookup...")
    whois = whois_lookup(ip)
    for k, v in whois.items():
        print(f"      {k}: {v}")

    print("\n[2/5] Geolocation Lookup...")
    geo = geolocation_lookup(ip)
    for k, v in geo.items():
        print(f"      {k}: {v}")

    print("\n[3/5] AbuseIPDB Check...")
    abuse = check_abuseipdb(ip)
    for k, v in abuse.items():
        print(f"      {k}: {v}")

    print("\n[4/5] VirusTotal Check...")
    vt = check_virustotal(ip)
    for k, v in vt.items():
        print(f"      {k}: {v}")

    print("\n[5/5] Nmap Port Scan...")
    nmap_output = scan_ports(ip)
    print(nmap_output)

    print(f"\n{'='*60}")
    print("  Report complete.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    full_intel_report(target_ip)
