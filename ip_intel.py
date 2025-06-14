import requests

def whois_lookup(ip):
    print(f"Whois lookup for: {ip}")
    # Add ipwhois code later

def geolocation_lookup(ip):
    response = requests.get(f"https://ipinfo.io/{ip}/json")
    print(response.json())

def scan_ports(ip):
    import os
    os.system(f"nmap -sS -Pn {ip}")

def check_threat_intel(ip):
    print("Check this IP in VirusTotal, AbuseIPDB APIs")

# Example use
ip = "8.8.8.8"
whois_lookup(ip)
geolocation_lookup(ip)
scan_ports(ip)
check_threat_intel(ip)
