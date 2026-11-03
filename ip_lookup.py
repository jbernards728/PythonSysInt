"""
Simple IP Address & Network Information Tool
Cisco DEVASC Project Activity - Option 2
Feature: Local LAN IP vs Public Gateway (NAT Detection)
"""

import socket
import requests
import json
from datetime import datetime
from pathlib import Path

TIMEOUT = 5  # seconds before timing out an unreachable endpoint

def get_local_ip():
    """
    Retrieve the local private IP address assigned to this device.
    Uses Python's standard socket library without making an external transmission.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connecting to an arbitrary public IP sets the socket interface to your active LAN card
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip


def get_public_ip(version):
    """
    Retrieve public IPv4 or IPv6 address.
    Uses version-specific hostnames (v4.ident.me / v6.ident.me).
    """
    url = f"https://v{version}.ident.me"
    try:
        response = requests.get(url, timeout=TIMEOUT)
        if response.status_code == 200:
            return response.text.strip()
    except requests.exceptions.RequestException:
        pass
    return None


def get_ip_details(ip_address=""):
    """
    Query ipapi.co REST API for ISP, ASN, and Geolocation metadata.
    """
    url = f"https://ipapi.co/{ip_address}/json/" if ip_address else "https://ipapi.co/json/"
    headers = {"User-Agent": "SimpleIPApp/1.0"}
    
    try:
        response = requests.get(url, headers=headers, timeout=TIMEOUT)
        if response.status_code == 200:
            return response.json()
    except requests.exceptions.RequestException:
        pass
    return {}


def perform_json_export(data, ip_address="127.0.0.1"):
    
    timestamp = datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
    safe_ip = ip_address.replace(":", "-")
    
    export_dir = Path(__file__).resolve().parent / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)

    file_path = export_dir / f"{timestamp}-{safe_ip}-ip-lookup.json"
    
    payload = json.dumps(data, indent=4, ensure_ascii=False)
    with file_path.open("x", encoding="utf-8", newline="\n") as file:
        file.write(payload)
        file.write("\n")
    
    return file_path
    
        

def main():
    print("=" * 50)
    print("        IPatingin IP Lookup Tool        ")
    print("=" * 50)

    # 1. Local Network Inspection
    local_ip = get_local_ip()
    print("\n[+] Local Host Binding:")
    print(f"  • Private LAN IP: {local_ip} (Internal NAT Interface)")

    # 2. Public Dual-Stack Inspection
    print("\n[+] Probing Public Edge Gateways:")
    ipv4 = get_public_ip(4)
    ipv6 = get_public_ip(6)
    print(f"  • Public IPv4   : {ipv4 if ipv4 else 'Unavailable / Not Found'}")
    print(f"  • Public IPv6   : {ipv6 if ipv6 else 'Not Supported / No Route'}")

    # 3. Query ISP and Geolocation Telemetry
    query_ip = ipv4 if ipv4 else ""
    print("\n[+] Fetching ISP & Telemetry via REST API...")
    data = get_ip_details(query_ip)

    if not data or "error" in data:
        print("  [!] Could not retrieve network information (offline or rate limited).")
    else:
        print("-" * 50)
        print("PROVIDER & ROUTING DETAILS")
        print("-" * 50)
        print(f"  • ISP Name      : {data.get('org', 'N/A')}")
        print(f"  • ASN           : {data.get('asn', 'N/A')}")
        
        print("\nGEOLOCATION DETAILS")
        print("-" * 50)
        print(f"  • City / Region : {data.get('city', 'N/A')}, {data.get('region', 'N/A')}")
        print(f"  • Country       : {data.get('country_name', 'N/A')} ({data.get('country_code', 'N/A')})")
        print(f"  • Coordinates   : Lat {data.get('latitude', 'N/A')}, Long {data.get('longitude', 'N/A')}")
        print(f"  • Timezone      : {data.get('timezone', 'N/A')}")

    print("=" * 50)

    # 4. Save Document Finding
    while True:
        answer = input("\n[?] Export result into JSON? (Yes/No) [No]\n").strip().casefold()

        if answer in {"yes", "y"}:
            print("\n[+] Exporting data into JSON...")
                    
            lookup_data = {
                "schema_version": 1,
                "lookup_time": datetime.now().astimezone().isoformat(timespec="seconds"),
                "local_network": {
                    "ip_address": local_ip,
                },
                "public_addresses": {
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                },
                "ip_details": {
                    "queried_ip": data.get("ip"),
                    "provider": data.get("org"),
                    "asn": data.get("asn"),
                    "location": {
                        "city": data.get("city"),
                        "region": data.get("region"),
                        "country": data.get("country_name"),
                        "country_code": data.get("country_code"),
                        "latitude": data.get("latitude"),
                        "longitude": data.get("longitude"),
                        "timezone": data.get("timezone"),
                    },
                },
            }
            
            try:
                file_path = perform_json_export(lookup_data, ipv4 or ipv6)
            except (OSError, TypeError, ValueError) as exc:
                print(f"[!] JSON export failed: {exc}")
            else:
                print(f"[+] JSON saved to {file_path.resolve()}")
            
            print(json.dumps(data, indent=4))
            
            print("=" * 50)
            break
        if answer in {"no", "n", ""}:
            print("[+] Export skipped.")
            return

        print("Please enter yes or no.")

if __name__ == "__main__":
    main()