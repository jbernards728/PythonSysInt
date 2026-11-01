#!/usr/bin/env python3
"""
Simple IP Address & Network Information Tool
Cisco DEVASC Project Activity - Option 2
Feature: Local LAN IP vs Public Gateway (NAT Detection)
"""

import socket
import requests

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


def main():
    print("=" * 50)
    print("        NETWORK TECHNICIAN IP LOOKUP TOOL        ")
    print("=" * 50)

    # 1. Local Network Inspection
    local_ip = get_local_ip()
    print(f"\n[+] Local Host Binding:")
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


if __name__ == "__main__":
    main()