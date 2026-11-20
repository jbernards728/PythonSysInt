import argparse
import csv
import ipaddress
import json
import os
import socket
from datetime import datetime
import requests


def get_local_lan_ip() -> str:
    """Existing Feature: Detects local LAN IP behind NAT using a UDP socket."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def analyze_ip_or_cidr(target: str) -> dict:
    """
    Existing + Backlog Feature 1:
    Validates IPv4/IPv6 addresses and calculates full CIDR subnet details.
    """
    try:
        network = ipaddress.ip_network(target.strip(), strict=False)
        is_single_ip = "/" not in target

        result = {
            "input": target.strip(),
            "version": f"IPv{network.version}",
            "is_private": network.is_private,
            "network_address": str(network.network_address),
            "netmask": str(network.netmask),
            "prefix_length": network.prefixlen,
            "total_addresses": network.num_addresses,
        }

        if network.version == 4:
            result["broadcast_address"] = str(network.broadcast_address)
            result["usable_hosts"] = (
                max(network.num_addresses - 2, 0) if network.prefixlen < 31 else network.num_addresses
            )
        else:
            result["broadcast_address"] = "N/A (IPv6)"
            result["usable_hosts"] = network.num_addresses

        if is_single_ip:
            ip_obj = ipaddress.ip_address(target.strip())
            result["ip_address"] = str(ip_obj)
            result["is_loopback"] = ip_obj.is_loopback

        return result
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4/IPv6 address or CIDR block: {target}") from exc


def lookup_geolocation_asn(ip_addr: str) -> dict:
    """
    Existing + Backlog Feature 2:
    Fetches Geolocation and ASN/ISP info with automatic secondary API fallback.
    """
    primary_url = f"https://ipapi.co/{ip_addr}/json/"
    fallback_url = f"http://ip-api.com/json/{ip_addr}"

    try:
        resp = requests.get(primary_url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if not data.get("error"):
                return {
                    "ip": ip_addr,
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "country": data.get("country_name", "Unknown"),
                    "asn_org": data.get("org", "Unknown"),
                    "source": "ipapi.co",
                }
    except requests.RequestException:
        pass

    # Fallback API if primary is rate-limited or unreachable
    resp = requests.get(fallback_url, timeout=5)
    resp.raise_for_status()
    data = resp.json()
    return {
        "ip": ip_addr,
        "city": data.get("city", "Unknown"),
        "region": data.get("regionName", "Unknown"),
        "country": data.get("country", "Unknown"),
        "asn_org": data.get("as", "Unknown"),
        "source": "ip-api.com",
    }


def batch_audit_and_export(ip_list: list[str], export_format: str = "json", filename: str = "audit_report") -> str:
    """
    Backlog Feature 3:
    Processes multiple IPs in batch and exports results to JSON or CSV.
    """
    results = []
    for item in ip_list:
        info = analyze_ip_or_cidr(item)
        if not info["is_private"] and "/" not in item:
            geo = lookup_geolocation_asn(item)
            info.update(geo)
        results.append(info)

    output_file = f"{filename}.{export_format.lower()}"
    if export_format.lower() == "json":
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    elif export_format.lower() == "csv":
        fieldnames = sorted({k for row in results for k in row.keys()})
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
    else:
        raise ValueError("Unsupported export format. Choose 'json' or 'csv'.")

    return output_file


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Network Intelligence CLI: Local LAN IP, CIDR calculator, Geolocation/ASN lookup, and batch export."
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="IPv4/IPv6 addresses or CIDR blocks to analyze (e.g., 8.8.8.8 192.168.1.0/24). Leave empty for interactive menu.",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "csv"],
        default=None,
        help="Export results to a file in the exports/ directory ('json' or 'csv').",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Custom output filename base (without extension).",
    )

    args = parser.parse_args()

    lan_ip = get_local_lan_ip()
    print(f"========================================")
    print(f" Local LAN IP (NAT): {lan_ip}")
    print(f"========================================")

    targets = args.targets
    export_fmt = args.format

    if not targets:
        user_input = input(
            "\nEnter IP(s) or CIDR block(s) separated by commas (or press Enter to analyze your Local LAN IP): "
        ).strip()
        if user_input:
            targets = [t.strip() for t in user_input.split(",") if t.strip()]
        else:
            targets = [lan_ip]

        if not export_fmt:
            choice = input("Export report? Enter 'json', 'csv', or press Enter to skip: ").strip().lower()
            if choice in ("json", "csv"):
                export_fmt = choice

    results = []
    for target in targets:
        print(f"\n--- Analyzing: {target} ---")
        try:
            info = analyze_ip_or_cidr(target)
            if not info["is_private"] and "/" not in target:
                try:
                    geo = lookup_geolocation_asn(target)
                    info.update(geo)
                except requests.RequestException as exc:
                    info["geolocation_error"] = str(exc)
            results.append(info)
            for k, v in info.items():
                print(f"  {k:18}: {v}")
        except ValueError as exc:
            print(f"  [ERROR] {exc}")

    if export_fmt and results:
        os.makedirs("exports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        default_base = os.path.join("exports", f"{timestamp}-{lan_ip}-ip-lookup")
        out_base = args.output if args.output else default_base
        valid_targets = [r["input"] for r in results]
        saved_path = batch_audit_and_export(valid_targets, export_format=export_fmt, filename=out_base)
        print(f"\n[OK] Report exported to: {saved_path}")


if __name__ == "__main__":
    main()
