import json
import os
import pytest
from unittest.mock import patch, MagicMock
from network_intel import (
    get_local_lan_ip,
    analyze_ip_or_cidr,
    lookup_geolocation_asn,
    batch_audit_and_export,
)


def test_local_lan_ip_nat_detection():
    lan_ip = get_local_lan_ip()
    assert isinstance(lan_ip, str)
    assert len(lan_ip.split(".")) == 4


def test_ipv4_and_ipv6_validation():
    v4 = analyze_ip_or_cidr("8.8.8.8")
    assert v4["version"] == "IPv4"
    assert v4["is_private"] is False

    v6 = analyze_ip_or_cidr("2001:4860:4860::8888")
    assert v6["version"] == "IPv6"
    assert v6["is_private"] is False


def test_invalid_ip_raises_value_error():
    with pytest.raises(ValueError):
        analyze_ip_or_cidr("999.999.999.999")


def test_cidr_subnet_calculation():
    subnet = analyze_ip_or_cidr("192.168.10.0/24")
    assert subnet["network_address"] == "192.168.10.0"
    assert subnet["broadcast_address"] == "192.168.10.255"
    assert subnet["usable_hosts"] == 254


@patch("network_intel.requests.get")
def test_geolocation_asn_primary_and_fallback(mock_get):
    # Simulate primary API failure (HTTP 429) followed by successful fallback API
    primary_fail = MagicMock(status_code=429)
    fallback_ok = MagicMock(status_code=200)
    fallback_ok.json.return_value = {
        "city": "Ashburn",
        "regionName": "Virginia",
        "country": "United States",
        "as": "AS15169 Google LLC",
    }
    mock_get.side_effect = [primary_fail, fallback_ok]

    res = lookup_geolocation_asn("8.8.8.8")
    assert res["source"] == "ip-api.com"
    assert res["asn_org"] == "AS15169 Google LLC"


def test_batch_audit_json_export(tmp_path):
    out_base = str(tmp_path / "test_export")
    created_file = batch_audit_and_export(["192.168.1.1", "10.0.0.0/24"], export_format="json", filename=out_base)

    assert os.path.exists(created_file)
    with open(created_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert len(data) == 2
    assert data[1]["usable_hosts"] == 254