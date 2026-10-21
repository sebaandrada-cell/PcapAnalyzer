"""DHCP transaction table, built from a dedicated synthetic capture."""
import pytest

from app.analysis.engine import analyze_pcap
from app.tshark import find_tshark
from tests.pcap_builder import build_dhcp_packets, write_pcap


@pytest.fixture(scope="module")
def dhcp_rows(tmp_path_factory):
    path = tmp_path_factory.mktemp("dhcp") / "dhcp.pcap"
    write_pcap(str(path), build_dhcp_packets())
    result = analyze_pcap(find_tshark(), str(path), "dhcp.pcap", path.stat().st_size)
    return {row.client_mac: row for row in result.dhcp_leases}


def test_one_row_per_transaction(dhcp_rows):
    assert len(dhcp_rows) == 3


def test_successful_dora_is_bound_with_latency(dhcp_rows):
    row = dhcp_rows["02:00:00:00:00:11"]
    assert row.status == "bound"
    assert row.ip == "10.0.0.50"
    assert row.server == "10.0.0.1"
    assert row.hostname == "laptop-1"
    assert row.latency_ms == pytest.approx(120.0, abs=1.0)


def test_nak_is_reported(dhcp_rows):
    row = dhcp_rows["02:00:00:00:00:12"]
    assert row.status == "nak"
    assert row.latency_ms is None


def test_discover_without_offer_is_no_offer(dhcp_rows):
    row = dhcp_rows["02:00:00:00:00:13"]
    assert row.status == "no_offer"
    assert row.ip is None
