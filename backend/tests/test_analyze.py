from __future__ import annotations

import pytest

from app.tshark import find_tshark

requires_tshark = pytest.mark.skipif(
    find_tshark() is None, reason="tshark no está instalado"
)


def _analyze(client, sample_pcap):
    with open(sample_pcap, "rb") as fh:
        response = client.post(
            "/analyze", files={"file": ("sample.pcap", fh, "application/octet-stream")}
        )
    assert response.status_code == 200, response.text
    return response.json()


def test_health(client):
    data = client.get("/health").json()
    assert data["status"] == "ok"
    assert "tshark" in data


def test_rejects_non_pcap(client):
    response = client.post(
        "/analyze", files={"file": ("notes.txt", b"this is not a pcap", "text/plain")}
    )
    assert response.status_code == 400
    assert "pcap" in response.json()["detail"].lower()


def test_rejects_empty_file(client):
    response = client.post(
        "/analyze", files={"file": ("empty.pcap", b"", "application/octet-stream")}
    )
    assert response.status_code == 400


def test_rejects_gzip_expansion_above_limit(client, monkeypatch):
    import gzip
    from app import config

    monkeypatch.setattr(config, "MAX_DECOMPRESSED_MB", 1)
    content = gzip.compress(b"\x0a\x0d\x0d\x0a" + b"x" * (1024 * 1024))
    response = client.post(
        "/analyze",
        files={"file": ("large.pcapng.gz", content, "application/gzip")},
    )
    assert response.status_code == 413
    assert "descomprimido" in response.json()["detail"]


@requires_tshark
def test_analysis_state_limits_are_reported(client, sample_pcap, monkeypatch):
    from app import config

    monkeypatch.setattr(config, "MAX_CONVERSATIONS", 1)
    monkeypatch.setattr(config, "MAX_TIME_SERIES_BUCKETS", 1)
    result = _analyze(client, sample_pcap)
    assert len(result["conversations"]["tcp"]) + len(result["conversations"]["udp"]) == 1
    assert {"conversations", "time_series"}.issubset(
        result["meta"]["truncated_sections"]
    )


def test_looks_like_capture():
    from app.main import _looks_like_capture

    # classic pcap (both endians), pcapng section header
    assert _looks_like_capture(b"\xd4\xc3\xb2\xa1rest")
    assert _looks_like_capture(b"\xa1\xb2\xc3\xd4rest")
    assert _looks_like_capture(b"\x0a\x0d\x0d\x0a\x1c\x00")
    # gzip: FLG=0x00 (no name) and FLG=0x08 (original filename stored)
    assert _looks_like_capture(b"\x1f\x8b\x08\x00\x00\x00")
    assert _looks_like_capture(b"\x1f\x8b\x08\x08\x00\x00")
    # junk is rejected
    assert not _looks_like_capture(b"this is not a pcap")
    assert not _looks_like_capture(b"\x89PNG\r\n")


@requires_tshark
def test_accepts_gzipped_capture(client, sample_pcap):
    import gzip

    with open(sample_pcap, "rb") as fh:
        gzipped = gzip.compress(fh.read())
    response = client.post(
        "/analyze",
        files={"file": ("sample.pcap.gz", gzipped, "application/gzip")},
    )
    assert response.status_code == 200, response.text
    assert response.json()["summary"]["packets"] > 0


@requires_tshark
def test_summary(client, sample_pcap):
    from tests.pcap_builder import build_sample_packets

    packets = build_sample_packets()
    result = _analyze(client, sample_pcap)
    summary = result["summary"]
    assert summary["packets"] == len(packets)
    assert summary["duration_seconds"] == pytest.approx(
        packets[-1][0] - packets[0][0], abs=0.01
    )
    assert summary["bytes"] > 0
    assert summary["conversations"] == 15  # 5 TCP + 10 UDP
    assert result["file"]["name"] == "sample.pcap"
    assert result["meta"]["tshark_version"].startswith("TShark")


@requires_tshark
def test_time_series(client, sample_pcap):
    result = _analyze(client, sample_pcap)
    series = result["time_series"]
    assert series, "expected time series points"
    assert sum(point["packets"] for point in series) == result["summary"]["packets"]
    assert sum(point["retransmissions"] for point in series) == 5  # 2 HTTP + 3 PMTUD
    ts_by_second = {point["t"]: point for point in series}
    assert ts_by_second[0]["retransmissions"] == 2  # HTTP retrans in first second
    assert [point["t"] for point in series] == sorted(ts_by_second)


@requires_tshark
def test_protocol_distribution(client, sample_pcap):
    result = _analyze(client, sample_pcap)
    protocols = {item["protocol"]: item for item in result["protocols"]}
    assert protocols["dns"]["packets"] == 13
    for expected in ("tls", "tcp", "esp", "isakmp", "arp", "icmp"):
        assert expected in protocols, "falta %s" % expected
    total_pct = sum(item["packet_pct"] for item in result["protocols"])
    assert total_pct == pytest.approx(100.0, abs=0.5)
    total_bytes_pct = sum(item["bytes_pct"] for item in result["protocols"])
    assert total_bytes_pct == pytest.approx(100.0, abs=0.5)


@requires_tshark
def test_conversations(client, sample_pcap):
    result = _analyze(client, sample_pcap)
    convs = result["conversations"]
    assert len(convs["tcp"]) == 5
    assert len(convs["udp"]) == 10

    http = next(conv for conv in convs["tcp"] if conv["dst_port"] == 80)
    assert http["packets"] == 9
    assert http["retransmissions"] == 2
    assert http["retransmission_pct"] == pytest.approx(22.2, abs=0.1)
    assert http["zero_window_events"] == 1
    assert http["bytes_src_to_dst"] > http["bytes_dst_to_src"]

    blackhole = next(conv for conv in convs["tcp"] if conv["dst_port"] == 8080)
    assert blackhole["mss_client"] == 1240
    assert blackhole["mss_server"] == 1460
    assert blackhole["handshake_rtt_ms"] == pytest.approx(10.0, abs=0.5)

    slow = next(conv for conv in convs["tcp"] if conv["dst_port"] == 9090)
    assert slow["handshake_rtt_ms"] == pytest.approx(600.0, abs=1.0)

    talkers = convs["top_talkers"]
    assert talkers, "expected top talkers"
    assert talkers[0]["address"] == "10.0.0.1"  # client sends/receives the most
    assert talkers[0]["bytes_total"] == max(t["bytes_total"] for t in talkers)


@requires_tshark
def test_tunnels(client, sample_pcap):
    result = _analyze(client, sample_pcap)
    tunnels = {(t["type"], t["peer_b"]): t for t in result["tunnels"]}

    esp = tunnels[("esp", "10.0.0.6")]
    assert esp["packets_a_to_b"] == 4
    assert esp["packets_b_to_a"] == 0

    ike_dead = tunnels[("ike", "10.0.0.6")]
    assert ike_dead["packets_a_to_b"] == 3
    assert ike_dead["packets_b_to_a"] == 0

    ike_half = tunnels[("ike", "10.0.0.7")]
    assert ike_half["packets_a_to_b"] == 1
    assert ike_half["packets_b_to_a"] == 1


@requires_tshark
def test_packet_list(client, sample_pcap):
    result = _analyze(client, sample_pcap)
    packet_list = result["packet_list"]
    assert packet_list["total"] == result["summary"]["packets"]
    assert packet_list["truncated"] is False
    assert len(packet_list["rows"]) == packet_list["total"]

    first = packet_list["rows"][0]
    assert first["number"] == 1
    assert first["protocol"] == "TCP"
    assert "[SYN]" in first["info"]
    assert first["src"] == "10.0.0.1"

    arp = next(row for row in packet_list["rows"] if row["protocol"] == "ARP")
    assert arp["src"] == "—"  # non-IP packet
    assert "10.0.0.99" in arp["info"]

    tls = next(row for row in packet_list["rows"] if "Alert" in row["info"])
    assert tls["protocol"].startswith("TLS")

    # tcp.stream tagging (for the flow graph): HTTP packets carry stream 0,
    # the ARP row carries none.
    http_syn = next(row for row in packet_list["rows"] if "[SYN]" in row["info"])
    assert http_syn["stream"] == 0
    assert arp["stream"] is None


@requires_tshark
def test_packet_list_truncation(sample_pcap, monkeypatch):
    from app import config
    from app.analysis import analyze_pcap
    from app.tshark import find_tshark
    from tests.pcap_builder import build_sample_packets

    monkeypatch.setattr(config, "PACKET_LIST_MAX", 10)
    result = analyze_pcap(find_tshark(), str(sample_pcap), "sample.pcap", 0)
    assert len(result.packet_list.rows) == 10
    assert result.packet_list.total == len(build_sample_packets())
    assert result.packet_list.truncated is True


@requires_tshark
def test_http_requests_table(client, sample_pcap):
    result = _analyze(client, sample_pcap)
    requests = result["http_requests"]
    assert len(requests) == 1
    request = requests[0]
    assert request["method"] == "GET"
    assert request["host"] == "server.example"
    assert request["uri"] == "/"
    assert request["client"] == "10.0.0.1"
    assert request["server"] == "10.0.0.2"
    assert request["status"] == 200


@requires_tshark
def test_dns_queries_table(client, sample_pcap):
    result = _analyze(client, sample_pcap)
    queries = {row["name"]: row for row in result["dns_queries"]}
    assert len(result["dns_queries"]) == 7

    assert queries["fast.example.com"]["status"] == "ok"
    assert queries["slow.example.com"]["status"] == "slow"
    assert queries["slow.example.com"]["latency_ms"] == pytest.approx(700.0, abs=5.0)
    assert queries["dead.example.com"]["status"] == "unanswered"
    assert queries["dead.example.com"]["latency_ms"] is None
    assert queries["fail.example.com"]["status"] == "servfail"
    assert queries["typo1.example.com"]["status"] == "nxdomain"


@requires_tshark
def test_service_response_times(client, sample_pcap):
    result = _analyze(client, sample_pcap)
    srt = {row["protocol"]: row for row in result["service_response_times"]}
    # DNS: fast (20ms) + slow (700ms) answered exchanges
    assert srt["DNS"]["samples"] >= 2
    assert srt["DNS"]["max_ms"] == pytest.approx(700.0, abs=5.0)
    # TCP handshake: SYN->SYN-ACK across the completed handshakes
    assert srt["TCP handshake"]["samples"] >= 3
    # HTTP: one request answered in 520 ms
    assert srt["HTTP"]["samples"] == 1
    assert srt["HTTP"]["avg_ms"] == pytest.approx(520.0, abs=5.0)


@requires_tshark
def test_tls_sessions(client, sample_pcap):
    result = _analyze(client, sample_pcap)
    sessions = result["tls_sessions"]
    assert len(sessions) == 1
    tls = sessions[0]
    assert tls["client"] == "10.0.0.1"
    assert tls["server"] == "10.0.0.2"
    assert tls["version"] == "TLS 1.2"        # handshake version 0x0303
    assert tls["cipher"] == "RSA_AES_128_CBC_SHA"  # 0x002f
    assert tls["alert"] == "handshake_failure"


@requires_tshark
def test_issue_detection(client, sample_pcap):
    result = _analyze(client, sample_pcap)
    issues = result["issues"]
    by_type = {}
    for issue in issues:
        by_type.setdefault(issue["type"], []).append(issue)

    expected = {
        "tcp_retransmissions",
        "tcp_syn_rst",
        "dns_unanswered",
        "dns_slow",
        "tls_handshake_failure",
        "mss_low",
        "icmp_frag_needed",
        "pmtud_blackhole",
        "ip_fragmentation_high",
        "ip_fragments_incomplete",
        "esp_one_way",
        "ike_no_response",
        "ike_handshake_incomplete",
        "tcp_slow_handshake",
        "dns_servfail",
        "dns_nxdomain",
        "ip_duplicate",
    }
    assert expected.issubset(by_type.keys()), "faltan tipos: %s" % (
        expected - set(by_type)
    )

    retrans = next(issue for issue in by_type["tcp_retransmissions"]
                   if issue["evidence"]["stream_id"] == 0)
    assert retrans["severity"] == "critical"  # 22% > 2% (CLAUDE.md threshold)
    assert retrans["evidence"]["retransmission_pct"] == pytest.approx(22.2, abs=0.1)

    syn_rst = by_type["tcp_syn_rst"][0]
    assert syn_rst["severity"] == "critical"
    assert syn_rst["evidence"]["dst_port"] == 8443
    assert syn_rst["evidence"]["syn_to_rst_ms"] == pytest.approx(5.0, abs=0.5)

    unanswered = by_type["dns_unanswered"]
    assert len(unanswered) == 1
    assert unanswered[0]["evidence"]["query_name"] == "dead.example.com"
    assert unanswered[0]["evidence"]["capture_boundary_possible"] is True
    assert "tcp_zero_window" not in by_type  # one isolated event is not sustained

    slow = by_type["dns_slow"]
    assert len(slow) == 1
    assert slow[0]["evidence"]["query_name"] == "slow.example.com"
    assert slow[0]["evidence"]["latency_ms"] == pytest.approx(700.0, abs=5.0)

    tls = by_type["tls_handshake_failure"][0]
    assert tls["severity"] == "warning"  # aviso per CLAUDE.md
    assert tls["evidence"]["alert_code"] == 40

    assert by_type["mss_low"][0]["evidence"]["mss_client"] == 1240
    assert by_type["icmp_frag_needed"][0]["evidence"]["path_mtu"] == 1400
    assert by_type["pmtud_blackhole"][0]["evidence"]["full_size_retransmissions"] == 3
    assert by_type["ip_fragments_incomplete"][0]["severity"] == "warning"
    assert by_type["ike_no_response"][0]["severity"] == "warning"
    assert by_type["ike_no_response"][0]["evidence"]["responder"] == "10.0.0.6"
    assert by_type["ike_handshake_incomplete"][0]["evidence"]["peer_b"] == "10.0.0.7"
    assert by_type["esp_one_way"][0]["evidence"]["silent_peer"] == "10.0.0.6"
    assert by_type["tcp_slow_handshake"][0]["evidence"]["handshake_rtt_ms"] == pytest.approx(600.0, abs=1.0)
    assert by_type["dns_servfail"][0]["evidence"]["count"] == 1
    assert by_type["dns_nxdomain"][0]["evidence"]["count"] == 3
    dup = by_type["ip_duplicate"][0]
    assert dup["severity"] == "warning"
    assert dup["evidence"]["ip"] == "10.0.0.99"
    assert len(dup["evidence"]["macs"]) == 2

    # critical issues must come first
    severities = [issue["severity"] for issue in issues]
    assert severities == sorted(
        severities, key=lambda s: {"critical": 0, "warning": 1, "info": 2}[s]
    )
