"""Application-layer detectors over data the engine already extracts:
HTTP errors and slow responses, DHCP failures and legacy TLS versions."""
from __future__ import annotations

import pytest

from app import config
from app.analysis import engine
from app.analysis.engine import DhcpTxnState, TlsSessionState, analyze_pcap
from app.detectors import DETECTORS, dhcp_problems, http_errors, tls_legacy
from app.models import HttpRequestRow
from app.tshark import find_tshark
from tests.test_detectors import _state

requires_tshark = pytest.mark.skipif(find_tshark() is None, reason="tshark no está instalado")


def _req(status, server="10.0.0.2", response_ms=20.0, uri="/"):
    return HttpRequestRow(time=0.0, client="10.0.0.1", server=server, method="GET",
                          host="app.test", uri=uri, status=status, response_ms=response_ms)


def _by_type(issues):
    return {issue.type: issue for issue in issues}


class TestHttpErrors:
    def test_server_errors_are_reported_per_server(self):
        state = _state(http_requests=[_req(200), _req(500), _req(503), _req(200, "10.0.0.9")])

        issue = _by_type(http_errors.detect(state))["http_server_errors"]

        assert issue.severity == "warning"
        assert issue.evidence == {"server": "10.0.0.2", "count": 2, "responses": 3,
                                  "codes": [500, 503], "error_pct": 66.7}
        assert "10.0.0.2" in issue.detail and "10.0.0.2" in issue.detail_en

    def test_mostly_failing_server_is_critical(self):
        state = _state(http_requests=[_req(502)] * 4 + [_req(200)])

        assert _by_type(http_errors.detect(state))["http_server_errors"].severity == "critical"

    def test_client_errors_need_a_burst_and_ignore_auth_challenges(self):
        few = _state(http_requests=[_req(404)] * (config.HTTP_4XX_MIN - 1) + [_req(401)] * 20)
        assert http_errors.detect(few) == []

        burst = _state(http_requests=[_req(404)] * config.HTTP_4XX_MIN + [_req(200)] * 20)
        issue = _by_type(http_errors.detect(burst))["http_client_errors"]
        assert issue.severity == "info" and issue.evidence["count"] == config.HTTP_4XX_MIN

    def test_slow_responses(self):
        state = _state(http_requests=[_req(200, response_ms=1500.0), _req(200, response_ms=30.0),
                                      _req(200, response_ms=4000.0)])

        issue = _by_type(http_errors.detect(state))["http_slow"]

        assert issue.severity == "warning"
        assert issue.evidence["count"] == 2 and issue.evidence["max_ms"] == 4000.0
        assert issue.evidence["threshold_ms"] == config.HTTP_SLOW_THRESHOLD_S * 1000

    def test_unanswered_and_healthy_requests_raise_nothing(self):
        state = _state(http_requests=[_req(None, response_ms=None), _req(200), _req(304)])

        assert http_errors.detect(state) == []


def _txn(mac, types, server=None, requests=None):
    txn = DhcpTxnState(client_mac=mac, server=server, types=set(types))
    txn.requests = requests if requests is not None else sum(1 for t in types if t in (1, 3))
    return txn


class TestDhcpProblems:
    def test_nak_declined_and_unanswered(self):
        state = _state(dhcp_txns={
            ("1", "a"): _txn("aa:aa", {1, 2, 3, 5}, "10.0.0.1"),      # healthy DORA
            ("2", "b"): _txn("bb:bb", {3, 6}, "10.0.0.1"),            # NAK
            ("3", "c"): _txn("cc:cc", {1, 2, 3, 5, 4}, "10.0.0.1"),   # DECLINE after ACK
            ("4", "d"): _txn("dd:dd", {1}, requests=2),               # DISCOVER x2, no OFFER
            ("6", "f"): _txn("ff:ff", {1}),                           # one DISCOVER: not enough
            ("5", "e"): _txn("ee:ee", {8}),                           # INFORM only
        })

        issues = _by_type(dhcp_problems.detect(state))

        assert set(issues) == {"dhcp_nak", "dhcp_declined", "dhcp_no_response"}
        assert issues["dhcp_nak"].evidence == {"count": 1, "clients": ["bb:bb"],
                                               "servers": ["10.0.0.1"]}
        assert issues["dhcp_declined"].evidence["clients"] == ["cc:cc"]
        assert issues["dhcp_no_response"].evidence == {"count": 1, "clients": ["dd:dd"],
                                                       "servers": []}
        assert all(issue.severity == "warning" for issue in issues.values())

    def test_a_single_unanswered_broadcast_is_not_reported(self):
        """On a capture taken at another host the unicast OFFER/ACK is invisible."""
        state = _state(dhcp_txns={("1", "a"): _txn("aa:aa", {1}),
                                  ("2", "a"): _txn("aa:aa", {3})})
        issues = dhcp_problems.detect(state)
        assert [i.type for i in issues] == ["dhcp_no_response"]  # two attempts, same MAC
        assert issues[0].evidence["count"] == 1  # distinct clients, not transactions
        lone = _state(dhcp_txns={("1", "a"): _txn("aa:aa", {1})})
        assert dhcp_problems.detect(lone) == []

    def test_healthy_leases_raise_nothing(self):
        state = _state(dhcp_txns={("1", "a"): _txn("aa:aa", {1, 2, 3, 5}, "10.0.0.1")})

        assert dhcp_problems.detect(state) == []


def _tls(stream_id, negotiated, server="10.0.0.2", sni=None):
    return TlsSessionState(stream_id=stream_id, client="10.0.0.1", server=server,
                           negotiated=negotiated, sni=sni)


class TestTlsLegacy:
    def test_legacy_versions_are_grouped_by_server(self):
        state = _state(tls_sessions={
            0: _tls(0, "0x0301", sni="old.test"), 1: _tls(1, "0x0302"),
            2: _tls(2, "0x0303"), 3: _tls(3, None), 4: _tls(4, "0x0300", "10.0.0.7"),
        })

        issues = tls_legacy.detect(state)

        assert [i.type for i in issues] == ["tls_legacy_version", "tls_legacy_version"]
        first = next(i for i in issues if i.evidence["server"] == "10.0.0.2")
        assert first.severity == "warning"
        assert first.evidence == {"server": "10.0.0.2", "sessions": 2, "stream_ids": [0, 1],
                                  "versions": ["TLS 1.0", "TLS 1.1"], "server_names": ["old.test"]}
        assert "TLS 1.0" in first.detail and "TLS 1.0" in first.detail_en

    def test_modern_tls_raises_nothing(self):
        assert tls_legacy.detect(_state(tls_sessions={0: _tls(0, "0x0303")})) == []


def test_new_detectors_are_registered():
    assert {http_errors, dhcp_problems, tls_legacy} <= set(DETECTORS)


def test_engine_records_http_response_time_and_server_hello_version(monkeypatch):
    base = {"frame_len": ["100"], "ip_src": ["10.0.0.1"], "ip_dst": ["10.0.0.2"],
            "tcp_srcport": ["40000"], "tcp_dstport": ["80"]}
    back = dict(base, ip_src=["10.0.0.2"], ip_dst=["10.0.0.1"],
                tcp_srcport=["80"], tcp_dstport=["40000"])
    packets = [
        dict(base, frame_number=["1"], frame_time_epoch=["1.0"], tcp_stream=["0"],
             frame_protocols=["eth:ethertype:ip:tcp:http"], http_request_method=["GET"],
             http_host=["app.test"], http_request_uri=["/slow"]),
        dict(back, frame_number=["2"], frame_time_epoch=["3.5"], tcp_stream=["0"],
             frame_protocols=["eth:ethertype:ip:tcp:http"], http_response_code=["503"],
             http_time=["2.5"], tcp_len=["400"]),
        dict(base, frame_number=["3"], frame_time_epoch=["4.0"], tcp_stream=["1"],
             frame_protocols=["eth:ethertype:ip:tcp:tls"], tls_handshake_type=["1"],
             tls_handshake_version=["0x0303"], tls_record_version=["0x0301"]),
        dict(back, frame_number=["4"], frame_time_epoch=["4.1"], tcp_stream=["1"],
             frame_protocols=["eth:ethertype:ip:tcp:tls"], tls_handshake_type=["2"],
             tls_handshake_version=["0x0301"], tls_record_version=["0x0301"]),
    ]
    monkeypatch.setattr(engine, "iter_packets", lambda *a, **k: iter(packets))
    monkeypatch.setattr(engine, "tshark_version", lambda path: "test")

    result = analyze_pcap("tshark", "x.pcap", "x.pcap", 1)

    request = result.http_requests[0]
    assert request.status == 503 and request.response_ms == 2500.0
    types = {issue.type for issue in result.issues}
    assert {"http_server_errors", "http_slow", "tls_legacy_version"} <= types


@requires_tshark
def test_dhcp_fixture_raises_dhcp_findings(tmp_path):
    from tests.pcap_builder import build_dhcp_packets, write_pcap

    path = tmp_path / "dhcp.pcap"
    write_pcap(str(path), build_dhcp_packets())

    types = {i.type for i in analyze_pcap(find_tshark(), str(path), "dhcp.pcap",
                                           path.stat().st_size).issues}

    assert {"dhcp_nak", "dhcp_no_response"} <= types


def test_one_way_capture_also_downgrades_dhcp_no_response():
    from app.analysis.quality import apply_quality_caveats
    from app.models import CaptureQuality, Issue, QualityNote

    issue = Issue(id="d", type="dhcp_no_response", severity="warning", title="t",
                  detail="d", title_en="t", detail_en="d", evidence={})
    one_way = CaptureQuality(verdict="poor", notes=[QualityNote(
        code="one_way", severity="warning", title="t", detail="d", title_en="t", detail_en="d")])

    assert apply_quality_caveats([issue], one_way)[0].severity == "info"


def test_http_time_to_first_byte_not_whole_download(monkeypatch):
    """A fast server sending a large body slowly is not an application problem."""
    req = {"frame_len": ["100"], "ip_src": ["10.0.0.1"], "ip_dst": ["10.0.0.2"],
           "tcp_srcport": ["40000"], "tcp_dstport": ["80"], "tcp_stream": ["0"],
           "frame_protocols": ["eth:ethertype:ip:tcp:http"]}
    resp = dict(req, ip_src=["10.0.0.2"], ip_dst=["10.0.0.1"], tcp_srcport=["80"],
                tcp_dstport=["40000"], frame_protocols=["eth:ethertype:ip:tcp"])
    packets = [
        dict(req, frame_number=["1"], frame_time_epoch=["1.0"], http_request_method=["GET"],
             http_host=["app.test"], http_request_uri=["/big"]),
        dict(resp, frame_number=["2"], frame_time_epoch=["1.02"], tcp_len=["1400"]),
        dict(resp, frame_number=["3"], frame_time_epoch=["2.5"], tcp_len=["1400"]),
        dict(resp, frame_number=["4"], frame_time_epoch=["4.0"], tcp_len=["200"],
             frame_protocols=["eth:ethertype:ip:tcp:http"], http_response_code=["200"],
             http_time=["3.0"]),
    ]
    monkeypatch.setattr(engine, "iter_packets", lambda *a, **k: iter(packets))
    monkeypatch.setattr(engine, "tshark_version", lambda path: "test")

    result = analyze_pcap("tshark", "x.pcap", "x.pcap", 1)

    assert result.http_requests[0].response_ms == 20.0
    assert "http_slow" not in {issue.type for issue in result.issues}


def test_demo_next_steps_cover_the_new_types_in_both_languages():
    from app.llm.demo import _NEXT_STEP_BY_TYPE, _NEXT_STEP_BY_TYPE_EN

    new = {"http_server_errors", "http_client_errors", "http_slow", "dhcp_nak",
           "dhcp_declined", "dhcp_no_response", "tls_legacy_version"}
    assert new <= set(_NEXT_STEP_BY_TYPE) and new <= set(_NEXT_STEP_BY_TYPE_EN)


def test_fragmentation_ratio_ignores_capture_duplicates():
    from app.detectors import ip_fragmentation

    # 6 fragments among 100 real packets, the capture holding each frame twice.
    state = _state(packets=200, duplicate_frames=100, frag_packets=6)

    issues = ip_fragmentation.detect(state)

    assert [i.type for i in issues] == ["ip_fragmentation_high"]
    assert issues[0].evidence["fragment_pct"] == 6.0
