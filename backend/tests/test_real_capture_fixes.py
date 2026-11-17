"""Fixes found by running the engine on public captures (wiki.wireshark.org
SampleCaptures). The captures themselves are not in the repository (no
licence stated); each case is reproduced here with synthetic data."""
from __future__ import annotations

from app import config
from app.analysis import engine
from app.analysis.engine import analyze_pcap
from app.detectors import tcp_retransmissions, tcp_syn_rst
from tests.test_detectors import _conv, _state


def _run(monkeypatch, packets):
    monkeypatch.setattr(engine, "iter_packets", lambda *a, **k: iter(packets))
    monkeypatch.setattr(engine, "tshark_version", lambda path: "test")
    return analyze_pcap("tshark", "x.pcap", "x.pcap", 1)


def _dns(number, ts, src, dst, txid, response, name=None, rcode="0"):
    layers = {"frame_number": [str(number)], "frame_time_epoch": [str(ts)],
              "frame_len": ["80"], "frame_protocols": ["eth:ethertype:ip:udp:dns"],
              "ip_src": [src], "ip_dst": [dst], "udp_stream": ["0"],
              "udp_srcport": ["53" if response else "32768"],
              "udp_dstport": ["32768" if response else "53"],
              "dns_id": [txid], "dns_flags_response": ["True" if response else "False"]}
    if name is not None:
        layers["dns_qry_name"] = [name]
    if response:
        layers["dns_flags_rcode"] = [rcode]
    return layers


# dhcp-and-dyndns.pcap.gz: DNS UPDATE responses do not repeat the zone name.
def test_dns_response_without_question_name_still_answers_the_query(monkeypatch):
    c, s = "10.20.20.4", "10.20.20.1"
    result = _run(monkeypatch, [
        _dns(1, 1.000, c, s, "0x21eb", False, "far-far-away"),
        _dns(2, 1.080, s, c, "0x21eb", True, None),
    ])

    assert [i.type for i in result.issues] == []
    assert [q.status for q in result.dns_queries] == ["ok"]
    assert result.dns_queries[0].name == "far-far-away"


# dns-icmp.pcapng.gz: the client repeats a query after 5 s with the same id.
def test_a_retried_query_is_one_slow_lookup_not_an_unanswered_one(monkeypatch):
    c, s = "192.168.43.9", "192.168.43.1"
    name = "8.8.8.8.in-addr.arpa"
    result = _run(monkeypatch, [
        _dns(1, 0.000, c, s, "0x528e", False, name),
        _dns(2, 5.001, c, s, "0x528e", False, name),
        _dns(3, 5.007, s, c, "0x528e", True, name),
    ])

    types = [i.type for i in result.issues]
    assert "dns_unanswered" not in types
    assert types == ["dns_slow"]  # the user waited 5 s
    assert [q.status for q in result.dns_queries] == ["slow"]
    assert result.dns_queries[0].latency_ms == 5007.0


def test_different_names_sharing_an_id_are_still_matched_separately(monkeypatch):
    c, s = "10.0.0.1", "10.0.0.53"
    result = _run(monkeypatch, [
        _dns(1, 0.0, c, s, "0x0001", False, "a.example"),
        _dns(2, 0.1, c, s, "0x0001", False, "b.example"),
        _dns(3, 0.2, s, c, "0x0001", True, "b.example"),
    ])

    statuses = {q.name: q.status for q in result.dns_queries}
    assert statuses == {"a.example": "unanswered", "b.example": "ok"}


# http.cap: one spurious retransmission in a 7-packet conversation was "critical".
class TestRetransmissionsFromRealCaptures:
    def test_spurious_retransmissions_are_not_counted_as_loss(self):
        conv = _conv(packets=7, retransmissions=0, spurious_retransmissions=1)
        assert tcp_retransmissions.detect(_state(tcp_convs={0: conv})) == []

    def test_a_single_retransmission_is_not_reported(self):
        conv = _conv(packets=7, retransmissions=1)
        assert tcp_retransmissions.detect(_state(tcp_convs={0: conv})) == []

    def test_two_retransmissions_still_are(self):
        conv = _conv(packets=8, retransmissions=2)
        issues = tcp_retransmissions.detect(_state(tcp_convs={0: conv}))
        assert [i.severity for i in issues] == ["critical"]


def test_engine_counts_spurious_retransmissions_apart(monkeypatch):
    base = {"frame_len": ["1500"], "frame_protocols": ["eth:ethertype:ip:tcp"],
            "tcp_stream": ["0"], "ip_src": ["10.0.0.2"], "ip_dst": ["10.0.0.1"],
            "tcp_srcport": ["80"], "tcp_dstport": ["40000"], "tcp_len": ["1430"]}
    result = _run(monkeypatch, [
        dict(base, frame_number=["1"], frame_time_epoch=["1.0"]),
        dict(base, frame_number=["2"], frame_time_epoch=["2.0"],
             tcp_analysis_spurious_retransmission=[""]),
    ])

    conv = result.conversations.tcp[0]
    assert conv.retransmissions == 0 and conv.spurious_retransmissions == 1


# dhcpfo.pcapng: 17 SYNs to the same closed port gave 15 separate criticals.
class TestSynRstGrouping:
    def _refused(self, stream_id, dst="192.168.7.71", port=647, t=0.0):
        return _conv(stream_id=stream_id, src="192.168.7.70", src_port=53812,
                     dst=dst, dst_port=port, syn_ts=t, rst_ts=t + 0.0002)

    def test_refusals_to_the_same_port_are_one_finding(self):
        convs = {i: self._refused(i, t=i * 0.5) for i in range(1, 16)}

        issues = tcp_syn_rst.detect(_state(tcp_convs=convs))

        assert len(issues) == 1
        issue = issues[0]
        assert issue.severity == "critical"
        assert issue.evidence["attempts"] == 15
        assert issue.evidence["stream_ids"] == list(range(1, 11))  # first ten
        assert issue.evidence["dst"] == "192.168.7.71" and issue.evidence["dst_port"] == 647
        assert "15" in issue.detail and "15" in issue.detail_en

    def test_different_destinations_stay_separate(self):
        convs = {1: self._refused(1), 2: self._refused(2, port=648),
                 3: self._refused(3, dst="192.168.7.72")}

        assert len(tcp_syn_rst.detect(_state(tcp_convs=convs))) == 3

    def test_a_single_refusal_keeps_its_stream(self):
        issues = tcp_syn_rst.detect(_state(tcp_convs={4: self._refused(4)}))

        assert issues[0].evidence["stream_id"] == 4
        assert issues[0].id == "tcp-syn-rst-4"
