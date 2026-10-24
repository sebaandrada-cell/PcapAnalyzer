"""TCP-analysis flags, ICMP errors, expert info and name resolution.

Integration tests run tshark on a dedicated synthetic capture
(``build_troubleshooting_packets``) so the main sample's counts stay put.
Exact equality is used only where the outcome follows from the TCP rules
(duplicate ACKs, window full, reset); Wireshark's reordering heuristic depends on
connection state, so those assertions use ``>=``.
"""
from __future__ import annotations

import re

import pytest

from app import config
from app.analysis.engine import IcmpErrorGroup, analyze_pcap
from app.detectors import (
    icmp_ttl_exceeded,
    icmp_unreachable,
    tcp_dup_acks,
    tcp_lost_segments,
    tcp_out_of_order,
    tcp_resets,
    tcp_window_full,
)
from app.tshark import find_tshark
from tests.pcap_builder import build_troubleshooting_packets, write_pcap
from tests.test_detectors import _conv, _state

requires_tshark = pytest.mark.skipif(find_tshark() is None, reason="tshark no está instalado")


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    path = tmp_path_factory.mktemp("troubleshooting") / "ts.pcap"
    write_pcap(str(path), build_troubleshooting_packets())
    return analyze_pcap(find_tshark(), str(path), "ts.pcap", path.stat().st_size)


@pytest.fixture(scope="module")
def convs(result):
    return {c.dst_port: c for c in result.conversations.tcp}


# ── engine: per-conversation counters ───────────────────────────────────────
@requires_tshark
class TestEngineCounters:
    def test_lost_segment_then_dup_acks_then_fast_retransmit(self, convs):
        conv = convs[5001]
        assert conv.dup_acks == 5
        assert conv.lost_segments == 1
        assert conv.retransmissions >= 1  # the fast retransmission

    def test_reordering_is_counted(self, convs):
        conv = convs[5002]
        assert conv.out_of_order >= 1
        assert conv.lost_segments >= 1

    def test_window_full(self, convs):
        assert convs[5003].window_full == 4

    def test_reset_after_the_handshake(self, convs):
        assert convs[5004].resets_midstream == 1
        assert convs[5001].resets_midstream == 0

    def test_ack_rtt_statistics(self, convs):
        conv = convs[5001]
        assert conv.rtt_avg_ms is not None and conv.rtt_avg_ms > 0
        assert conv.rtt_max_ms >= conv.rtt_avg_ms


# ── engine: packet rows ─────────────────────────────────────────────────────
@requires_tshark
class TestPacketRows:
    def test_dup_ack_row_carries_tcp_fields(self, result):
        row = next(r for r in result.packet_list.rows if "dup_ack" in r.analysis)
        assert row.sport == 5001 and row.dport == 40001
        assert row.tcp_flags == ["ACK"]
        assert row.ack == 101 and row.win == 65535 and row.payload == 0
        assert row.ttl == 64
        assert row.expert in ("note", "warning", "error", "chat")
        assert row.expert_message

    def test_syn_row_lists_flags(self, result):
        syn = next(r for r in result.packet_list.rows if r.tcp_flags == ["SYN"])
        assert syn.stream is not None and syn.sport and syn.dport

    def test_icmp_error_rows_do_not_inherit_the_quoted_tcp_fields(self, result):
        icmp_rows = [r for r in result.packet_list.rows if r.protocol.upper().startswith("ICMP")]
        assert icmp_rows
        assert all(r.tcp_flags == [] and r.analysis == [] and r.seq is None for r in icmp_rows)


# ── engine: expert information ─────────────────────────────────────────────
@requires_tshark
class TestExpertInfo:
    def test_sorted_by_severity_then_count(self, result):
        rank = {"error": 3, "warning": 2, "note": 1, "chat": 0}
        keys = [(-rank[e.severity], -e.count) for e in result.expert_info]
        assert keys == sorted(keys)

    def test_sequence_warnings_are_present(self, result):
        sequence = [e for e in result.expert_info if e.group == "Sequence" and e.severity == "warning"]
        assert sequence and sum(e.count for e in sequence) >= 4

    def test_numbered_messages_are_merged(self, result):
        # "Duplicate ACK (#1)", "(#2)"... must collapse into one line
        assert not any(re.search(r"\(#\d+\)", e.summary) for e in result.expert_info)
        dup = [e for e in result.expert_info if e.summary.startswith("Duplicate ACK")]
        assert len(dup) == 1 and dup[0].count >= 5

    def test_first_packet_points_at_a_real_packet(self, result):
        assert all(1 <= e.first_packet <= result.summary.packets for e in result.expert_info)


# ── engine: name resolution ────────────────────────────────────────────────
@requires_tshark
def test_dns_answers_populate_resolved_names(result):
    assert [(r.address, r.name) for r in result.resolved_names] == [
        ("10.1.0.2", "intranet.example.com")
    ]


# ── end to end: the issues a person would read ─────────────────────────────
@requires_tshark
class TestIssuesOnTheCapture:
    def test_every_new_detector_fires_except_resets(self, result):
        types = {issue.type for issue in result.issues}
        assert {"tcp_dup_acks", "tcp_lost_segments", "tcp_window_full",
                "icmp_unreachable", "icmp_ttl_exceeded"} <= types
        # a single reset conversation is below the threshold of 3
        assert "tcp_resets" not in types

    def test_icmp_unreachable_is_split_by_reporter_and_code(self, result):
        found = {(i.evidence["reporter"], i.evidence["code"]): i
                 for i in result.issues if i.type == "icmp_unreachable"}
        assert set(found) == {("10.1.0.2", 3), ("10.1.0.254", 1), ("10.1.0.253", 13)}
        admin = found[("10.1.0.253", 13)]
        assert admin.evidence["count"] == 2
        assert admin.evidence["targets"] == ["10.1.0.88"]  # the *quoted* destination
        assert admin.evidence["victims"] == ["10.1.0.1"]
        assert found[("10.1.0.254", 1)].evidence["targets"] == ["10.1.0.77"]

    def test_ttl_exceeded(self, result):
        issue = next(i for i in result.issues if i.type == "icmp_ttl_exceeded")
        assert issue.evidence["reporter"] == "10.1.0.254"
        assert issue.evidence["count"] == 6

    def test_stream_ids_in_evidence_point_at_real_conversations(self, result):
        streams = {c.stream_id for c in result.conversations.tcp}
        for issue in result.issues:
            if issue.type.startswith("tcp_") and "stream_id" in issue.evidence:
                assert issue.evidence["stream_id"] in streams

    def test_main_sample_is_unchanged_by_the_new_detectors(self, sample_pcap):
        main = analyze_pcap(find_tshark(), str(sample_pcap), "sample.pcap", 0)
        assert len(main.issues) == 18
        new_types = {"tcp_dup_acks", "tcp_lost_segments", "tcp_out_of_order",
                     "tcp_window_full", "tcp_resets", "icmp_unreachable",
                     "icmp_ttl_exceeded"}
        assert not new_types & {i.type for i in main.issues}


# ── unit tests: thresholds and severities (synthetic state, no tshark) ─────
class TestTcpDetectorThresholds:
    def test_dup_acks_needs_the_threshold(self):
        below = _state(tcp_convs={0: _conv(packets=50, dup_acks=config.TCP_DUP_ACK_MIN - 1)})
        assert tcp_dup_acks.detect(below) == []
        at = _state(tcp_convs={0: _conv(packets=50, dup_acks=config.TCP_DUP_ACK_MIN)})
        issues = tcp_dup_acks.detect(at)
        assert [i.type for i in issues] == ["tcp_dup_acks"]
        assert issues[0].severity == "warning"

    def test_out_of_order_is_info_unless_it_is_a_big_share(self):
        small = _state(tcp_convs={0: _conv(packets=1000, out_of_order=config.TCP_OUT_OF_ORDER_MIN)})
        assert tcp_out_of_order.detect(small)[0].severity == "info"
        big = _state(tcp_convs={0: _conv(packets=40, out_of_order=config.TCP_OUT_OF_ORDER_MIN)})
        assert tcp_out_of_order.detect(big)[0].severity == "warning"
        assert tcp_out_of_order.detect(_state(tcp_convs={0: _conv(packets=40, out_of_order=1)})) == []

    def test_lost_segments_is_only_a_warning_when_loss_is_confirmed(self):
        bare = _state(tcp_convs={0: _conv(packets=20, lost_segments=2)})
        issue = tcp_lost_segments.detect(bare)[0]
        assert issue.severity == "info" and issue.evidence["confirmed_loss"] is False
        confirmed = _state(tcp_convs={0: _conv(packets=20, lost_segments=2, dup_acks=3)})
        issue = tcp_lost_segments.detect(confirmed)[0]
        assert issue.severity == "warning" and issue.evidence["confirmed_loss"] is True
        assert tcp_lost_segments.detect(_state(tcp_convs={0: _conv(packets=20)})) == []

    def test_window_full_threshold(self):
        assert tcp_window_full.detect(
            _state(tcp_convs={0: _conv(window_full=config.TCP_WINDOW_FULL_MIN - 1)})) == []
        issues = tcp_window_full.detect(
            _state(tcp_convs={0: _conv(window_full=config.TCP_WINDOW_FULL_MIN)}))
        assert [i.severity for i in issues] == ["warning"]

    def test_resets_are_aggregated_and_scale_with_the_count(self):
        def state(n):
            return _state(tcp_convs={i: _conv(stream_id=i, resets_midstream=1) for i in range(n)})
        assert tcp_resets.detect(state(config.TCP_RESET_MIN_CONVS - 1)) == []
        few = tcp_resets.detect(state(config.TCP_RESET_MIN_CONVS))
        assert len(few) == 1 and few[0].severity == "info"
        assert few[0].evidence["conversations"] == config.TCP_RESET_MIN_CONVS
        assert tcp_resets.detect(state(12))[0].severity == "warning"


class TestIcmpDetectors:
    @staticmethod
    def _group(family=4, icmp_type=3, code=3, count=1, reporter="10.0.0.2"):
        group = IcmpErrorGroup(family=family, reporter=reporter, icmp_type=icmp_type,
                               code=code, count=count, targets=["10.0.0.9"],
                               victims=["10.0.0.1"])
        return _state(icmp_errors={(family, reporter, icmp_type, code): group})

    def test_port_admin_and_route_get_different_advice(self):
        port = icmp_unreachable.detect(self._group(code=3))[0]
        admin = icmp_unreachable.detect(self._group(code=13))[0]
        route = icmp_unreachable.detect(self._group(code=1))[0]
        assert "escuchando" in port.detail and "listening" in port.detail_en
        assert "firewall" in admin.detail.lower() and "firewall" in admin.detail_en.lower()
        assert "ruta" in route.detail and "route" in route.detail_en

    def test_icmpv6_codes_use_their_own_table(self):
        issue = icmp_unreachable.detect(self._group(family=6, icmp_type=1, code=4))[0]
        assert "puerto inalcanzable" in issue.title and "listening" in issue.detail_en

    def test_unknown_code_does_not_crash(self):
        issue = icmp_unreachable.detect(self._group(code=99))[0]
        assert "99" in issue.title

    def test_unreachable_ignores_ttl_exceeded_and_vice_versa(self):
        ttl = self._group(icmp_type=11, code=0, count=10, reporter="10.0.0.254")
        assert icmp_unreachable.detect(ttl) == []
        assert len(icmp_ttl_exceeded.detect(ttl)) == 1
        assert icmp_ttl_exceeded.detect(self._group(code=3)) == []

    def test_ttl_exceeded_needs_a_pattern(self):
        few = self._group(icmp_type=11, code=0, count=config.ICMP_TTL_EXCEEDED_MIN - 1)
        assert icmp_ttl_exceeded.detect(few) == []

    def test_reassembly_timeout_has_its_own_wording(self):
        issue = icmp_ttl_exceeded.detect(
            self._group(icmp_type=11, code=1, count=config.ICMP_TTL_EXCEEDED_MIN))[0]
        assert "reensamblado" in issue.title and "reassembly" in issue.title_en.lower()


def test_every_new_detector_provides_english_text():
    states = [
        (tcp_dup_acks, _state(tcp_convs={0: _conv(packets=50, dup_acks=9)})),
        (tcp_out_of_order, _state(tcp_convs={0: _conv(packets=20, out_of_order=9)})),
        (tcp_lost_segments, _state(tcp_convs={0: _conv(packets=20, lost_segments=3)})),
        (tcp_window_full, _state(tcp_convs={0: _conv(window_full=9)})),
        (tcp_resets, _state(tcp_convs={i: _conv(stream_id=i, resets_midstream=1) for i in range(4)})),
        (icmp_unreachable, TestIcmpDetectors._group(code=3)),
        (icmp_ttl_exceeded, TestIcmpDetectors._group(icmp_type=11, code=0, count=9)),
    ]
    for module, state in states:
        issues = module.detect(state)
        assert issues, module.__name__
        for issue in issues:
            assert issue.title_en and issue.detail_en, issue.type
            assert issue.title_en != issue.title
