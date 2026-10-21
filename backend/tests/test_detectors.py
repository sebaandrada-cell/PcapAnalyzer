"""Unit tests: one per detector, using synthetic CaptureState fixtures
(no tshark needed)."""
from __future__ import annotations

import pytest

from app.analysis.engine import (
    CaptureState,
    ConvState,
    DnsError,
    DnsExchange,
    DnsQuery,
    FragGroup,
    IcmpFragEvent,
    TlsAlert,
    TunnelState,
)
from app.detectors import (
    build_issues,
    dns_errors,
    dns_problems,
    duplicate_ip,
    ip_fragmentation,
    mtu_mss,
    tcp_handshake,
    tcp_retransmissions,
    tcp_syn_rst,
    tcp_zero_window,
    tls_alerts,
    vpn_tunnels,
)


def _conv(**kwargs) -> ConvState:
    base = dict(stream_id=0, src="10.0.0.1", src_port=1234,
                dst="10.0.0.2", dst_port=80)
    base.update(kwargs)
    return ConvState(**base)


def _state(**kwargs) -> CaptureState:
    state = CaptureState()
    for key, value in kwargs.items():
        setattr(state, key, value)
    return state


class TestTcpRetransmissions:
    def test_critical_above_2_pct(self):
        state = _state(tcp_convs={0: _conv(packets=100, retransmissions=3)})
        issues = tcp_retransmissions.detect(state)
        assert len(issues) == 1
        assert issues[0].severity == "critical"
        assert issues[0].evidence["retransmission_pct"] == 3.0

    def test_warning_between_1_and_2_pct(self):
        state = _state(tcp_convs={0: _conv(packets=200, retransmissions=3)})
        assert tcp_retransmissions.detect(state)[0].severity == "warning"

    def test_ignores_below_threshold_and_tiny_conversations(self):
        state = _state(tcp_convs={
            0: _conv(packets=1000, retransmissions=1),       # 0.1% < warn
            1: _conv(stream_id=1, packets=3, retransmissions=3),  # < min packets
        })
        assert tcp_retransmissions.detect(state) == []


class TestTcpSynRst:
    def test_syn_then_immediate_rst_is_critical(self):
        conv = _conv(syn_ts=10.0, rst_ts=10.005, synack_seen=False)
        issues = tcp_syn_rst.detect(_state(tcp_convs={0: conv}))
        assert len(issues) == 1
        assert issues[0].severity == "critical"
        assert issues[0].evidence["syn_to_rst_ms"] == pytest.approx(5.0)

    def test_no_issue_when_synack_was_seen(self):
        conv = _conv(syn_ts=10.0, rst_ts=10.005, synack_seen=True)
        assert tcp_syn_rst.detect(_state(tcp_convs={0: conv})) == []

    def test_no_issue_when_rst_is_late(self):
        conv = _conv(syn_ts=10.0, rst_ts=25.0, synack_seen=False)
        assert tcp_syn_rst.detect(_state(tcp_convs={0: conv})) == []


class TestTcpZeroWindow:
    def test_zero_window_events_flagged(self):
        state = _state(tcp_convs={0: _conv(packets=10, zero_window_events=3)})
        issues = tcp_zero_window.detect(state)
        assert len(issues) == 1
        assert issues[0].severity == "warning"
        assert issues[0].evidence["zero_window_events"] == 3

    def test_single_event_is_not_called_sustained(self):
        state = _state(tcp_convs={0: _conv(packets=10, zero_window_events=1)})
        assert tcp_zero_window.detect(state) == []

    def test_silent_without_events(self):
        state = _state(tcp_convs={0: _conv(packets=10)})
        assert tcp_zero_window.detect(state) == []


class TestDnsProblems:
    def test_unanswered_query(self):
        query = DnsQuery(ts=1.0, name="dead.example.com",
                         server="10.0.0.53", client="10.0.0.1")
        issues = dns_problems.detect(_state(dns_pending={("0", "1", "x"): [query]}))
        assert len(issues) == 1
        assert issues[0].type == "dns_unanswered"
        assert issues[0].evidence["query_name"] == "dead.example.com"

    def test_slow_response_above_500ms(self):
        exchange = DnsExchange(name="slow.example.com", server="10.0.0.53",
                               client="10.0.0.1", latency_s=0.7)
        issues = dns_problems.detect(_state(dns_answered=[exchange]))
        assert len(issues) == 1
        assert issues[0].type == "dns_slow"
        assert issues[0].evidence["latency_ms"] == pytest.approx(700.0)

    def test_fast_response_is_fine(self):
        exchange = DnsExchange(name="fast.example.com", server="10.0.0.53",
                               client="10.0.0.1", latency_s=0.02)
        assert dns_problems.detect(_state(dns_answered=[exchange])) == []


class TestTlsAlerts:
    def _alert(self, desc: int, level: int = 2) -> TlsAlert:
        return TlsAlert(ts=1.0, src="10.0.0.2", dst="10.0.0.1",
                        level=level, desc=desc, stream_id=0)

    def test_handshake_failure(self):
        issues = tls_alerts.detect(_state(tls_alerts=[self._alert(40)]))
        assert len(issues) == 1
        assert issues[0].type == "tls_handshake_failure"
        assert issues[0].severity == "warning"

    def test_other_fatal_alert(self):
        issues = tls_alerts.detect(_state(tls_alerts=[self._alert(48)]))
        assert issues[0].type == "tls_alert"
        assert "unknown_ca" in issues[0].title

    def test_close_notify_ignored(self):
        assert tls_alerts.detect(_state(tls_alerts=[self._alert(0, level=1)])) == []


class TestMtuMss:
    def test_low_mss_is_flagged(self):
        state = _state(tcp_convs={0: _conv(mss_client=1240, mss_server=1460)})
        issues = mtu_mss.detect(state)
        assert [i.type for i in issues] == ["mss_low"]
        assert issues[0].severity == "info"

    def test_normal_mss_is_silent(self):
        state = _state(tcp_convs={0: _conv(mss_client=1460, mss_server=1460)})
        assert mtu_mss.detect(state) == []

    def test_icmp_frag_needed(self):
        event = IcmpFragEvent(ts=1.0, src="10.0.0.254", dst="10.0.0.5", mtu=1400)
        issues = mtu_mss.detect(_state(icmp_frag_events=[event]))
        assert [i.type for i in issues] == ["icmp_frag_needed"]
        assert issues[0].evidence["path_mtu"] == 1400

    def test_pmtud_blackhole_without_icmp(self):
        conv = _conv(mss_client=1460, mss_server=1460, full_size_retrans=3)
        issues = mtu_mss.detect(_state(tcp_convs={0: conv}))
        assert "pmtud_blackhole" in [i.type for i in issues]

    def test_pmtud_suppressed_when_icmp_reached_peer(self):
        conv = _conv(mss_client=1460, mss_server=1460, full_size_retrans=3)
        event = IcmpFragEvent(ts=1.0, src="10.0.0.254", dst=conv.src, mtu=1400)
        issues = mtu_mss.detect(_state(tcp_convs={0: conv},
                                       icmp_frag_events=[event]))
        assert "pmtud_blackhole" not in [i.type for i in issues]


class TestIpFragmentation:
    def test_high_fragmentation_pct(self):
        state = _state(packets=100, frag_packets=10,
                       frag_groups={("a", "b", "0x1", "17"): FragGroup(packets=10, has_last=True)})
        issues = ip_fragmentation.detect(state)
        assert [i.type for i in issues] == ["ip_fragmentation_high"]
        assert issues[0].evidence["fragment_pct"] == 10.0

    def test_incomplete_datagram_is_critical(self):
        state = _state(packets=1000, frag_packets=2,
                       frag_groups={("a", "b", "0x2", "17"): FragGroup(
                           packets=2, has_first=True,
                       )})
        issues = ip_fragmentation.detect(state)
        assert [i.type for i in issues] == ["ip_fragments_incomplete"]
        assert issues[0].severity == "warning"
        assert issues[0].evidence["capture_boundary_possible"] is True

    def test_trailing_fragment_without_first_fragment_is_not_called_incomplete(self):
        state = _state(packets=1000, frag_packets=1,
                       frag_groups={("a", "b", "0x2", "17"): FragGroup(
                           packets=1, has_last=True,
                       )})
        assert ip_fragmentation.detect(state) == []

    def test_complete_low_rate_is_silent(self):
        state = _state(packets=1000, frag_packets=2,
                       frag_groups={("a", "b", "0x3", "17"): FragGroup(packets=2, has_last=True)})
        assert ip_fragmentation.detect(state) == []


class TestVpnTunnels:
    @staticmethod
    def _tunnels(*tunnels):
        return {(t.type, tuple(sorted((t.peer_a, t.peer_b)))): t for t in tunnels}

    def test_ike_no_response(self):
        state = _state(tunnels=self._tunnels(
            TunnelState("ike", "10.0.0.1", "10.0.0.6", packets_a2b=3)))
        issues = vpn_tunnels.detect(state)
        assert [i.type for i in issues] == ["ike_no_response"]
        assert issues[0].severity == "warning"

    def test_ike_incomplete_without_esp(self):
        state = _state(tunnels=self._tunnels(
            TunnelState("ike", "10.0.0.1", "10.0.0.7", packets_a2b=1, packets_b2a=1)))
        issues = vpn_tunnels.detect(state)
        assert [i.type for i in issues] == ["ike_handshake_incomplete"]

    def test_ike_with_esp_is_healthy(self):
        state = _state(tunnels=self._tunnels(
            TunnelState("ike", "10.0.0.1", "10.0.0.7", packets_a2b=2, packets_b2a=2),
            TunnelState("esp", "10.0.0.1", "10.0.0.7", packets_a2b=10, packets_b2a=9)))
        assert vpn_tunnels.detect(state) == []

    def test_esp_one_way(self):
        state = _state(tunnels=self._tunnels(
            TunnelState("esp", "10.0.0.1", "10.0.0.6", packets_a2b=4)))
        issues = vpn_tunnels.detect(state)
        assert [i.type for i in issues] == ["esp_one_way"]
        assert issues[0].evidence["silent_peer"] == "10.0.0.6"


class TestTcpHandshake:
    def test_slow_handshake(self):
        conv = _conv(syn_ts=1.0, synack_ts=1.6, synack_seen=True)
        issues = tcp_handshake.detect(_state(tcp_convs={0: conv}))
        assert [i.type for i in issues] == ["tcp_slow_handshake"]
        assert issues[0].evidence["handshake_rtt_ms"] == pytest.approx(600.0)

    def test_fast_handshake_is_silent(self):
        conv = _conv(syn_ts=1.0, synack_ts=1.02, synack_seen=True)
        assert tcp_handshake.detect(_state(tcp_convs={0: conv})) == []


class TestDnsErrors:
    def test_servfail_flagged_individually(self):
        errors = [DnsError(rcode=2, name="fail.example.com",
                           server="10.0.0.53", client="10.0.0.1")]
        issues = dns_errors.detect(_state(dns_errors=errors))
        assert [i.type for i in issues] == ["dns_servfail"]

    def test_nxdomain_needs_a_burst(self):
        errors = [DnsError(rcode=3, name="typo%d.example.com" % i,
                           server="10.0.0.53", client="10.0.0.1")
                  for i in range(3)]
        issues = dns_errors.detect(_state(dns_errors=errors))
        assert [i.type for i in issues] == ["dns_nxdomain"]
        assert issues[0].evidence["count"] == 3

    def test_single_nxdomain_is_silent(self):
        errors = [DnsError(rcode=3, name="typo.example.com",
                           server="10.0.0.53", client="10.0.0.1")]
        assert dns_errors.detect(_state(dns_errors=errors)) == []


class TestDuplicateIp:
    def test_two_macs_same_ip_is_a_warning_with_context(self):
        state = _state(arp_map={"10.0.0.99": {"02:00:00:00:00:0a": 1,
                                              "02:00:00:00:00:0b": 1}})
        issues = duplicate_ip.detect(state)
        assert [i.type for i in issues] == ["ip_duplicate"]
        assert issues[0].severity == "warning"
        assert issues[0].evidence["proxy_arp_or_segment_boundary_possible"] is True

    def test_single_mac_is_silent(self):
        state = _state(arp_map={"10.0.0.99": {"02:00:00:00:00:0a": 5}})
        assert duplicate_ip.detect(state) == []


def test_build_issues_sorts_by_severity():
    state = _state(
        tcp_convs={
            0: _conv(packets=10, zero_window_events=3),               # warning
            1: _conv(stream_id=1, syn_ts=1.0, rst_ts=1.01),           # critical
        }
    )
    severities = [issue.severity for issue in build_issues(state)]
    assert severities == ["critical", "warning"]


def test_every_issue_has_english_text(sample_pcap):
    """Each detector must supply title_en/detail_en alongside the Spanish text."""
    from app.analysis.engine import analyze_pcap
    from app.tshark import find_tshark

    result = analyze_pcap(find_tshark(), str(sample_pcap), "sample.pcap",
                          sample_pcap.stat().st_size)
    assert result.issues
    for issue in result.issues:
        assert issue.title_en and issue.detail_en, issue.type
        assert issue.title_en != issue.title, issue.type
