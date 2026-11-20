"""Tunnel tracking and health: Teredo/GRE/L2TP, handshakes, renegotiation, table."""
from __future__ import annotations

from app import config
from app.analysis.engine import CaptureState, _build_tunnels, _consume_packet
from app.detectors import vpn_tunnels

A, B = "10.0.0.1", "203.0.113.9"


def _pkt(ts: float, src: str, dst: str, chain: str, length: int = 100, **extra) -> dict:
    layers = {
        "frame_time_epoch": [str(ts)],
        "frame_len": [str(length)],
        "frame_protocols": [chain],
        "ip_src": [src], "ip_dst": [dst],
    }
    layers.update({key: [value] for key, value in extra.items()})
    return layers


def _wg(ts, src, dst, wg_type):
    return _pkt(ts, src, dst, "eth:ethertype:ip:udp:wg", wg_type=str(wg_type))


def _ike(ts, src, dst, response):
    return _pkt(ts, src, dst, "eth:ethertype:ip:udp:isakmp",
                isakmp_exchangetype="34",
                isakmp_rspi="f05534eef373dc1b" if response else "0000000000000000",
                isakmp_flag_r="True" if response else "False")


def _types(state):
    return [issue.type for issue in vpn_tunnels.detect(state)]


def test_teredo_is_tracked_as_a_tunnel():
    state = CaptureState()
    _consume_packet(state, _pkt(1.0, A, B, "eth:ethertype:ip:udp:teredo:ipv6:icmpv6"))
    _consume_packet(state, _pkt(1.1, B, A, "eth:ethertype:ip:udp:teredo:ipv6:icmpv6"))
    assert [t.type for t in _build_tunnels(state)] == ["teredo"]


def test_tunnel_table_has_duration_direction_bytes_idle_and_handshakes():
    state = CaptureState()
    _consume_packet(state, _wg(100.0, A, B, 1))
    _consume_packet(state, _wg(100.1, B, A, 2))
    _consume_packet(state, _pkt(101.0, A, B, "eth:ethertype:ip:udp:wg", length=300, wg_type="4"))
    _consume_packet(state, _pkt(131.0, B, A, "eth:ethertype:ip:udp:wg", length=500, wg_type="4"))
    tunnel = _build_tunnels(state)[0]
    assert tunnel.type == "wireguard"
    assert tunnel.duration_s == 31.0
    assert tunnel.bytes_a_to_b == 400 and tunnel.bytes_b_to_a == 600
    assert tunnel.max_idle_s == 30.0
    assert tunnel.handshakes == 1


def test_wireguard_handshake_without_response():
    state = CaptureState()
    for i in range(3):
        _consume_packet(state, _wg(10.0 + 5 * i, A, B, 1))
    issues = vpn_tunnels.detect(state)
    assert [i.type for i in issues] == ["tunnel_handshake_no_response"]
    assert issues[0].evidence["tunnel_type"] == "wireguard"
    assert issues[0].evidence["initiations"] == 3
    assert issues[0].title_en and issues[0].detail_en


def test_openvpn_handshake_without_response():
    state = CaptureState()
    for i in range(2):
        _consume_packet(state, _pkt(10.0 + i, A, B, "eth:ethertype:ip:udp:openvpn", openvpn_opcode="7"))
    assert _types(state) == ["tunnel_handshake_no_response"]


def test_answered_handshake_is_silent():
    state = CaptureState()
    _consume_packet(state, _wg(10.0, A, B, 1))
    _consume_packet(state, _wg(10.1, B, A, 2))
    assert _types(state) == []


def test_one_way_non_esp_tunnel_has_its_own_type():
    state = CaptureState()
    for i in range(config.ESP_ONE_WAY_MIN):
        _consume_packet(state, _pkt(10.0 + i, A, B, "eth:ethertype:ip:gre:ip:icmp"))
    issues = vpn_tunnels.detect(state)
    assert [i.type for i in issues] == ["tunnel_one_way"]
    assert issues[0].evidence["tunnel_type"] == "gre"


def test_esp_one_way_keeps_its_type():
    state = CaptureState()
    for i in range(config.ESP_ONE_WAY_MIN):
        _consume_packet(state, _pkt(10.0 + i, A, B, "eth:ethertype:ip:esp"))
    assert _types(state) == ["esp_one_way"]


def test_frequent_wireguard_renegotiation():
    state = CaptureState()
    for i in range(config.TUNNEL_RENEGOTIATION_MIN):
        _consume_packet(state, _wg(10.0 + 10 * i, A, B, 1))
        _consume_packet(state, _wg(10.1 + 10 * i, B, A, 2))
    issues = vpn_tunnels.detect(state)
    assert [i.type for i in issues] == ["tunnel_renegotiation"]
    assert issues[0].evidence["handshakes"] == config.TUNNEL_RENEGOTIATION_MIN
    assert issues[0].evidence["avg_interval_s"] == 10.0


def test_normal_rekey_interval_is_silent():
    state = CaptureState()
    for i in range(6):  # WireGuard rekeys every 120 s by design
        _consume_packet(state, _wg(10.0 + 120 * i, A, B, 1))
        _consume_packet(state, _wg(10.1 + 120 * i, B, A, 2))
    assert _types(state) == []


def test_frequent_ike_renegotiation():
    state = CaptureState()
    for i in range(config.TUNNEL_RENEGOTIATION_MIN):
        _consume_packet(state, _ike(10.0 + 5 * i, A, B, response=False))
        _consume_packet(state, _ike(10.1 + 5 * i, B, A, response=True))
        _consume_packet(state, _pkt(10.2 + 5 * i, A, B, "eth:ethertype:ip:esp"))
        _consume_packet(state, _pkt(10.3 + 5 * i, B, A, "eth:ethertype:ip:esp"))
    issues = vpn_tunnels.detect(state)
    assert [i.type for i in issues] == ["tunnel_renegotiation"]
    assert issues[0].evidence["tunnel_type"] == "ike"


def test_demo_next_steps_exist_for_new_types():
    from app.llm.demo import _NEXT_STEP_BY_TYPE, _NEXT_STEP_BY_TYPE_EN
    for kind in ("tunnel_one_way", "tunnel_handshake_no_response", "tunnel_renegotiation"):
        assert kind in _NEXT_STEP_BY_TYPE and kind in _NEXT_STEP_BY_TYPE_EN


def test_one_way_capture_softens_tunnel_no_response_issues():
    from app.analysis.quality import NO_RESPONSE_TYPES
    assert {"tunnel_one_way", "tunnel_handshake_no_response"} <= NO_RESPONSE_TYPES
