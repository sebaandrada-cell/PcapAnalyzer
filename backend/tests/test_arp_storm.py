"""ARP storm detection: a sustained rate of ARP requests on the segment."""
from __future__ import annotations

from app import config
from app.analysis.engine import CaptureState, _consume_packet
from app.detectors import arp_storm


def _arp(ts: float, sender_ip: str, target_ip: str, mac: str = "02:00:00:00:00:01",
         opcode: str = "1") -> dict:
    return {
        "frame_time_epoch": [str(ts)],
        "frame_len": ["60"],
        "frame_protocols": ["eth:ethertype:arp"],
        "eth_src": [mac],
        "arp_opcode": [opcode],
        "arp_src_proto_ipv4": [sender_ip],
        "arp_src_hw_mac": [mac],
        "arp_dst_proto_ipv4": [target_ip],
    }


def _feed(state: CaptureState, seconds: int, per_second: int, start: float = 1000.0,
          mac: str = "02:00:00:00:00:01", opcode: str = "1") -> None:
    n = 0
    for sec in range(seconds):
        for i in range(per_second):
            ts = start + sec + i / (per_second + 1)
            _consume_packet(state, _arp(ts, "10.0.0.1", "10.0.%d.%d" % (n // 250, n % 250 + 1),
                                        mac=mac, opcode=opcode))
            n += 1


def test_sustained_arp_request_rate_is_reported():
    state = CaptureState()
    _feed(state, seconds=5, per_second=30)

    issues = arp_storm.detect(state)

    assert [i.type for i in issues] == ["arp_storm"]
    issue = issues[0]
    assert issue.severity == "warning"
    assert issue.title_en and issue.detail_en
    ev = issue.evidence
    assert ev["peak_requests_per_s"] == 30
    assert ev["seconds_over_threshold"] == 5
    assert ev["requests"] == 150
    assert ev["distinct_targets"] == 150
    assert ev["top_senders"][0] == {"mac": "02:00:00:00:00:01", "ips": ["10.0.0.1"],
                                    "requests": 150}


def test_short_burst_is_silent():
    state = CaptureState()
    _feed(state, seconds=config.ARP_STORM_MIN_SECONDS - 1, per_second=50)
    assert arp_storm.detect(state) == []


def test_rate_below_threshold_is_silent():
    state = CaptureState()
    _feed(state, seconds=20, per_second=config.ARP_STORM_RATE_PER_S - 1)
    assert arp_storm.detect(state) == []


def test_arp_replies_do_not_count():
    state = CaptureState()
    _feed(state, seconds=5, per_second=30, opcode="2")
    assert arp_storm.detect(state) == []


def test_detector_is_registered():
    from app.detectors import DETECTORS
    assert arp_storm in DETECTORS


def test_demo_has_next_steps_in_both_languages():
    from app.llm.demo import _NEXT_STEP_BY_TYPE, _NEXT_STEP_BY_TYPE_EN
    assert "arp_storm" in _NEXT_STEP_BY_TYPE and "arp_storm" in _NEXT_STEP_BY_TYPE_EN
