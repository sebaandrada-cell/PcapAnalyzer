"""DNS transaction tracking, including ID reuse on one conversation."""
from app.analysis.engine import CaptureState, _consume_packet


def _dns_packet(ts, src, dst, response=False):
    return {
        "frame_time_epoch": [str(ts)],
        "frame_len": ["60"],
        "frame_protocols": ["eth:ip:udp:dns"],
        "ip_src": [src], "ip_dst": [dst],
        "udp_stream": ["0"], "udp_srcport": ["53000"], "udp_dstport": ["53"],
        "dns_id": ["42"], "dns_qry_name": ["example.test"],
        "dns_flags_response": ["True" if response else "False"],
        "dns_flags_rcode": ["0"],
    }


def test_keeps_overlapping_dns_queries_with_the_same_id():
    state = CaptureState()
    _consume_packet(state, _dns_packet(1.0, "10.0.0.1", "10.0.0.53"))
    _consume_packet(state, _dns_packet(1.1, "10.0.0.1", "10.0.0.53"))
    _consume_packet(state, _dns_packet(1.2, "10.0.0.53", "10.0.0.1", response=True))
    _consume_packet(state, _dns_packet(1.4, "10.0.0.53", "10.0.0.1", response=True))

    assert [round(item.latency_s, 1) for item in state.dns_answered] == [0.2, 0.3]
    assert not state.dns_pending
