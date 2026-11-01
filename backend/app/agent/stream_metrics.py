"""Per-stream metrics computed from the packets of one TCP/UDP conversation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

EVENT_FLAGS = (
    "retransmission", "fast_retransmission", "spurious_retransmission", "dup_ack",
    "out_of_order", "lost_segment", "zero_window", "window_full",
)


@dataclass
class StreamPacket:
    frame: int
    time: float
    src: str
    sport: int
    dst: str
    dport: int
    flags: List[str]
    seq: Optional[int]
    ack: Optional[int]
    length: int  # tcp.len / udp.length
    window: Optional[int]
    analysis: List[str]
    ack_rtt: Optional[float]
    delta: float


def _endpoint(pkt: StreamPacket, side: str) -> str:
    return "%s:%s" % ((pkt.src, pkt.sport) if side == "src" else (pkt.dst, pkt.dport))


def _rtt_stats(values: List[float]) -> dict:
    if not values:
        return {"avg": None, "p95": None, "max": None, "samples": 0}
    ordered = sorted(values)
    p95 = ordered[int(round(0.95 * (len(ordered) - 1)))]
    return {
        "avg": round(sum(values) / len(values) * 1000, 3),
        "p95": round(p95 * 1000, 3),
        "max": round(max(values) * 1000, 3),
        "samples": len(values),
    }


def compute_stream_metrics(packets: List[StreamPacket]) -> dict:
    if not packets:
        return {"packets": 0}
    first = packets[0]
    a, b = _endpoint(first, "src"), _endpoint(first, "dst")

    def direction(p: StreamPacket) -> str:
        return "a_to_b" if _endpoint(p, "src") == a else "b_to_a"

    bytes_ab = sum(p.length for p in packets if direction(p) == "a_to_b")
    bytes_ba = sum(p.length for p in packets if direction(p) == "b_to_a")
    duration = packets[-1].time - first.time

    handshake_rtt = None
    if "SYN" in first.flags and "ACK" not in first.flags:
        synack = next((p for p in packets[1:] if "SYN" in p.flags and "ACK" in p.flags), None)
        if synack is not None:
            handshake_rtt = round((synack.time - first.time) * 1000, 3)

    rtts: Dict[str, List[float]] = {"a_to_b": [], "b_to_a": []}
    for p in packets:
        if p.ack_rtt is not None:
            rtts[direction(p)].append(p.ack_rtt)

    throughput = {
        "a_to_b": round(bytes_ab * 8 / duration, 1) if duration > 0 else 0.0,
        "b_to_a": round(bytes_ba * 8 / duration, 1) if duration > 0 else 0.0,
    }

    largest_gap = None
    for prev, cur in zip(packets, packets[1:]):
        gap = cur.time - prev.time
        if largest_gap is None or gap > largest_gap["seconds"]:
            largest_gap = {
                "after_frame": prev.frame, "before_frame": cur.frame,
                "seconds": round(gap, 6), "last_sender": "a" if direction(prev) == "a_to_b" else "b",
            }

    events = {name: [p.frame for p in packets if name in p.analysis] for name in EVENT_FLAGS}

    close: dict = {"type": "none", "initiator": None, "frame": None, "seconds_after_last_data": None}
    last_data = max((p.time for p in packets if p.length > 0), default=None)
    for p in packets:
        kind = "rst" if "RST" in p.flags else "fin" if "FIN" in p.flags else None
        if kind:
            close = {
                "type": kind,
                "initiator": "a" if direction(p) == "a_to_b" else "b",
                "frame": p.frame,
                "seconds_after_last_data": round(p.time - last_data, 6) if last_data is not None else None,
            }
            break

    return {
        "endpoints": {"a": a, "b": b},
        "packets": len(packets),
        "bytes_a_to_b": bytes_ab,
        "bytes_b_to_a": bytes_ba,
        "duration_s": round(duration, 6),
        "handshake_rtt_ms": handshake_rtt,
        "ack_rtt_ms": {k: _rtt_stats(v) for k, v in rtts.items()},
        "throughput_bps": throughput,
        "largest_gap": largest_gap,
        "events": events,
        "close": close,
    }


def select_rows(packets: List[StreamPacket], max_rows: int) -> Tuple[List[StreamPacket], bool]:
    """Keep every row when it fits; otherwise head, tail and ±3 around each event or gap."""
    if len(packets) <= max_rows:
        return list(packets), False
    keep = set(range(0, 5)) | set(range(len(packets) - 5, len(packets)))
    interesting = [i for i, p in enumerate(packets) if p.analysis or "SYN" in p.flags or "FIN" in p.flags or "RST" in p.flags]
    if len(packets) > 1:
        gaps = sorted(range(1, len(packets)), key=lambda i: packets[i].time - packets[i - 1].time, reverse=True)[:3]
        interesting += gaps + [i - 1 for i in gaps]
    for i in interesting:
        keep.update(range(max(0, i - 3), min(len(packets), i + 4)))
    rows = [packets[i] for i in sorted(keep)][:max_rows]
    return rows, True
