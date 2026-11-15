"""Robustness against malformed input and capture-quality assessment.

Captures are built by hand (see ``tests/pcap_builder``) so every scenario is a
known-healthy transfer plus exactly one capture artefact.
"""
from __future__ import annotations

import struct

import pytest

from app.analysis import engine
from app.analysis.engine import analyze_pcap
from app.tshark import find_tshark
from tests import pcap_builder as pb

requires_tshark = pytest.mark.skipif(find_tshark() is None, reason="tshark no está instalado")


def _a2b(payload: bytes) -> bytes:
    return pb.MAC_B + pb.MAC_A + b"\x08\x00" + payload


def _b2a(payload: bytes) -> bytes:
    return pb.MAC_A + pb.MAC_B + b"\x08\x00" + payload


def healthy_flows(n_flows: int = 6, data_pkts: int = 10, size: int = 600):
    """Clean transfers: handshake, data ACKed one by one, FIN close. No loss."""
    pkts, t = [], 0.0
    payload = b"x" * size
    for flow in range(n_flows):
        client, server = "10.1.0.%d" % (flow + 1), "10.2.0.%d" % (flow % 3 + 1)
        sport, dport, isn_c, isn_s = 20000 + flow, 443, 1000, 5000
        pkts.append((t, _a2b(pb.tcp(client, server, sport, dport, isn_c, 0, pb.SYN))))
        t += 0.001
        pkts.append((t, _b2a(pb.tcp(server, client, dport, sport, isn_s, isn_c + 1,
                                    pb.SYN | pb.ACK))))
        t += 0.001
        pkts.append((t, _a2b(pb.tcp(client, server, sport, dport, isn_c + 1, isn_s + 1,
                                    pb.ACK))))
        t += 0.001
        seq = isn_c + 1
        for _ in range(data_pkts):
            pkts.append((t, _a2b(pb.tcp(client, server, sport, dport, seq, isn_s + 1,
                                        pb.PSH | pb.ACK, payload=payload))))
            t += 0.001
            seq += size
            pkts.append((t, _b2a(pb.tcp(server, client, dport, sport, isn_s + 1, seq,
                                        pb.ACK))))
            t += 0.001
        pkts.append((t, _a2b(pb.tcp(client, server, sport, dport, seq, isn_s + 1,
                                    pb.FIN | pb.ACK))))
        t += 0.001
        pkts.append((t, _b2a(pb.tcp(server, client, dport, sport, isn_s + 1, seq + 1,
                                    pb.FIN | pb.ACK))))
        t += 0.001
        pkts.append((t, _a2b(pb.tcp(client, server, sport, dport, seq + 1, isn_s + 2,
                                    pb.ACK))))
        t += 0.001
    return pkts


def write_raw(path, records, snaplen: int = 65535) -> None:
    """records: (sec, usec, frame[, captured_len]) written verbatim (no validation)."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1))
        for record in records:
            sec, usec, frame = record[0], record[1], record[2]
            caplen = record[3] if len(record) > 3 else len(frame)
            fh.write(struct.pack("!IIII", sec, usec, caplen, len(frame)))
            fh.write(frame[:caplen])


def write_packets(path, packets) -> None:
    write_raw(path, [(int(ts), min(999999, int(round((ts - int(ts)) * 1e6))), frame)
                     for ts, frame in packets])


def analyze(path):
    return analyze_pcap(find_tshark(), str(path), path.name, path.stat().st_size)


# ── Step 1: malformed input must not abort the analysis ──────────────────

@requires_tshark
def test_malformed_timestamp_does_not_abort_the_analysis(tmp_path):
    packets = healthy_flows(n_flows=1, data_pkts=3)
    records = [(int(ts), int(ts % 1 * 1e6), frame) for ts, frame in packets]
    # Sub-second field out of range: tshark prints "0.(1000000000 nanoseconds)".
    records[4] = (0, 1_000_000, records[4][2])
    path = tmp_path / "bad_ts.pcap"
    write_raw(path, records)

    result = analyze(path)

    assert result.summary.packets == len(packets)
    assert result.meta.skipped_packets == 0  # tolerated, not dropped


def test_packet_with_unparseable_field_is_skipped_and_counted(monkeypatch):
    good = {"frame_number": ["1"], "frame_time_epoch": ["1.5"], "frame_len": ["60"],
            "frame_protocols": ["eth:ethertype:ip:tcp"], "ip_src": ["10.0.0.1"],
            "ip_dst": ["10.0.0.2"], "tcp_stream": ["0"], "tcp_srcport": ["1"],
            "tcp_dstport": ["2"]}
    bad = dict(good, frame_number=["2"], tcp_stream=["not-a-number"])
    monkeypatch.setattr(engine, "iter_packets", lambda *a, **k: iter([good, bad, good]))
    monkeypatch.setattr(engine, "tshark_version", lambda path: "test")

    result = analyze_pcap("tshark", "x.pcap", "x.pcap", 1)

    assert result.meta.skipped_packets == 1
    assert result.conversations.tcp[0].packets == 2
