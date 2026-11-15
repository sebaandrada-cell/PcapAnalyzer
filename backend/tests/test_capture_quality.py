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
    later = dict(good, frame_number=["3"], frame_time_epoch=["2.5"])  # not a duplicate
    monkeypatch.setattr(engine, "iter_packets", lambda *a, **k: iter([good, bad, later]))
    monkeypatch.setattr(engine, "tshark_version", lambda path: "test")

    result = analyze_pcap("tshark", "x.pcap", "x.pcap", 1)

    assert result.meta.skipped_packets == 1
    assert result.conversations.tcp[0].packets == 2


# ── Step 2: capture quality ──────────────────────────────────────────────

def mirrored(packets, delta: float = 0.00002):
    """A SPAN port copying ingress and egress: every frame twice, 20 us apart."""
    return sorted(list(packets) + [(ts + delta, frame) for ts, frame in packets],
                  key=lambda item: item[0])


def _note(result, code):
    return next((n for n in result.capture_quality.notes if n.code == code), None)


@pytest.fixture(scope="module")
def healthy(tmp_path_factory):
    path = tmp_path_factory.mktemp("quality") / "healthy.pcap"
    write_packets(path, healthy_flows())
    return analyze(path)


@requires_tshark
def test_healthy_capture_has_good_quality_and_no_notes(healthy):
    assert healthy.issues == []
    assert healthy.capture_quality.verdict == "good"
    assert healthy.capture_quality.notes == []
    assert healthy.capture_quality.duplicate_frames == 0


@requires_tshark
def test_mirror_duplicates_do_not_create_issues(tmp_path, healthy):
    base = healthy_flows()
    path = tmp_path / "mirror.pcap"
    write_packets(path, mirrored(base))

    result = analyze(path)

    assert result.issues == []
    quality = result.capture_quality
    assert quality.duplicate_frames == len(base)
    assert quality.duplicate_pct == 50.0
    assert quality.verdict == "poor"
    assert _note(result, "duplicate_frames").severity == "warning"
    # Totals describe the file; conversations describe the traffic.
    assert result.summary.packets == 2 * len(base)
    assert [c.packets for c in result.conversations.tcp] == \
        [c.packets for c in healthy.conversations.tcp]
    flagged = [row for row in result.packet_list.rows if "duplicate_frame" in row.analysis]
    assert len(flagged) == len(base)
    assert all(row.analysis == ["duplicate_frame"] and row.expert is None for row in flagged)
    assert all(entry.severity not in ("warning", "error") for entry in result.expert_info)


def _flow_with_real_retransmissions():
    client, server, sport, dport = "10.1.0.1", "10.2.0.1", 20000, 443
    pkts = [
        (0.000, _a2b(pb.tcp(client, server, sport, dport, 1000, 0, pb.SYN))),
        (0.001, _b2a(pb.tcp(server, client, dport, sport, 5000, 1001, pb.SYN | pb.ACK))),
        (0.002, _a2b(pb.tcp(client, server, sport, dport, 1001, 5001, pb.ACK))),
    ]
    data = _a2b(pb.tcp(client, server, sport, dport, 1001, 5001, pb.PSH | pb.ACK,
                       payload=b"y" * 500))
    pkts += [(0.010, data), (0.210, data), (0.610, data)]  # RTO retransmissions
    pkts.append((0.620, _b2a(pb.tcp(server, client, dport, sport, 5001, 1501, pb.ACK))))
    return pkts


@requires_tshark
def test_real_retransmissions_survive_mirroring(tmp_path):
    plain_path, mirror_path = tmp_path / "plain.pcap", tmp_path / "mirror.pcap"
    write_packets(plain_path, _flow_with_real_retransmissions())
    write_packets(mirror_path, mirrored(_flow_with_real_retransmissions()))

    plain, mirror = analyze(plain_path), analyze(mirror_path)

    assert plain.conversations.tcp[0].retransmissions == 2
    assert mirror.conversations.tcp[0].retransmissions == 2
    assert [i.type for i in mirror.issues] == [i.type for i in plain.issues]
    assert "tcp_retransmissions" in [i.type for i in mirror.issues]


@requires_tshark
def test_one_way_capture_is_flagged(tmp_path):
    only_client = [(ts, fr) for ts, fr in healthy_flows() if fr[:6] == pb.MAC_B]
    path = tmp_path / "oneway.pcap"
    write_packets(path, only_client)

    quality = analyze(path).capture_quality

    assert quality.tcp_conversations_checked == 6
    assert quality.one_way_conversations == 6
    assert quality.verdict == "poor"
    assert next(n for n in quality.notes if n.code == "one_way").severity == "warning"


@requires_tshark
def test_unanswered_syn_retries_are_not_a_one_way_capture(tmp_path):
    syn = _a2b(pb.tcp("10.1.0.1", "10.2.0.9", 20000, 443, 1000, 0, pb.SYN))
    path = tmp_path / "blocked.pcap"
    write_packets(path, [(0.0, syn), (1.0, syn), (3.0, syn), (7.0, syn)])

    quality = analyze(path).capture_quality

    assert quality.one_way_conversations == 0
    assert all(n.code != "one_way" for n in quality.notes)


@requires_tshark
def test_truncated_frames_are_reported(tmp_path):
    packets = healthy_flows(n_flows=1, data_pkts=5)
    records = [(int(ts), int(round(ts % 1 * 1e6)), fr, min(len(fr), 96))
               for ts, fr in packets]
    path = tmp_path / "snaplen.pcap"
    write_raw(path, records, snaplen=96)

    quality = analyze(path).capture_quality

    assert quality.truncated_frames == sum(1 for _, fr in packets if len(fr) > 96) == 5
    assert next(n for n in quality.notes if n.code == "truncated_frames").severity == "warning"


@requires_tshark
def test_connections_already_open_at_capture_start_are_reported(tmp_path):
    flows, per_flow = 4, 3 + 2 * 10 + 3
    packets = healthy_flows(n_flows=flows)
    without_handshake = [pkt for index, pkt in enumerate(packets) if index % per_flow >= 3]
    path = tmp_path / "midstream.pcap"
    write_packets(path, without_handshake)

    quality = analyze(path).capture_quality

    assert quality.midstream_conversations == flows
    assert next(n for n in quality.notes if n.code == "midstream").severity == "info"
    assert quality.verdict == "fair"


def test_skipped_packets_become_a_quality_note(monkeypatch):
    good = {"frame_number": ["1"], "frame_time_epoch": ["1.5"], "frame_len": ["60"],
            "frame_protocols": ["eth:ethertype:ip:tcp"], "ip_src": ["10.0.0.1"],
            "ip_dst": ["10.0.0.2"], "tcp_stream": ["0"], "tcp_srcport": ["1"],
            "tcp_dstport": ["2"]}
    bad = dict(good, tcp_stream=["not-a-number"])
    monkeypatch.setattr(engine, "iter_packets", lambda *a, **k: iter([good, bad]))
    monkeypatch.setattr(engine, "tshark_version", lambda path: "test")

    quality = analyze_pcap("tshark", "x.pcap", "x.pcap", 1).capture_quality

    assert quality.skipped_packets == 1
    assert next(n for n in quality.notes if n.code == "malformed_packets").severity == "warning"


def test_one_way_capture_downgrades_no_response_findings():
    from app.analysis.quality import apply_quality_caveats
    from app.models import CaptureQuality, Issue, QualityNote

    def issue(issue_type, severity):
        return Issue(id=issue_type, type=issue_type, severity=severity, title="t",
                     detail="d", title_en="t", detail_en="d", evidence={})

    issues = [issue("dns_unanswered", "warning"), issue("ike_no_response", "critical"),
              issue("esp_one_way", "warning"), issue("tcp_retransmissions", "critical")]
    one_way = CaptureQuality(verdict="poor", notes=[QualityNote(
        code="one_way", severity="warning", title="t", detail="d", title_en="t", detail_en="d")])

    out = apply_quality_caveats(issues, one_way)

    assert [i.severity for i in out] == ["info", "info", "info", "critical"]
    assert all(i.evidence.get("capture_one_way") for i in out[:3])
    assert "un solo sentido" in out[0].detail and "one direction" in out[0].detail_en
    assert out[3].detail == "d"
    # A partial asymmetry (info note) does not touch the findings.
    partial = CaptureQuality(verdict="fair", notes=[QualityNote(
        code="one_way", severity="info", title="t", detail="d", title_en="t", detail_en="d")])
    assert apply_quality_caveats([issue("dns_unanswered", "warning")], partial)[0].severity == "warning"


# ── Where the quality assessment is surfaced ─────────────────────────────

def _quality_with_duplicates():
    from app.models import CaptureQuality, QualityNote

    return CaptureQuality(
        verdict="poor", duplicate_frames=10, duplicate_pct=50.0,
        notes=[QualityNote(code="duplicate_frames", severity="warning",
                           title="Tramas duplicadas en la captura (50.0%)",
                           detail="10 de 20 tramas son copias exactas.",
                           title_en="Duplicate frames in the capture (50.0%)",
                           detail_en="10 of 20 frames are exact copies.")],
    )


@requires_tshark
def test_agent_overview_carries_the_capture_quality(tmp_path):
    from app.agent.tools import ToolContext, capture_overview
    from app.sessions import SessionStore

    path = tmp_path / "mirror.pcap"
    write_packets(path, mirrored(healthy_flows(n_flows=3)))
    analysis = analyze(path)
    store = SessionStore(directory=str(tmp_path / "s"))
    session = store.create("tok", str(path), "mirror.pcap", analysis)
    with store.decrypted_pcap(session) as pcap:
        content = capture_overview(
            ToolContext(session=session, pcap_path=pcap, tshark_path=find_tshark())).content

    assert content["capture_quality"]["verdict"] == "poor"
    assert content["capture_quality"]["notes"][0]["code"] == "duplicate_frames"
    # Read before the findings: it decides how much to trust them.
    keys = list(content)
    assert keys.index("capture_quality") < keys.index("issues")


def test_agent_prompt_tells_the_model_to_read_the_capture_quality():
    from app.agent.prompts import agent_system

    for lang in ("es", "en"):
        assert "capture_quality" in agent_system(lang)


def test_llm_context_and_pdf_include_the_capture_quality():
    import io

    from pypdf import PdfReader

    from app.llm.context import build_llm_context
    from app.report import build_report
    from tests.test_llm import make_analysis

    analysis = make_analysis().model_copy(update={"capture_quality": _quality_with_duplicates()})

    assert build_llm_context(analysis)["capture_quality"]["verdict"] == "poor"
    text = "\n".join(page.extract_text() for page in
                     PdfReader(io.BytesIO(build_report(analysis))).pages)
    assert "Calidad de la captura" in text and "Tramas duplicadas" in text
    # A clean capture adds no section.
    clean = "\n".join(page.extract_text() for page in
                      PdfReader(io.BytesIO(build_report(make_analysis()))).pages)
    assert "Calidad de la captura" not in clean
