"""Agent tools: tshark runner, field allowlist and the six capture tools."""
from __future__ import annotations

import pytest

from app import config
from app.agent.fields import check_fields
from app.agent.tshark_run import ToolError, ToolTimeout, run_tshark, validate_filter
from app.tshark import find_tshark

needs_tshark = pytest.mark.skipif(find_tshark() is None, reason="tshark not installed")


def test_check_fields_allowlist():
    assert check_fields(["frame.number", "tcp.flags.syn", "_ws.col.info"], False) == []
    assert check_fields(["tcp.payload", "data.data", "http.file_data"], False) == [
        "tcp.payload", "data.data", "http.file_data",
    ]
    assert check_fields(["tcp.payload"], True) == []
    assert check_fields(["frame.number; rm -rf /", "ssh.banner"], False) == [
        "frame.number; rm -rf /", "ssh.banner",
    ]


@needs_tshark
def test_run_tshark_rejects_shell_metacharacters_as_plain_args(sample_pcap):
    out = run_tshark([
        "-r", str(sample_pcap),
        "-Y", 'frame.number == 1 && _ws.col.info contains "$(touch /tmp/x)"',
        "-T", "fields", "-e", "frame.number",
    ])
    assert out.strip() == ""  # no match, no crash, nothing executed


@needs_tshark
def test_validate_filter_errors(sample_pcap):
    validate_filter(str(sample_pcap), "tcp.flags.reset == 1")
    with pytest.raises(ToolError) as exc:
        validate_filter(str(sample_pcap), "tcp.flags.reset ==== 1")
    assert "Filtro no válido" in str(exc.value)
    with pytest.raises(ToolError):
        validate_filter(str(sample_pcap), "a" * 2001)
    with pytest.raises(ToolError):
        validate_filter(str(sample_pcap), "frame.number == 1\n&& tcp")


@needs_tshark
def test_run_tshark_timeout(sample_pcap, monkeypatch):
    monkeypatch.setattr("app.agent.tshark_run.find_tshark", lambda: "/bin/sleep")
    with pytest.raises(ToolTimeout):
        run_tshark(["5"], timeout_s=1)


# ---- tools over the sample capture ------------------------------------------
from app.agent.tools import ToolContext, capture_overview, filter_packets  # noqa: E402
from app.analysis import analyze_pcap  # noqa: E402
from app.sessions import SessionStore  # noqa: E402


@pytest.fixture
def ctx(sample_pcap, tmp_path):
    tshark = find_tshark()
    analysis = analyze_pcap(
        tshark_path=tshark, pcap_path=str(sample_pcap),
        original_filename="sample.pcap", size_bytes=sample_pcap.stat().st_size,
    )
    store = SessionStore(directory=str(tmp_path / "s"))
    session = store.create("tok", str(sample_pcap), "sample.pcap", analysis)
    with store.decrypted_pcap(session) as path:
        yield ToolContext(session=session, pcap_path=path, tshark_path=tshark)


@needs_tshark
def test_capture_overview_is_complete(ctx):
    r = capture_overview(ctx)
    assert not r.is_error and r.content["summary"]["packets"] == 56
    assert len(r.content["issues"]) == 18
    assert len(r.content["tcp_conversations"]) == len(ctx.session.analysis.conversations.tcp)
    assert {"stream_id", "dup_acks", "rtt_avg_ms"} <= set(r.content["tcp_conversations"][0])


@needs_tshark
def test_filter_packets_rows_and_paging(ctx):
    r = filter_packets(ctx, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                       ["frame.number", "ip.dst", "tcp.dstport"], limit=2)
    assert not r.is_error and r.content["returned"] == 2 and r.content["has_more"] is True
    assert r.content["rows"][0]["frame"] == 1 and r.content["rows"][0]["tcp.dstport"] == "80"
    r2 = filter_packets(ctx, "tcp.flags.syn == 1 && tcp.flags.ack == 0", ["frame.number"],
                        limit=2, offset=2)
    assert r2.content["rows"][0]["frame"] > 1 and r2.content["offset"] == 2


@needs_tshark
def test_filter_packets_rejects_content_fields_unless_allowed(ctx):
    r = filter_packets(ctx, "tcp", ["tcp.payload"])
    assert r.is_error and r.content["error"] == "fields_not_allowed"
    ctx.session.content_allowed = True
    assert not filter_packets(ctx, "tcp", ["tcp.payload"]).is_error


@needs_tshark
def test_filter_packets_invalid_filter(ctx):
    r = filter_packets(ctx, "tcp.port ==== 80", ["frame.number"])
    assert r.is_error and r.content["error"] == "invalid_filter"


# ---- statistics (tshark -z) ---------------------------------------------------
from app.agent.stats_parse import (  # noqa: E402
    parse_conversations, parse_endpoints, parse_expert, parse_io_stat, parse_protocol_hierarchy,
)
from app.agent.tools import STAT_KINDS, statistics  # noqa: E402


def test_parse_conversations_from_tshark_text():
    text = """================================================================================
TCP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
10.0.0.1:34567             <-> 10.0.0.2:80                      4 282 bytes       5 561 bytes       9 843 bytes     0.000000000         0.5500
================================================================================
"""
    assert parse_conversations(text) == [{
        "a": "10.0.0.1:34567", "b": "10.0.0.2:80", "frames_b_to_a": 4, "bytes_b_to_a": 282,
        "frames_a_to_b": 5, "bytes_a_to_b": 561, "frames": 9, "bytes": 843,
        "rel_start": 0.0, "duration": 0.55,
    }]


def test_parse_endpoints_converts_units():
    text = """================================================================================
IPv4 Endpoints
Filter:<No Filter>
                       | Packets | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
10.0.0.1                       53   14 kB              37      13 kB               16      1128 bytes  
================================================================================
"""
    assert parse_endpoints(text) == [{
        "address": "10.0.0.1", "packets": 53, "bytes": 14000, "tx_packets": 37, "tx_bytes": 13000,
        "rx_packets": 16, "rx_bytes": 1128,
    }]


def test_parse_io_stat_and_hierarchy():
    io = "| Interval | Frames | Bytes |\n|---------------------------|\n|  0 <> 2  |     11 |   951 |\n| 14 <> Dur|      2 |    84 |\n=============================\n"
    assert parse_io_stat(io) == [{"interval_start": 0.0, "frames": 11, "bytes": 951},
                                 {"interval_start": 14.0, "frames": 2, "bytes": 84}]
    phs = "frame                                    frames:56 bytes:14790\n  eth                                    frames:56 bytes:14790\n    ip                                   frames:54 bytes:14706\n      tcp                                frames:26 bytes:6794\n    arp                                  frames:2 bytes:84\n"
    rows = parse_protocol_hierarchy(phs)
    assert rows[3] == {"protocol": "frame:eth:ip:tcp", "frames": 26, "bytes": 6794}
    assert rows[4]["protocol"] == "frame:eth:arp"


def test_parse_expert_groups_by_severity():
    text = ("\nWarns (3)\n=============\n   Frequency      Group           Protocol  Summary\n"
            "           1   Sequence                TCP  TCP Zero Window segment\n"
            "           1   Sequence                TCP  Connection reset (RST)\n\n"
            "Notes (1)\n=============\n   Frequency      Group           Protocol  Summary\n"
            "           5   Sequence                TCP  This frame is a (suspected) retransmission\n")
    rows = parse_expert(text)
    assert rows[0] == {"severity": "warning", "frequency": 1, "group": "Sequence",
                       "protocol": "TCP", "summary": "TCP Zero Window segment"}
    assert rows[-1]["severity"] == "note" and rows[-1]["frequency"] == 5


@needs_tshark
def test_statistics_kinds_on_sample(ctx):
    conv = statistics(ctx, "conversations_tcp")
    assert not conv.is_error
    assert any("10.0.0.2:80" in (r["a"], r["b"]) for r in conv.content["rows"])
    io = statistics(ctx, "io_per_interval", interval_s=2)
    assert len(io.content["rows"]) >= 7 and sum(r["frames"] for r in io.content["rows"]) == 56
    assert statistics(ctx, "expert").content["rows"]
    assert statistics(ctx, "protocol_hierarchy").content["rows"]
    assert statistics(ctx, "endpoints_ip").content["rows"][0]["address"]
    assert statistics(ctx, "dns").content["rows"]["rcode"]["No such name"] == 3
    srt = statistics(ctx, "service_response_time", protocol="icmp")
    assert srt.content["kind"] == "service_response_time" and not srt.is_error
    assert statistics(ctx, "service_response_time", protocol="dns").is_error
    assert statistics(ctx, "nope").is_error and "kinds" in statistics(ctx, "nope").content
    filtered = statistics(ctx, "conversations_tcp", display_filter="tcp.port == 80")
    assert len(filtered.content["rows"]) == 1
    assert statistics(ctx, "conversations_tcp", display_filter="tcp.port ==== 80").is_error
    assert set(STAT_KINDS) >= {"conversations_tcp", "io_per_interval", "expert"}


# ---- stream_detail -------------------------------------------------------------
from app.agent.stream_metrics import StreamPacket, compute_stream_metrics, select_rows  # noqa: E402
from app.agent.tools import stream_detail  # noqa: E402


def _pk(frame, t, a_to_b=True, flags=(), seq=None, ack=None, length=0, analysis=(), rtt=None):
    src, sport, dst, dport = (("10.0.0.1", 1000, "10.0.0.2", 80) if a_to_b
                              else ("10.0.0.2", 80, "10.0.0.1", 1000))
    return StreamPacket(frame, t, src, sport, dst, dport, list(flags), seq, ack, length,
                        65535, list(analysis), rtt, 0.0)


def test_compute_stream_metrics_synthetic():
    pk = [
        _pk(1, 0.0, True, ["SYN"]), _pk(2, 0.05, False, ["SYN", "ACK"], rtt=0.05),
        _pk(3, 0.06, True, ["ACK"], rtt=0.01), _pk(4, 0.1, True, ["PSH", "ACK"], length=100),
        _pk(5, 0.3, False, ["ACK"], rtt=0.2),
        _pk(6, 2.3, True, ["PSH", "ACK"], length=100, analysis=["retransmission"]),
        _pk(7, 2.4, False, ["RST", "ACK"]),
    ]
    m = compute_stream_metrics(pk)
    assert m["handshake_rtt_ms"] == 50.0 and m["bytes_a_to_b"] == 200 and m["packets"] == 7
    assert m["largest_gap"] == {"after_frame": 5, "before_frame": 6, "seconds": 2.0, "last_sender": "b"}
    assert m["events"]["retransmission"] == [6]
    assert m["close"] == {"type": "rst", "initiator": "b", "frame": 7,
                          "seconds_after_last_data": pytest.approx(0.1)}
    assert m["ack_rtt_ms"]["b_to_a"]["max"] == 200.0


def test_select_rows_keeps_events():
    pk = [_pk(i, i * 0.01) for i in range(1, 501)]
    pk[249].analysis = ["retransmission"]
    rows, truncated = select_rows(pk, 50)
    assert truncated and [r.frame for r in rows[:5]] == [1, 2, 3, 4, 5]
    assert 250 in [r.frame for r in rows] and rows[-1].frame == 500


@needs_tshark
def test_stream_detail_on_sample(ctx):
    r = stream_detail(ctx, 0)
    assert not r.is_error
    assert r.content["metrics"]["endpoints"] == {"a": "10.0.0.1:34567", "b": "10.0.0.2:80"}
    assert r.content["metrics"]["events"]["retransmission"] == [5, 6]
    assert 7 in r.content["metrics"]["events"]["zero_window"]
    r1 = stream_detail(ctx, 1)
    assert r1.content["metrics"]["close"]["type"] == "rst"
    assert r1.content["metrics"]["handshake_rtt_ms"] is None
    assert stream_detail(ctx, 999).is_error and stream_detail(ctx, 0, protocol="sctp").is_error


# ---- follow_stream, masking, protocol_reference ------------------------------------
from app.agent.masking import mask_sensitive  # noqa: E402
from app.agent.tools import REFERENCE_TOPICS, follow_stream, protocol_reference  # noqa: E402


def test_mask_sensitive():
    raw = ("GET /login?user=bob&password=hunter2 HTTP/1.1\r\nAuthorization: Basic Ym9iOmh1bnRlcjI=\r\n"
           "Cookie: sid=abc\r\nHost: x\r\n")
    out = mask_sensitive(raw)
    assert "hunter2" not in out and "Ym9i" not in out and "sid=abc" not in out and "Host: x" in out
    assert "password=***" in out and "Authorization: ***" in out


@needs_tshark
def test_follow_stream_requires_content_switch(ctx):
    r = follow_stream(ctx, 0)
    assert r.is_error and r.content["error"] == "content_disabled"
    ctx.session.content_allowed = True
    r = follow_stream(ctx, 0)
    assert not r.is_error and "GET / HTTP/1.1" in r.content["text"]
    assert r.content["nodes"]["b"] == "10.0.0.2:80"
    # stream 3 (:8080) carries a 5 KB download; stream 0 is smaller than the 256 B floor
    small = follow_stream(ctx, 3, max_bytes=256)
    assert small.content["truncated"] is True and small.content["bytes_returned"] <= 256


def test_protocol_reference_topics():
    for topic in REFERENCE_TOPICS:
        r = protocol_reference(topic)
        assert not r.is_error and len(r.content["text"]) > 200
    assert protocol_reference("quantum").is_error


# ---- tool definitions and dispatcher ------------------------------------------------
import json  # noqa: E402

from app.agent.tools import (  # noqa: E402
    TOOL_DEFINITIONS, ToolResult, execute_tool, serialize_result, tool_result_block,
)


def test_tool_definitions_are_strict_and_complete():
    names = {t["name"] for t in TOOL_DEFINITIONS}
    assert names == {"capture_overview", "filter_packets", "stream_detail", "statistics",
                     "follow_stream", "protocol_reference"}
    for t in TOOL_DEFINITIONS:
        assert t["strict"] is True
        assert t["input_schema"]["additionalProperties"] is False and "required" in t["input_schema"]


def test_serialize_result_truncates_to_valid_json():
    big = ToolResult(content={"rows": [{"frame": i, "_ws.col.info": "x" * 500} for i in range(400)]})
    text, truncated = serialize_result(big, max_bytes=20000)
    assert truncated and len(text.encode()) <= 20000
    data = json.loads(text)
    assert data["truncated"] is True and len(data["rows"]) < 400


@needs_tshark
def test_execute_tool_dispatch_and_errors(ctx):
    assert not execute_tool(ctx, "capture_overview", {}).is_error
    assert execute_tool(ctx, "nope", {}).content["error"] == "unknown_tool"
    big = execute_tool(ctx, "filter_packets", {"display_filter": "tcp", "fields": ["frame.number"], "limit": 10 ** 9})
    assert big.content["returned"] <= config.TOOL_MAX_ROWS
    assert execute_tool(ctx, "stream_detail", {"stream_id": "zero"}).content["error"] == "invalid_input"
    block = tool_result_block("tu_1", execute_tool(ctx, "protocol_reference", {"topic": "tls"}))
    assert block["type"] == "tool_result" and block["is_error"] is False and "tls" in block["content"]


@needs_tshark
def test_execute_tool_timeout_is_reported_not_raised(ctx, monkeypatch):
    from app.agent import tshark_run

    def boom(*a, **k):
        raise tshark_run.ToolTimeout("slow")

    monkeypatch.setattr("app.agent.tools.run_tshark", boom)
    assert execute_tool(ctx, "statistics", {"kind": "expert"}).content["error"] == "timeout"
