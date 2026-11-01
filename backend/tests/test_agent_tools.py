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
