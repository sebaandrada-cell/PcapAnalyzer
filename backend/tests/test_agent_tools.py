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
