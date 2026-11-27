"""What the AI can read with "allow packet content" OFF: no cleartext logins
through the Info column and no URL query strings (they often carry tokens)."""
from __future__ import annotations

import json

import pytest

from app.agent.fields import check_fields, strip_query
from app.agent.tools import ToolContext, capture_overview, filter_packets
from app.analysis import analyze_pcap
from app.sessions import SessionStore
from app.tshark import find_tshark
from tests.pcap_builder import MAC_A, MAC_B, tcp, write_pcap

needs_tshark = pytest.mark.skipif(find_tshark() is None, reason="tshark not installed")

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"
SECRETS = ("Sup3rSecret", "imap-pass-42", "tok-9f8e7d")


def _frame(payload: bytes) -> bytes:
    return MAC_B + MAC_A + b"\x08\x00" + payload


def _packets():
    return [
        (1.0, _frame(tcp(CLIENT, SERVER, 40001, 21, 1, 1, 0x18, payload=b"PASS Sup3rSecret\r\n"))),
        (2.0, _frame(tcp(CLIENT, SERVER, 40002, 143, 1, 1, 0x18,
                         payload=b"a1 LOGIN alice imap-pass-42\r\n"))),
        (3.0, _frame(tcp(CLIENT, SERVER, 40003, 80, 1, 1, 0x18,
                         payload=b"GET /reset?token=tok-9f8e7d HTTP/1.1\r\nHost: intranet\r\n\r\n"))),
    ]


@pytest.fixture
def ctx(tmp_path):
    tshark = find_tshark()
    pcap = tmp_path / "secrets.pcap"
    write_pcap(str(pcap), _packets())
    analysis = analyze_pcap(tshark_path=tshark, pcap_path=str(pcap),
                            original_filename="secrets.pcap", size_bytes=pcap.stat().st_size)
    store = SessionStore(directory=str(tmp_path / "s"))
    session = store.create("tok", str(pcap), "secrets.pcap", analysis)
    with store.decrypted_pcap(session) as path:
        yield ToolContext(session=session, pcap_path=path, tshark_path=tshark)


def _dump(result) -> str:
    return json.dumps(result.content)


def test_strip_query_keeps_the_path():
    assert strip_query("/reset?token=abc") == "/reset?[query hidden]"
    assert strip_query("http://intranet/a/b?x=1&y=2") == "http://intranet/a/b?[query hidden]"
    assert strip_query("/plain/path") == "/plain/path"
    assert strip_query("GET /reset?token=abc HTTP/1.1") == "GET /reset?[query hidden] HTTP/1.1"


def test_query_parameter_fields_need_the_content_switch():
    assert check_fields(["http.request.uri.query", "http.request.uri.query.parameter"], False) == [
        "http.request.uri.query", "http.request.uri.query.parameter"]
    assert check_fields(["http.request.uri.query"], True) == []


@needs_tshark
def test_info_column_hides_cleartext_logins_without_the_switch(ctx):
    r = filter_packets(ctx, "tcp", ["_ws.col.info", "http.request.uri", "http.request.full_uri"])
    assert not r.is_error
    text = _dump(r)
    for secret in SECRETS:
        assert secret not in text, secret
    assert "[hidden" in text
    assert "/reset" in text  # the path stays useful for troubleshooting
    assert "frame.protocols" not in r.content["fields"]  # helper field is not leaked


@needs_tshark
def test_content_switch_shows_everything(ctx):
    ctx.session.content_allowed = True
    text = _dump(filter_packets(ctx, "tcp", ["_ws.col.info", "http.request.uri"]))
    assert "Sup3rSecret" in text and "tok-9f8e7d" in text


@needs_tshark
def test_capture_overview_strips_url_queries_without_the_switch(ctx):
    text = _dump(capture_overview(ctx))
    assert "tok-9f8e7d" not in text and "/reset" in text
    ctx.session.content_allowed = True
    assert "tok-9f8e7d" in _dump(capture_overview(ctx))
