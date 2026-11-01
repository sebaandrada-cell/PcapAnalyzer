"""HTTP surface of investigation sessions and the agent chat."""
from __future__ import annotations

import gzip
import hashlib
import time

import pytest

from app import config
from app.tshark import find_tshark

pytestmark = pytest.mark.skipif(find_tshark() is None, reason="tshark not installed")

# Token-mode principals are identified by the SHA-256 of the bearer token.
PRINCIPAL = hashlib.sha256(b"test-token").hexdigest()


def _analyze(client, sample_pcap, name="sample.pcap", data=None):
    data = data if data is not None else sample_pcap.read_bytes()
    return client.post("/analyze", files={"file": (name, data, "application/octet-stream")})


def test_analyze_returns_session(client, sample_pcap):
    r = _analyze(client, sample_pcap)
    assert r.status_code == 200
    s = r.json()["session"]
    assert s and s["ttl_minutes"] == 60 and s["content_allowed"] is False
    status = client.get("/sessions/%s" % s["id"]).json()
    assert status["messages"] == 0 and status["usage"]["questions"] == 0


def test_gzip_upload_gets_session_with_decompressed_pcap(client, sample_pcap):
    from app.sessions import session_store

    r = _analyze(client, sample_pcap, "sample.pcap.gz", gzip.compress(sample_pcap.read_bytes()))
    sid = r.json()["session"]["id"]
    session = session_store.peek(sid, PRINCIPAL)
    assert session.pcap_bytes == sample_pcap.stat().st_size


def test_session_patch_and_delete(client, sample_pcap):
    sid = _analyze(client, sample_pcap).json()["session"]["id"]
    patched = client.patch("/sessions/%s" % sid, json={"content_allowed": True}).json()
    assert patched["content_allowed"] is True
    assert client.delete("/sessions/%s" % sid).status_code == 204
    assert client.get("/sessions/%s" % sid).status_code == 404


def test_foreign_token_gets_404(client, sample_pcap, monkeypatch):
    sid = _analyze(client, sample_pcap).json()["session"]["id"]
    monkeypatch.setattr(config, "API_TOKENS", ["test-token", "other"])
    r = client.get("/sessions/%s" % sid, headers={"Authorization": "Bearer other"})
    assert r.status_code == 404


def test_sessions_disabled_returns_null(client, sample_pcap, monkeypatch):
    monkeypatch.setattr(config, "SESSIONS_ENABLED", False)
    assert _analyze(client, sample_pcap).json()["session"] is None


def test_async_job_creates_session(client, sample_pcap):
    r = client.post(
        "/analyze/async",
        files={"file": ("s.pcap", sample_pcap.read_bytes(), "application/octet-stream")},
    )
    job_id = r.json()["job_id"]
    job = None
    for _ in range(100):
        job = client.get("/jobs/%s" % job_id).json()
        if job["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    assert job["status"] == "done" and job["result"]["session"]["id"]


# ---- chat endpoint (SSE) ----------------------------------------------------------
import json  # noqa: E402

from app.agent import router as agent_router  # noqa: E402
from app.agent import runner  # noqa: E402
from app.agent.prompts import INVESTIGATE_SENTINEL  # noqa: E402


def _events(resp):
    out = []
    for frame in resp.text.strip().split("\n\n"):
        lines = frame.split("\n")
        ev = lines[0][len("event: "):]
        data = json.loads(lines[1][len("data: "):])
        out.append((ev, data))
    return out


def test_chat_streams_events_from_runner(client, sample_pcap, monkeypatch):
    sid = _analyze(client, sample_pcap).json()["session"]["id"]

    def fake_run_turn(session, text, lang, tshark_path, emit, client=None):
        emit(runner.TurnEvent("tool_start", {"name": "capture_overview", "label": "capture_overview"}))
        emit(runner.TurnEvent("tool_end", {"name": "capture_overview", "ms": 3, "is_error": False, "truncated": False}))
        emit(runner.TurnEvent("text", {"delta": "Veredicto [[pkt: 1]]"}))
        emit(runner.TurnEvent("usage", {"input_tokens": 1, "output_tokens": 1, "cache_read_tokens": 0,
                                        "cache_write_tokens": 0, "session_total_tokens": 2}))
        emit(runner.TurnEvent("done", {"stop_reason": "end_turn", "limited": False}))
        return runner.TurnResult("Veredicto [[pkt: 1]]", "end_turn", False, {})

    monkeypatch.setattr(agent_router, "run_turn", fake_run_turn)
    monkeypatch.setattr(agent_router, "ai_available", lambda: True)
    r = client.post("/sessions/%s/chat" % sid, json={"message": INVESTIGATE_SENTINEL, "lang": "es"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    assert [e for e, _ in _events(r)] == ["tool_start", "tool_end", "text", "usage", "done"]


def test_chat_demo_mode_streams_report_without_budget(client, sample_pcap, monkeypatch):
    monkeypatch.setattr(config, "LLM_DEMO", True)
    sid = _analyze(client, sample_pcap).json()["session"]["id"]
    ev = _events(client.post("/sessions/%s/chat" % sid, json={"message": INVESTIGATE_SENTINEL}))
    text = "".join(d["delta"] for e, d in ev if e == "text")
    assert "[[filter: tcp.stream eq" in text and ev[-1][0] == "done"
    reply = _events(client.post("/sessions/%s/chat" % sid, json={"message": "¿por qué?"}))
    assert "ANTHROPIC_API_KEY" in "".join(d["delta"] for e, d in reply if e == "text")


def test_chat_409_when_turn_in_progress_or_repeated_investigate(client, sample_pcap, monkeypatch):
    from app.sessions import session_store

    sid = _analyze(client, sample_pcap).json()["session"]["id"]
    session = session_store.peek(sid, PRINCIPAL)
    monkeypatch.setattr(agent_router, "ai_available", lambda: True)
    assert session.lock.acquire(blocking=False)
    try:
        assert client.post("/sessions/%s/chat" % sid, json={"message": "hola"}).status_code == 409
    finally:
        session.lock.release()
    session.messages = [{"role": "user", "content": "x"}]
    assert client.post("/sessions/%s/chat" % sid, json={"message": INVESTIGATE_SENTINEL}).status_code == 409


def test_chat_charges_daily_budget_and_reports_503_without_key(client, sample_pcap, monkeypatch):
    sid = _analyze(client, sample_pcap).json()["session"]["id"]
    monkeypatch.setattr(agent_router, "ai_available", lambda: False)
    assert client.post("/sessions/%s/chat" % sid, json={"message": "hola"}).status_code == 503
    monkeypatch.setattr(agent_router, "ai_available", lambda: True)
    monkeypatch.setattr(config, "LLM_MAX_CALLS_PER_DAY", 1)
    from app import guards
    guards.llm_budget._per_principal.clear()  # the daily counter is process-wide
    guards.llm_budget._global = 0
    calls = []

    def fake(session, text, lang, tshark_path, emit, client=None):
        calls.append(text)
        emit(runner.TurnEvent("done", {"stop_reason": "end_turn", "limited": False}))
        return runner.TurnResult("", "end_turn", False, {})

    monkeypatch.setattr(agent_router, "run_turn", fake)
    assert client.post("/sessions/%s/chat" % sid, json={"message": "uno"}).status_code == 200
    assert client.post("/sessions/%s/chat" % sid, json={"message": "dos"}).status_code == 429
    assert calls == ["uno"]


def test_chat_error_event_when_pcap_vanishes_mid_turn(client, sample_pcap, monkeypatch):
    sid = _analyze(client, sample_pcap).json()["session"]["id"]
    monkeypatch.setattr(agent_router, "ai_available", lambda: True)

    def fake(session, text, lang, tshark_path, emit, client=None):
        emit(runner.TurnEvent("text", {"delta": "a"}))
        raise FileNotFoundError("pcap gone")

    monkeypatch.setattr(agent_router, "run_turn", fake)
    ev = _events(client.post("/sessions/%s/chat" % sid, json={"message": "hola"}))
    assert ev[-1] == ("error", {"code": "internal", "message": "La investigación falló; inténtalo de nuevo."})
