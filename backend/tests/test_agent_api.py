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
