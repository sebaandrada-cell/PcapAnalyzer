"""Investigation sessions: encrypted capture at rest, TTL, limits, ownership."""
from __future__ import annotations

import gzip
import os
import time

import pytest

from app import config
from app.sessions import SessionStore, session_info
from tests.test_llm import make_analysis


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SESSION_TTL_MINUTES", 60)
    monkeypatch.setattr(config, "MAX_SESSIONS", 20)
    monkeypatch.setattr(config, "MAX_SESSION_BYTES", 2 * 1024 ** 3)
    return SessionStore(directory=str(tmp_path / "sessions"))


def _pcap(tmp_path, data=b"\xd4\xc3\xb2\xa1" + b"x" * 5000, name="a.pcap"):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _enc_files(store):
    return [f for f in os.listdir(store.directory) if f.endswith(".pcap.enc")]


def test_create_encrypts_and_roundtrips(store, tmp_path):
    src = _pcap(tmp_path)
    s = store.create("tok", src, "a.pcap", make_analysis())
    assert s.pcap_bytes == 5004 and os.path.exists(src)  # source is left to the caller
    enc = _enc_files(store)
    assert len(enc) == 1
    assert b"xxxx" not in open(os.path.join(store.directory, enc[0]), "rb").read()
    with store.decrypted_pcap(s) as path:
        assert open(path, "rb").read() == open(src, "rb").read()
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert not os.path.exists(path)  # temp removed on exit


def test_gzip_source_is_stored_decompressed(store, tmp_path):
    raw = b"\xd4\xc3\xb2\xa1" + b"y" * 3000
    p = tmp_path / "a.pcap.gz"
    p.write_bytes(gzip.compress(raw))
    s = store.create("tok", str(p), "a.pcap.gz", make_analysis())
    assert s.pcap_bytes == len(raw)
    with store.decrypted_pcap(s) as path:
        assert open(path, "rb").read() == raw


def test_get_is_owner_scoped_and_renews(store, tmp_path):
    s = store.create("tok", _pcap(tmp_path), "a.pcap", make_analysis())
    assert store.get(s.id, "other") is None
    before = s.last_used_at
    time.sleep(0.01)
    assert store.get(s.id, "tok") is s and s.last_used_at > before
    assert store.peek(s.id, "tok").last_used_at == s.last_used_at


def test_expiry_and_cleanup(store, tmp_path, monkeypatch):
    s = store.create("tok", _pcap(tmp_path), "a.pcap", make_analysis())
    monkeypatch.setattr(config, "SESSION_TTL_MINUTES", 0)
    assert store.get(s.id, "tok") is None
    assert store.cleanup() == 1 and store.count() == 0
    assert _enc_files(store) == []


def test_limits_evict_oldest(store, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MAX_SESSIONS", 2)
    a = store.create("tok", _pcap(tmp_path, name="1.pcap"), "1", make_analysis())
    b = store.create("tok", _pcap(tmp_path, name="2.pcap"), "2", make_analysis())
    c = store.create("tok", _pcap(tmp_path, name="3.pcap"), "3", make_analysis())
    assert store.peek(a.id, "tok") is None
    assert store.peek(b.id, "tok") and store.peek(c.id, "tok")
    monkeypatch.setattr(config, "MAX_SESSION_BYTES", 6000)  # each pcap is 5004 bytes
    d = store.create("tok", _pcap(tmp_path, name="4.pcap"), "4", make_analysis())
    assert store.count() == 1 and store.peek(d.id, "tok")


def test_delete_removes_file(store, tmp_path):
    s = store.create("tok", _pcap(tmp_path), "a.pcap", make_analysis())
    assert store.delete(s.id, "other") is False
    assert store.delete(s.id, "tok") is True and store.count() == 0
    assert _enc_files(store) == []


def test_purge_orphans_on_startup(tmp_path):
    d = tmp_path / "sessions"
    d.mkdir()
    (d / "stale.pcap.enc").write_bytes(b"garbage")
    store = SessionStore(directory=str(d))
    assert store.purge_orphans() == 1 and not os.listdir(d)


def test_session_info_shape(store, tmp_path):
    s = store.create("tok", _pcap(tmp_path), "a.pcap", make_analysis())
    info = session_info(s)
    assert info.id == s.id and info.ttl_minutes == 60 and info.content_allowed is False
    assert abs(info.expires_at - (s.last_used_at + 3600)) < 1
