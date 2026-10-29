from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from app import config
from app import shared_db
from app.supabase_jobs import SupabaseJobStore


class FakeConnection:
    def __init__(self):
        self.statements = []

    def execute(self, query, params=()):
        self.statements.append((query, params))
        if "RETURNING id" in query:
            return SimpleNamespace(fetchone=lambda: {"id": params[0]})
        if "AS count" in query:
            return SimpleNamespace(fetchone=lambda: {"count": 0})
        if "AS bytes" in query:
            return SimpleNamespace(fetchone=lambda: {"bytes": 0})
        return SimpleNamespace(fetchone=lambda: None)


def make_store(monkeypatch):
    monkeypatch.setattr(config, "SUPABASE_URL", "https://project.supabase.co")
    monkeypatch.setattr(config, "SUPABASE_ANON_KEY", "anon-key")
    monkeypatch.setattr(config, "SUPABASE_SERVICE_ROLE_KEY", "service-key")
    monkeypatch.setattr(config, "SUPABASE_DB_URL", "postgresql://unused")
    monkeypatch.setattr(config, "SUPABASE_STORAGE_BUCKET", "pcap-captures")
    return SupabaseJobStore()


def fake_database(monkeypatch):
    connection = FakeConnection()

    @contextmanager
    def database_connection():
        yield connection

    monkeypatch.setattr(shared_db, "connection", database_connection)
    return connection


def test_upload_capture_uses_storage_upload_endpoint(monkeypatch, tmp_path):
    store = make_store(monkeypatch)
    capture_path = tmp_path / "capture.pcap"
    capture_path.write_bytes(b"pcap-data")
    request = {}

    def fake_post(url, *, headers, content, timeout):
        request["url"] = url
        request["headers"] = headers
        request["body"] = b"".join(content)
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr("app.supabase_jobs.httpx.post", fake_post)

    store._upload_capture(str(capture_path), "tenant/job/capture.pcap", 9)

    assert request["url"] == (
        "https://project.supabase.co/storage/v1/object/"
        "pcap-captures/tenant/job/capture.pcap"
    )
    assert request["headers"]["Content-Length"] == "9"
    assert request["headers"]["x-upsert"] == "false"
    assert request["body"] == b"pcap-data"


def test_submit_reserves_job_before_upload(monkeypatch):
    store = make_store(monkeypatch)
    connection = fake_database(monkeypatch)
    uploaded = []

    def fake_upload(local_path, storage_key, size_bytes):
        assert any(
            "INSERT INTO public.analysis_jobs" in query and "'uploading'" in query
            for query, _ in connection.statements
        )
        uploaded.append(storage_key)

    monkeypatch.setattr(store, "_upload_capture", fake_upload)

    job = store.submit(
        local_path="/tmp/capture.pcap",
        filename="capture.pcap",
        size_bytes=10,
        owner_id="user-id",
        tenant_id="tenant-id",
    )

    assert job.status == "queued"
    assert uploaded == ["tenant-id/%s/capture.pcap" % job.id]
    assert any(
        "SET status = 'queued'" in query and "RETURNING id" in query
        for query, _ in connection.statements
    )


def test_submit_cleans_up_and_records_failed_upload(monkeypatch):
    store = make_store(monkeypatch)
    connection = fake_database(monkeypatch)

    def fail_upload(local_path, storage_key, size_bytes):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(store, "_upload_capture", fail_upload)
    monkeypatch.setattr(store, "delete_capture", lambda storage_key: True)

    with pytest.raises(RuntimeError, match="storage unavailable"):
        store.submit(
            local_path="/tmp/capture.pcap",
            filename="capture.pcap",
            size_bytes=10,
            owner_id="user-id",
            tenant_id="tenant-id",
        )

    assert any(
        "SET capture_deleted_at" in query
        for query, _ in connection.statements
    )
    assert any(
        "SET status = 'error'" in query
        for query, _ in connection.statements
    )


def test_storage_headers_legacy_jwt_key_goes_in_both_headers(monkeypatch):
    store = make_store(monkeypatch)
    monkeypatch.setattr(config, "SUPABASE_SERVICE_ROLE_KEY", "eyJ.legacy.jwt")
    assert store._storage_headers() == {
        "apikey": "eyJ.legacy.jwt",
        "Authorization": "Bearer eyJ.legacy.jwt",
    }


def test_storage_headers_new_secret_key_is_only_sent_as_apikey(monkeypatch):
    store = make_store(monkeypatch)
    monkeypatch.setattr(config, "SUPABASE_SERVICE_ROLE_KEY", "sb_secret_example")
    assert store._storage_headers() == {"apikey": "sb_secret_example"}
