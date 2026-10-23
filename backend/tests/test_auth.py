from __future__ import annotations

import pytest
from fastapi import HTTPException

from app import config
from app.auth import RequestQuota


def test_analysis_requires_bearer_token(client):
    response = client.get("/jobs/nonexistent", headers={"Authorization": ""})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    upload = client.post(
        "/analyze",
        files={"file": ("capture.pcap", b"not a capture", "application/octet-stream")},
        headers={"Authorization": ""},
    )
    assert upload.status_code == 401


def test_rejects_invalid_bearer_token(client):
    response = client.get(
        "/jobs/nonexistent",
        headers={"Authorization": "Bearer invalid-token"},
    )
    assert response.status_code == 401


def test_cors_headers_are_included_on_authentication_errors(client):
    response = client.post(
        "/analyze",
        headers={
            "Origin": "http://localhost:5173",
            "Authorization": "",
        },
    )
    assert response.status_code == 401
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_health_reports_auth_configuration(client):
    data = client.get("/health").json()
    assert data["auth"]["enabled"] is True


def test_request_quota_is_per_principal(monkeypatch):
    monkeypatch.setattr(config, "API_MAX_REQUESTS_PER_MINUTE", 1)
    quota = RequestQuota()
    quota.consume("principal-a")
    quota.consume("principal-b")
    with pytest.raises(HTTPException) as error:
        quota.consume("principal-a")
    assert error.value.status_code == 429
    assert error.value.headers["Retry-After"]


def test_supabase_jwt_maps_user_to_tenant(monkeypatch):
    from types import SimpleNamespace
    from cryptography.hazmat.primitives.asymmetric import rsa
    from app import auth
    import time

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    issuer = "https://example.supabase.co/auth/v1"
    token = auth.jwt.encode(
        {
            "sub": "75d03c9e-59b4-43bd-bbd6-f810a87e0061",
            "role": "authenticated",
            "aud": "authenticated",
            "iss": issuer,
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )

    monkeypatch.setattr(config, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(config, "SUPABASE_ANON_KEY", "public-key")
    monkeypatch.setattr(config, "SUPABASE_JWT_SECRET", "")
    monkeypatch.setattr(
        auth,
        "_jwks_client",
        SimpleNamespace(
            get_signing_key_from_jwt=lambda access_token: SimpleNamespace(key=public_key)
        ),
    )
    monkeypatch.setattr(
        auth.shared_db, "resolve_tenant_id", lambda user_id: "tenant-id"
    )

    principal = auth._validate_supabase_token(token)
    assert principal.user_id == "75d03c9e-59b4-43bd-bbd6-f810a87e0061"
    assert principal.tenant_id == "tenant-id"
    assert principal.auth_mode == "supabase"


def test_authorization_header_uses_supabase_validation_in_supabase_mode(monkeypatch):
    """Regression: the middleware path must honor AUTH_MODE=supabase.

    authenticate_authorization_header used to validate every bearer token
    against the static API_TOKENS list, so a logged-in Supabase user got
    "define API_TOKENS en el backend" (503) when API_TOKENS was empty.
    """
    from app import auth

    expected = auth.Principal(
        user_id="user-1", tenant_id="tenant-1", auth_mode="supabase"
    )
    charged = []
    monkeypatch.setattr(config, "SUPABASE_ENABLED", True)
    monkeypatch.setattr(config, "API_TOKENS", [])
    monkeypatch.setattr(
        auth, "_validate_supabase_token", lambda token: expected
    )
    monkeypatch.setattr(
        auth.shared_db, "consume_request_quota", lambda tenant: charged.append(tenant)
    )

    principal = auth.authenticate_authorization_header(
        "Bearer a.supabase.jwt", charge=True
    )
    assert principal is expected
    assert charged == ["tenant-1"]

    # Polling endpoints are not charged against the request quota.
    charged.clear()
    auth.authenticate_authorization_header("Bearer a.supabase.jwt", charge=False)
    assert charged == []

    # No / malformed header is still a plain 401 in supabase mode.
    for header in (None, "", "Basic abc", "Bearer"):
        with pytest.raises(HTTPException) as excinfo:
            auth.authenticate_authorization_header(header, charge=True)
        assert excinfo.value.status_code == 401


def test_supabase_rejects_service_role_jwt(monkeypatch):
    from types import SimpleNamespace
    from cryptography.hazmat.primitives.asymmetric import rsa
    from app import auth
    import time

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    token = auth.jwt.encode(
        {
            "sub": "75d03c9e-59b4-43bd-bbd6-f810a87e0061",
            "role": "service_role",
            "aud": "authenticated",
            "iss": "https://example.supabase.co/auth/v1",
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )

    monkeypatch.setattr(config, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(config, "SUPABASE_ANON_KEY", "public-key")
    monkeypatch.setattr(config, "SUPABASE_JWT_SECRET", "")
    monkeypatch.setattr(
        auth,
        "_jwks_client",
        SimpleNamespace(
            get_signing_key_from_jwt=lambda access_token: SimpleNamespace(key=public_key)
        ),
    )
    with pytest.raises(HTTPException) as error:
        auth._validate_supabase_token(token)
    assert error.value.status_code == 401


def test_api_rate_limit_returns_429(client, monkeypatch):
    monkeypatch.setattr(config, "API_TOKENS", ["test-token", "quota-test-token"])
    monkeypatch.setattr(config, "API_MAX_REQUESTS_PER_MINUTE", 1)
    headers = {"Authorization": "Bearer quota-test-token"}
    response = client.post(
        "/analyze",
        files={"file": ("invalid.pcap", b"invalid", "application/octet-stream")},
        headers=headers,
    )
    assert response.status_code == 400
    limited = client.post(
        "/analyze",
        files={"file": ("invalid.pcap", b"invalid", "application/octet-stream")},
        headers=headers,
    )
    assert limited.status_code == 429


def test_jobs_are_not_visible_to_other_tokens(client, monkeypatch):
    from app.jobs import Job, job_store
    import hashlib

    monkeypatch.setattr(config, "API_TOKENS", ["test-token", "other-token"])
    owner_id = hashlib.sha256(b"test-token").hexdigest()
    job = Job(id="private-job", filename="capture.pcap", owner_id=owner_id)
    with job_store._lock:
        job_store._jobs[job.id] = job
    try:
        response = client.get(
            "/jobs/private-job",
            headers={"Authorization": "Bearer other-token"},
        )
        assert response.status_code == 404
    finally:
        with job_store._lock:
            job_store._jobs.pop(job.id, None)
