import pytest
from fastapi import HTTPException

from app import config
from app.guards import DailyBudget, IpRateLimiter, client_ip


def test_ip_limiter_blocks_after_limit():
    limiter = IpRateLimiter()
    for _ in range(3):
        limiter.check("1.2.3.4", 3)
    with pytest.raises(HTTPException) as exc:
        limiter.check("1.2.3.4", 3)
    assert exc.value.status_code == 429
    limiter.check("5.6.7.8", 3)  # other IPs unaffected


def test_daily_budget_caps_per_principal_and_global(monkeypatch):
    monkeypatch.setattr(config, "LLM_MAX_CALLS_PER_DAY", 2)
    monkeypatch.setattr(config, "LLM_MAX_CALLS_PER_DAY_GLOBAL", 3)
    budget = DailyBudget()
    budget.consume("a")
    budget.consume("a")
    with pytest.raises(HTTPException):
        budget.consume("a")
    budget.consume("b")
    with pytest.raises(HTTPException):
        budget.consume("c")


def test_middleware_throttles_by_ip_and_caps_body(client, monkeypatch):
    monkeypatch.setattr(config, "IP_MAX_REQUESTS_PER_MINUTE", 2)
    assert client.get("/health").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/health").status_code == 429


def test_oversized_declared_body_rejected(client):
    response = client.post(
        "/diagnose", content=b"x", headers={"Content-Length": str(50 * 1024 * 1024)}
    )
    assert response.status_code == 413


class _Req:
    def __init__(self, xff=None, host="10.0.0.9"):
        self.headers = {"x-forwarded-for": xff} if xff is not None else {}
        self.client = type("C", (), {"host": host})()


def test_client_ip_default_takes_last_entry(monkeypatch):
    monkeypatch.setattr(config, "TRUSTED_PROXY_HOPS", 0)
    assert client_ip(_Req("1.1.1.1, 2.2.2.2")) == "2.2.2.2"


def test_client_ip_behind_cloudflare_and_render(monkeypatch):
    monkeypatch.setattr(config, "TRUSTED_PROXY_HOPS", 2)
    real = "80.103.212.148, 104.22.136.105, 10.30.225.224"
    assert client_ip(_Req(real)) == "80.103.212.148"
    # A client-supplied prefix cannot override the address Cloudflare saw.
    spoofed = "6.6.6.6, " + real
    assert client_ip(_Req(spoofed)) == "80.103.212.148"


def test_client_ip_short_header_falls_back_to_rightmost(monkeypatch):
    monkeypatch.setattr(config, "TRUSTED_PROXY_HOPS", 2)
    assert client_ip(_Req("9.9.9.9")) == "9.9.9.9"
    assert client_ip(_Req(None, host="10.1.1.1")) == "10.1.1.1"
