import pytest
from fastapi import HTTPException

from app import config
from app.guards import DailyBudget, IpRateLimiter


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
