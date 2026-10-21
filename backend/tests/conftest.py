from __future__ import annotations

import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from tests.pcap_builder import write_pcap  # noqa: E402

SAMPLE_PCAP = BACKEND_DIR / "tests" / "fixtures" / "sample.pcap"


@pytest.fixture(autouse=True)
def _no_demo_mode(monkeypatch):
    """Tests must not depend on the developer's local backend/.env."""
    from app import config

    monkeypatch.setattr(config, "LLM_DEMO", False)


@pytest.fixture(scope="session")
def sample_pcap() -> Path:
    """Deterministic sample capture, regenerated on every test run."""
    SAMPLE_PCAP.parent.mkdir(parents=True, exist_ok=True)
    write_pcap(str(SAMPLE_PCAP))
    return SAMPLE_PCAP


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient

    from app import config
    from app.main import app

    config.AUTH_MODE = "token"
    config.SUPABASE_ENABLED = False
    config.API_TOKENS = ["test-token"]
    config.API_MAX_REQUESTS_PER_MINUTE = 10000
    with TestClient(app, headers={"Authorization": "Bearer test-token"}) as test_client:
        yield test_client
