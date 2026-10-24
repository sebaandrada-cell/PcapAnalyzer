"""Demo mode (LLM_DEMO=1): fake AI responses without API calls."""
from __future__ import annotations

import pytest

from app import config
from app.llm.demo import DEMO_MARK, demo_diagnosis, demo_query
from tests.test_llm import make_analysis


@pytest.fixture
def demo_mode(monkeypatch):
    monkeypatch.setattr(config, "LLM_DEMO", True)


class TestDemoDiagnosis:
    def test_contains_three_sections_and_demo_mark(self):
        result = demo_diagnosis(make_analysis())
        for section in ("**Qué está pasando**", "**Causa probable**",
                        "**Siguiente paso recomendado**"):
            assert section in result["diagnosis"]
        assert DEMO_MARK in result["diagnosis"]
        assert result["model"] == "demo"

    def test_handles_clean_capture(self):
        analysis = make_analysis(issue_count=0)
        result = demo_diagnosis(analysis)
        assert "no presenta problemas" in result["diagnosis"]

    def test_english_next_steps_are_in_english(self):
        """Regression: the English text used to end with Spanish recommendations."""
        from app.llm.demo import _NEXT_STEP_BY_TYPE, _NEXT_STEP_BY_TYPE_EN

        analysis = make_analysis()  # tcp_retransmissions issues
        text = demo_diagnosis(analysis, "en")["diagnosis"]
        assert _NEXT_STEP_BY_TYPE_EN["tcp_retransmissions"] in text
        assert _NEXT_STEP_BY_TYPE["tcp_retransmissions"] not in text
        spanish = demo_diagnosis(analysis, "es")["diagnosis"]
        assert _NEXT_STEP_BY_TYPE["tcp_retransmissions"] in spanish

    def test_next_step_languages_cover_the_same_issue_types(self):
        from app.llm.demo import _NEXT_STEP_BY_TYPE, _NEXT_STEP_BY_TYPE_EN

        assert set(_NEXT_STEP_BY_TYPE_EN) == set(_NEXT_STEP_BY_TYPE)
        assert all(_NEXT_STEP_BY_TYPE_EN.values())


class TestDemoQuery:
    def test_keyword_mapping_and_matches(self):
        result = demo_query("conexiones con retransmisiones", make_analysis())
        assert result["filter"] == "tcp.analysis.retransmission"
        assert "(modo demo)" in result["explanation"]
        # make_analysis issues are tcp_retransmissions -> all match
        assert result["matched_issue_ids"] == ["issue-0", "issue-1"]

    def test_accents_are_normalized(self):
        result = demo_query("¿por qué va lento? mucha latencia", make_analysis())
        assert "ack_rtt" in result["filter"]

    def test_fallback_filter(self):
        result = demo_query("cosas raras en general", make_analysis())
        assert result["filter"] == "ip"
        assert result["matched_issue_ids"] == []


class TestDemoEndpoints:
    def test_diagnose_endpoint_in_demo_mode(self, client, demo_mode):
        response = client.post(
            "/diagnose", json={"analysis": make_analysis().model_dump()}
        )
        assert response.status_code == 200
        assert DEMO_MARK in response.json()["diagnosis"]
        assert response.json()["model"] == "demo"

    def test_query_endpoint_in_demo_mode(self, client, demo_mode):
        response = client.post(
            "/query",
            json={"question": "tráfico dns con problemas",
                  "analysis": make_analysis().model_dump()},
        )
        assert response.status_code == 200
        assert response.json()["filter"] == "dns"

    def test_health_reports_demo_model(self, client, demo_mode):
        data = client.get("/health").json()
        assert data["ai"] == {"available": True, "model": "demo", "hint": None}
