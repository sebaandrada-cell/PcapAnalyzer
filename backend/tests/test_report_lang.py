"""The PDF report comes out in the language of the web app."""
from __future__ import annotations

from typing import List

import pytest

from app import report
from app.models import Issue
from tests.test_llm import make_analysis


@pytest.fixture
def texts(monkeypatch) -> List[str]:
    """Text of every Paragraph and table cell the report builds."""
    captured: List[str] = []
    real_paragraph, real_table = report.Paragraph, report._table

    def paragraph(text, style, *args, **kwargs):
        captured.append(text)
        return real_paragraph(text, style, *args, **kwargs)

    def table(data, *args, **kwargs):
        captured.extend(str(cell) for row in data for cell in row if isinstance(cell, str))
        return real_table(data, *args, **kwargs)

    monkeypatch.setattr(report, "Paragraph", paragraph)
    monkeypatch.setattr(report, "_table", table)
    return captured


def _analysis():
    analysis = make_analysis(issue_count=0)
    analysis.issues = [Issue(
        id="i-0", type="tcp_retransmissions", severity="critical",
        title="Retransmisiones altas", detail="Detalle en español",
        title_en="High retransmissions", detail_en="Detail in English",
        conversation=None, evidence={})]
    return analysis


def test_english_report(texts):
    pdf = report.build_report(_analysis(), "## Verdict\nReset [[pkt: 11]] and [[pkt: 3-4]].", lang="en")
    assert pdf[:4] == b"%PDF"
    joined = "\n".join(texts)
    for english in ("Capture analysis report", "Summary", "Packets", "Detected problems",
                    "High retransmissions", "Detail in English", "CRITICAL",
                    "AI-assisted investigation", "packet 11", "packets 3–4",
                    "Protocol distribution"):
        assert english in joined, english
    for spanish in ("Informe de análisis", "Resumen", "Paquetes", "Problemas detectados",
                    "Retransmisiones altas", "CRÍTICO", "paquete 11", "Distribución"):
        assert spanish not in joined, spanish


def test_spanish_stays_the_default(texts):
    report.build_report(_analysis())
    joined = "\n".join(texts)
    assert "Informe de análisis de captura" in joined
    assert "Retransmisiones altas" in joined and "CRÍTICO" in joined


def test_report_endpoint_uses_the_request_language(client, monkeypatch):
    seen = {}

    def fake_build(analysis, diagnosis=None, lang="es"):
        seen["lang"] = lang
        return b"%PDF-fake"

    monkeypatch.setattr("app.main.build_report", fake_build)
    body = {"analysis": _analysis().model_dump()}
    response = client.post("/report", json=body, headers={"Accept-Language": "en"})
    assert response.status_code == 200
    assert seen["lang"] == "en"
