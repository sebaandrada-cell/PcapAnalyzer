"""The PDF renders the agent's investigation report with its evidence marks."""
from __future__ import annotations

from typing import List

import pytest

from app import report
from tests.test_llm import make_analysis


@pytest.fixture
def paragraphs(monkeypatch) -> List[str]:
    """Capture the text of every Paragraph the report builds (no PDF parsing needed)."""
    captured: List[str] = []
    real = report.Paragraph

    def spy(text, style, *args, **kwargs):
        captured.append(text)
        return real(text, style, *args, **kwargs)

    monkeypatch.setattr(report, "Paragraph", spy)
    return captured


def test_report_renders_investigation_marks(paragraphs):
    text = ("## Veredicto\nRST a los 5 ms [[pkt: 11]] [[filter: tcp.stream eq 1]].\n\n"
            "## Hallazgos\n- uno [[pkt: 10-11]]\n- **dos** `tcp.port == 80`\n\n_(nota en cursiva)_")
    pdf = report.build_report(make_analysis(), text)
    assert pdf[:4] == b"%PDF"
    joined = "\n".join(paragraphs)
    assert "Investigación asistida por IA" in joined
    assert "paquete 11" in joined and "paquetes 10–11" in joined
    assert "[[pkt" not in joined and "[[filter" not in joined
    assert '<font face="Courier">tcp.stream eq 1</font>' in joined
    assert "<b>dos</b>" in joined and "<i>nota en cursiva</i>" in joined
    assert any(p.startswith("• uno") for p in paragraphs)
    assert "Veredicto" in joined and "Hallazgos" in joined


def test_legacy_diagnosis_still_uses_the_old_title(paragraphs):
    report.build_report(make_analysis(), "**Qué está pasando**: todo bien.\n\n**Causa probable**: nada.")
    joined = "\n".join(paragraphs)
    assert "Diagnóstico asistido (IA)" in joined and "Investigación asistida por IA" not in joined


def test_malicious_text_is_escaped(paragraphs):
    report.build_report(make_analysis(), "## X\n<script>alert(1)</script> [[filter: a<b]]")
    joined = "\n".join(paragraphs)
    assert "<script>" not in joined and "&lt;script&gt;" in joined
    assert '<font face="Courier">a&lt;b</font>' in joined
