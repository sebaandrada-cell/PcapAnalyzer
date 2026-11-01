"""Agent prompts and the tool-use loop (Anthropic client mocked)."""
from __future__ import annotations

from app.agent import prompts


def test_prompts_are_stable_and_contain_rules():
    assert prompts.agent_system("es") == prompts.agent_system("es")
    for lang in ("es", "en"):
        s = prompts.agent_system(lang)
        assert "capture_overview" in s and "[[pkt:" in s and "[[filter:" in s
        assert "untrusted" in s.lower()
        req = prompts.investigate_request(lang)
        for header in prompts.REPORT_HEADERS[lang]:
            assert header in req
    assert "Spanish" in prompts.agent_system("es") and "English" in prompts.agent_system("en")
    assert prompts.limit_reached_note("en")
    assert prompts.INVESTIGATE_SENTINEL == "__investigate__"
