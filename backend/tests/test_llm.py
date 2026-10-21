"""AI layer tests with a mocked Anthropic client (no network calls)."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.llm import client as llm_client
from app.llm import service
from app.llm.context import MAX_ISSUES, build_llm_context
from app.models import (
    AnalysisResult,
    Conversations,
    FileInfo,
    Issue,
    Meta,
    ProtocolStat,
    Summary,
    TcpConversation,
    TimeSeriesPoint,
    TopTalker,
)


def make_analysis(issue_count: int = 2) -> AnalysisResult:
    conv = TcpConversation(
        stream_id=0, src="10.0.0.1", src_port=34567, dst="10.0.0.2", dst_port=80,
        packets=8, bytes=723, bytes_src_to_dst=561, bytes_dst_to_src=162,
        start_time_epoch=0.0, end_time_epoch=0.5, duration_seconds=0.5,
        retransmissions=2, retransmission_pct=25.0, zero_window_events=1,
        mss_client=None, mss_server=None, handshake_rtt_ms=10.0,
    )
    issues = [
        Issue(id="issue-%d" % i, type="tcp_retransmissions", severity="critical",
              title="Issue %d" % i, detail="detail", conversation=None, evidence={})
        for i in range(issue_count)
    ]
    return AnalysisResult(
        file=FileInfo(name="sample.pcap", size_bytes=1000),
        summary=Summary(packets=20, bytes=1570, duration_seconds=5.0,
                        conversations=6, avg_packets_per_second=4.0,
                        avg_bytes_per_second=314.0),
        protocols=[ProtocolStat(protocol="tcp", packets=12, bytes=900,
                                packet_pct=60.0, bytes_pct=57.3)],
        time_series=[TimeSeriesPoint(t=0, packets=8, bytes=723, retransmissions=2)],
        conversations=Conversations(
            tcp=[conv], udp=[],
            top_talkers=[TopTalker(address="10.0.0.1", packets=10, bytes_sent=1000,
                                   bytes_received=500, bytes_total=1500)],
        ),
        tunnels=[],
        issues=issues,
        meta=Meta(engine_version="0.1.0", tshark_version="TShark 4.6.6",
                  analysis_duration_ms=100),
    )


class FakeMessages:
    def __init__(self, text: str, stop_reason: str = "end_turn"):
        self.text = text
        self.stop_reason = stop_reason
        self.last_kwargs = None

    def create(self, **kwargs):
        self.last_kwargs = kwargs
        return SimpleNamespace(
            stop_reason=self.stop_reason,
            model=kwargs["model"],
            content=[SimpleNamespace(type="text", text=self.text)],
            usage=SimpleNamespace(input_tokens=100, output_tokens=50),
        )


def fake_client(text: str, stop_reason: str = "end_turn"):
    return SimpleNamespace(messages=FakeMessages(text, stop_reason))


@pytest.fixture(autouse=True)
def reset_llm_client():
    llm_client.reset_client()
    yield
    llm_client.reset_client()


class TestContext:
    def test_caps_issue_count(self):
        context = build_llm_context(make_analysis(issue_count=MAX_ISSUES + 5))
        assert len(context["issues"]) == MAX_ISSUES
        assert context["issues_truncated"] == 5

    def test_includes_key_sections(self):
        context = build_llm_context(make_analysis())
        assert context["summary"]["packets"] == 20
        assert context["summary"]["total_retransmissions"] == 2
        assert context["tcp_conversations"][0]["stream_id"] == 0
        assert context["issues"][0]["id"] == "issue-0"


class TestDiagnose:
    def test_returns_text_and_usage(self, monkeypatch):
        fake = fake_client("**Qué está pasando**: retransmisiones altas.")
        monkeypatch.setattr(service, "_require_client", lambda: fake)
        result = service.diagnose(make_analysis())
        assert "retransmisiones" in result["diagnosis"]
        assert result["usage"]["output_tokens"] == 50
        kwargs = fake.messages.last_kwargs
        assert kwargs["thinking"] == {"type": "adaptive"}
        assert "output_config" not in kwargs
        assert "sample.pcap" in kwargs["messages"][0]["content"]

    def test_refusal_maps_to_service_error(self, monkeypatch):
        fake = fake_client("", stop_reason="refusal")
        monkeypatch.setattr(service, "_require_client", lambda: fake)
        with pytest.raises(service.AIServiceError):
            service.diagnose(make_analysis())


class TestTranslateQuery:
    def test_parses_structured_output_and_filters_matches(self, monkeypatch):
        payload = json.dumps({
            "filter": "tcp.analysis.retransmission && ip.addr == 10.0.0.2",
            "explanation": "Retransmisiones hacia 10.0.0.2",
            "matched_tcp_streams": [0, 99],       # 99 does not exist
            "matched_issue_ids": ["issue-0", "bogus"],
        })
        fake = fake_client(payload)
        monkeypatch.setattr(service, "_require_client", lambda: fake)
        result = service.translate_query("conexiones con retransmisiones", make_analysis())
        assert result["filter"].startswith("tcp.analysis.retransmission")
        assert result["matched_tcp_streams"] == [0]      # invented ids dropped
        assert result["matched_issue_ids"] == ["issue-0"]
        assert fake.messages.last_kwargs["output_config"]["format"]["type"] == "json_schema"

    def test_unparseable_output_raises(self, monkeypatch):
        fake = fake_client("not json")
        monkeypatch.setattr(service, "_require_client", lambda: fake)
        with pytest.raises(service.AIServiceError):
            service.translate_query("algo", make_analysis())


class TestEndpoints:
    def test_diagnose_503_without_credentials(self, client, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
        monkeypatch.setattr(llm_client, "get_client", lambda: None)
        response = client.post(
            "/diagnose", json={"analysis": make_analysis().model_dump()}
        )
        assert response.status_code == 503
        assert "ANTHROPIC_API_KEY" in response.json()["detail"]

    def test_diagnose_endpoint_with_fake_client(self, client, monkeypatch):
        fake = fake_client("**Qué está pasando**: todo bien.")
        monkeypatch.setattr(service, "_require_client", lambda: fake)
        response = client.post(
            "/diagnose", json={"analysis": make_analysis().model_dump()}
        )
        assert response.status_code == 200
        assert response.json()["diagnosis"].startswith("**Qué está pasando**")

    def test_query_endpoint_with_fake_client(self, client, monkeypatch):
        payload = json.dumps({
            "filter": "dns", "explanation": "Tráfico DNS",
            "matched_tcp_streams": [], "matched_issue_ids": [],
        })
        fake = fake_client(payload)
        monkeypatch.setattr(service, "_require_client", lambda: fake)
        response = client.post(
            "/query",
            json={"question": "muéstrame el DNS",
                  "analysis": make_analysis().model_dump()},
        )
        assert response.status_code == 200
        assert response.json()["filter"] == "dns"

    def test_query_validates_question_length(self, client):
        response = client.post(
            "/query", json={"question": "ab", "analysis": make_analysis().model_dump()}
        )
        assert response.status_code == 422

    def test_health_reports_ai_availability(self, client, monkeypatch):
        monkeypatch.setattr(llm_client, "get_client", lambda: None)
        data = client.get("/health").json()
        assert data["ai"]["available"] is False
        assert data["ai"]["hint"]
