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


# ---- run_turn with a scripted fake client -----------------------------------------
from types import SimpleNamespace  # noqa: E402

import pytest  # noqa: E402

from app import config  # noqa: E402
from app.agent import runner  # noqa: E402
from app.agent.prompts import INVESTIGATE_SENTINEL  # noqa: E402
from app.sessions import SessionStore  # noqa: E402
from tests.test_llm import make_analysis  # noqa: E402


def _usage(i=100, o=50):
    return SimpleNamespace(input_tokens=i, output_tokens=o, cache_read_input_tokens=0,
                           cache_creation_input_tokens=0)


def _text(t):
    return SimpleNamespace(type="text", text=t)


def _tool(id_, name, inp):
    return SimpleNamespace(type="tool_use", id=id_, name=name, input=inp)


def _msg(content, stop="end_turn"):
    return SimpleNamespace(content=content, stop_reason=stop, usage=_usage(), model="claude-opus-5-5")


class FakeStream:
    def __init__(self, msg):
        self.msg = msg

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    @property
    def text_stream(self):
        for b in self.msg.content:
            if b.type == "text":
                yield b.text

    def get_final_message(self):
        return self.msg


class FakeClient:
    def __init__(self, scripted):
        self.scripted = list(scripted)
        self.calls = []


def make_client(scripted):
    c = FakeClient(scripted)

    def stream(**kwargs):
        c.calls.append(kwargs)
        return FakeStream(c.scripted.pop(0))

    c.beta = SimpleNamespace(messages=SimpleNamespace(stream=stream))
    return c


@pytest.fixture
def session(tmp_path, sample_pcap):
    store = SessionStore(directory=str(tmp_path / "s"))
    s = store.create("tok", str(sample_pcap), "sample.pcap", make_analysis())
    runner.session_store = store  # the runner decrypts through the store
    return s


def test_run_turn_executes_tools_and_persists_complete_turn(session):
    client = make_client([
        _msg([_tool("t1", "protocol_reference", {"topic": "tls"}),
              _tool("t2", "protocol_reference", {"topic": "dns"})], stop="tool_use"),
        _msg([_text("Veredicto: todo bien [[pkt: 1]]")]),
    ])
    events = []
    result = runner.run_turn(session, INVESTIGATE_SENTINEL, "es", "/usr/bin/tshark", events.append, client=client)
    assert result.text.startswith("Veredicto") and result.limited is False
    types = [e.type for e in events]
    assert types.count("tool_start") == 2 and types.count("tool_end") == 2
    assert types[-1] == "done" and "usage" in types
    assert [m["role"] for m in session.messages] == ["user", "assistant", "user", "assistant"]
    assert len(session.messages[2]["content"]) == 2
    assert all(b["type"] == "tool_result" for b in session.messages[2]["content"])
    assert session.usage.questions == 1 and session.usage.input_tokens == 200
    first = client.calls[0]
    assert first["model"] == config.LLM_MODEL and first["fallbacks"] == "default"
    assert first["output_config"]["effort"] == config.AGENT_EFFORT
    assert first["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert first["tools"][-1]["cache_control"] == {"type": "ephemeral"}
    assert "context_management" not in first


def test_run_turn_enforces_tool_cap(session, monkeypatch):
    monkeypatch.setattr(config, "AGENT_MAX_TOOL_CALLS", 2)
    client = make_client([
        _msg([_tool("a", "protocol_reference", {"topic": "tls"})], stop="tool_use"),
        _msg([_tool("b", "protocol_reference", {"topic": "tls"})], stop="tool_use"),
        _msg([_tool("c", "protocol_reference", {"topic": "tls"})], stop="tool_use"),  # 3rd -> not executed
        _msg([_text("cierre")]),
    ])
    result = runner.run_turn(session, "hola", "es", "/usr/bin/tshark", lambda e: None, client=client)
    assert result.limited is True and result.text == "cierre"
    last = client.calls[-1]
    # The tool set stays (API + cache prefix); the closing call forbids further calls.
    assert len(last["tools"]) == len(client.calls[0]["tools"]) and last["tool_choice"] == {"type": "none"}
    assert last["messages"][-1]["role"] == "system"


def test_run_turn_failure_leaves_history_untouched(session):
    client = make_client([_msg([_tool("a", "protocol_reference", {"topic": "tls"})], stop="tool_use")])
    with pytest.raises(Exception):
        runner.run_turn(session, "hola", "es", "/usr/bin/tshark", lambda e: None, client=client)
    assert session.messages == [] and session.usage.questions == 0


def test_run_turn_refusal(session):
    from app.llm.service import AIServiceError

    client = make_client([_msg([], stop="refusal")])
    with pytest.raises(AIServiceError):
        runner.run_turn(session, "hola", "es", "/usr/bin/tshark", lambda e: None, client=client)


def test_run_turn_session_token_cap(session, monkeypatch):
    monkeypatch.setattr(config, "SESSION_MAX_TOKENS", 10)
    session.usage.input_tokens = 20
    with pytest.raises(runner.AgentLimitError):
        runner.run_turn(session, "hola", "es", "/usr/bin/tshark", lambda e: None, client=make_client([]))


def test_run_turn_compacts_when_history_is_large(session, monkeypatch):
    monkeypatch.setattr(config, "AGENT_COMPACT_TOKENS", 10)
    session.messages = [{"role": "user", "content": "x" * 400},
                        {"role": "assistant", "content": [{"type": "text", "text": "y" * 400}]}]
    client = make_client([_msg([_text("ok")])])
    runner.run_turn(session, "más", "es", "/usr/bin/tshark", lambda e: None, client=client)
    assert client.calls[0]["context_management"] == {"edits": [{"type": "compact_20260112"}]}


def test_run_turn_maps_api_errors_to_user_messages(session):
    import anthropic
    import httpx

    from app.llm.service import AIServiceError, AIUnavailableError

    def failing_client(exc):
        c = FakeClient([])

        def stream(**kwargs):
            raise exc

        c.beta = SimpleNamespace(messages=SimpleNamespace(stream=stream))
        return c

    response = httpx.Response(401, request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"))
    with pytest.raises(AIUnavailableError) as exc:
        runner.run_turn(session, "hola", "es", "/usr/bin/tshark", lambda e: None,
                        client=failing_client(anthropic.AuthenticationError("bad key", response=response, body=None)))
    assert "ANTHROPIC_API_KEY" in str(exc.value)
    response429 = httpx.Response(429, request=response.request)
    with pytest.raises(AIServiceError) as exc:
        runner.run_turn(session, "hola", "es", "/usr/bin/tshark", lambda e: None,
                        client=failing_client(anthropic.RateLimitError("slow down", response=response429, body=None)))
    assert exc.value.status_code == 429
    with pytest.raises(AIServiceError):
        runner.run_turn(session, "hola", "es", "/usr/bin/tshark", lambda e: None,
                        client=failing_client(anthropic.APIConnectionError(request=response.request)))
    assert session.messages == []


# ---- final-review fixes ------------------------------------------------------------
def test_limited_call_keeps_tools_and_disables_tool_choice(session, monkeypatch):
    """C1: the closing call must keep the tool set (API + cache prefix) and use tool_choice none."""
    monkeypatch.setattr(config, "AGENT_MAX_TOOL_CALLS", 1)
    client = make_client([
        _msg([_tool("a", "protocol_reference", {"topic": "tls"})], stop="tool_use"),
        _msg([_tool("b", "protocol_reference", {"topic": "tls"})], stop="tool_use"),
        _msg([_text("parte 1")], stop="max_tokens"),
        _msg([_text("parte 2")]),
    ])
    result = runner.run_turn(session, "hola", "es", "/usr/bin/tshark", lambda e: None, client=client)
    assert result.limited is True
    closing = client.calls[2]
    assert len(closing["tools"]) == len(client.calls[0]["tools"])
    assert closing["tool_choice"] == {"type": "none"}
    system_notes = [m for m in client.calls[3]["messages"] if m["role"] == "system"]
    assert len(system_notes) == 1  # appended once, not on every limited iteration


def test_history_carries_one_cache_breakpoint_at_the_end(session):
    """I1: the last user message of every call carries the cache breakpoint."""
    client = make_client([
        _msg([_tool("a", "protocol_reference", {"topic": "tls"})], stop="tool_use"),
        _msg([_text("ok")]),
    ])
    runner.run_turn(session, "hola", "es", "/usr/bin/tshark", lambda e: None, client=client)
    for call in client.calls:
        marked = [m for m in call["messages"] if isinstance(m["content"], list)
                  and m["content"] and m["content"][-1].get("cache_control")]
        assert len(marked) == 1 and marked[0] is call["messages"][-1]
    assert session.messages[-2]["content"][-1].get("cache_control") is None  # not persisted


def test_cancel_stops_turn_without_persisting(session):
    """C2: a cancelled turn (client gone) ends at the next event and leaves history untouched."""
    import threading

    cancel = threading.Event()
    client = make_client([
        _msg([_tool("a", "protocol_reference", {"topic": "tls"})], stop="tool_use"),
        _msg([_text("nunca")]),
    ])

    def emit(event):
        cancel.set()

    with pytest.raises(runner.TurnCancelled):
        runner.run_turn(session, "hola", "es", "/usr/bin/tshark", emit, client=client, cancel=cancel)
    assert session.messages == [] and session.usage.questions == 0


def test_session_gone_mid_turn_is_reported_distinctly(session, monkeypatch):
    """I5: a vanished capture closes the pending tool steps and raises SessionGoneError."""
    from contextlib import contextmanager

    @contextmanager
    def gone(_session):
        raise FileNotFoundError("pcap gone")
        yield  # pragma: no cover

    monkeypatch.setattr(runner.session_store, "decrypted_pcap", gone)
    client = make_client([_msg([_tool("a", "protocol_reference", {"topic": "tls"})], stop="tool_use")])
    events = []
    with pytest.raises(runner.SessionGoneError):
        runner.run_turn(session, "hola", "es", "/usr/bin/tshark", events.append, client=client)
    ends = [e for e in events if e.type == "tool_end"]
    assert len(ends) == 1 and ends[0].data["is_error"] is True
    assert session.messages == []
