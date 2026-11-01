"""The tool-use loop: one user question -> model calls -> tools -> final answer.

The loop is written by hand (not the SDK tool runner) because it has to emit
progress events between calls and enforce the product's own caps. History is
append-only and only persisted to the session once the whole turn succeeded.
"""
from __future__ import annotations

import copy
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .. import config
from ..llm.client import availability, get_client
from ..llm.service import AIServiceError, AIUnavailableError
from ..sessions import Session, session_store  # noqa: F401  (module attribute; tests swap it)
from .prompts import INVESTIGATE_SENTINEL, agent_system, investigate_request, limit_reached_note
from .tools import TOOL_DEFINITIONS, ToolContext, ToolResult, execute_tool, tool_result_block

_FALLBACK_BETA = "server-side-fallback-2026-07-01"
_TASK_BUDGET_BETA = "task-budgets-2026-03-13"
_COMPACT_BETA = "compact-2026-01-12"
_MAX_TOKENS = 16000
_MAX_PARALLEL_TOOLS = 4


@dataclass
class TurnEvent:
    type: str  # tool_start | tool_end | text | usage | done | error
    data: dict


@dataclass
class TurnResult:
    text: str
    stop_reason: str
    limited: bool
    usage: Dict[str, int]


class AgentLimitError(RuntimeError):
    """The session already spent its token allowance."""


def _block_to_dict(block: Any) -> Dict[str, Any]:
    if hasattr(block, "model_dump"):
        return block.model_dump(exclude_none=True)
    return {k: v for k, v in vars(block).items() if v is not None}


def _label(name: str, tool_input: Dict[str, Any]) -> str:
    for key in ("display_filter", "kind", "stream_id", "topic"):
        if tool_input.get(key) not in (None, ""):
            return "%s: %s" % (name, tool_input[key])
    return name


def _estimate_tokens(messages: List[dict]) -> int:
    return len(json.dumps(messages, ensure_ascii=False, default=str)) // 4


def _add_usage(totals: Dict[str, int], usage: Any) -> None:
    totals["input_tokens"] += getattr(usage, "input_tokens", 0) or 0
    totals["output_tokens"] += getattr(usage, "output_tokens", 0) or 0
    totals["cache_read_tokens"] += getattr(usage, "cache_read_input_tokens", 0) or 0
    totals["cache_write_tokens"] += getattr(usage, "cache_creation_input_tokens", 0) or 0


def _run_tools(
    session: Session,
    tshark_path: str,
    tool_uses: List[Any],
    emit: Callable[[TurnEvent], None],
) -> List[dict]:
    """Execute a batch of tool_use blocks under one decrypted copy of the capture."""
    results: List[dict] = []
    for block in tool_uses:
        emit(TurnEvent("tool_start", {"name": block.name, "label": _label(block.name, dict(block.input))}))
    with session_store.decrypted_pcap(session) as pcap_path:
        ctx = ToolContext(session=session, pcap_path=pcap_path, tshark_path=tshark_path)

        def one(block: Any):
            started = time.monotonic()
            result = execute_tool(ctx, block.name, dict(block.input))
            return block, result, int((time.monotonic() - started) * 1000)

        with ThreadPoolExecutor(max_workers=min(_MAX_PARALLEL_TOOLS, len(tool_uses))) as pool:
            for block, result, ms in pool.map(one, tool_uses):
                emit(TurnEvent("tool_end", {
                    "name": block.name, "ms": ms, "is_error": result.is_error, "truncated": result.truncated,
                }))
                results.append(tool_result_block(block.id, result))
    return results


def _budget_exhausted_results(tool_uses: List[Any]) -> List[dict]:
    result = ToolResult(content={"error": "tool_budget_exhausted"}, is_error=True)
    return [tool_result_block(block.id, result) for block in tool_uses]


def _map_api_error(exc: Exception) -> Exception:
    """Most-specific-first mapping of anthropic SDK errors; unknown errors pass through."""
    try:
        import anthropic
    except Exception:  # pragma: no cover
        return exc
    if isinstance(exc, anthropic.AuthenticationError):
        return AIUnavailableError(
            "La API de Anthropic rechazó la clave (401). Revisa ANTHROPIC_API_KEY en el backend y reinícialo."
        )
    if isinstance(exc, anthropic.PermissionDeniedError):
        return AIServiceError("La clave de Anthropic no tiene permiso para este modelo (403).", status_code=403)
    if isinstance(exc, anthropic.RateLimitError):
        return AIServiceError(
            "Límite de peticiones de la API de Anthropic alcanzado; inténtalo de nuevo en unos segundos.",
            status_code=429,
        )
    if isinstance(exc, anthropic.APIStatusError):
        return AIServiceError("Error de la API de Anthropic (%s)." % exc.status_code)
    if isinstance(exc, anthropic.APIConnectionError):
        return AIServiceError("No se pudo conectar con la API de Anthropic.")
    return exc


def run_turn(
    session: Session,
    user_text: str,
    lang: str,
    tshark_path: str,
    emit: Callable[[TurnEvent], None],
    client: Any = None,
) -> TurnResult:
    spent = session.usage.input_tokens + session.usage.output_tokens
    if spent >= config.SESSION_MAX_TOKENS:
        raise AgentLimitError("Esta sesión alcanzó su límite de tokens (%d)." % config.SESSION_MAX_TOKENS)
    if client is None:
        client = get_client()
        if client is None:
            raise AIUnavailableError(availability()["hint"])

    text = investigate_request(lang) if user_text == INVESTIGATE_SENTINEL else user_text
    history: List[dict] = list(session.messages) + [{"role": "user", "content": text}]
    system = [{"type": "text", "text": agent_system(lang), "cache_control": {"type": "ephemeral"}}]
    tools = copy.deepcopy(TOOL_DEFINITIONS)
    tools[-1]["cache_control"] = {"type": "ephemeral"}

    totals = {"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0}
    tool_calls = 0
    model_calls = 0
    limited = False
    continued = False
    final_text = ""
    stop_reason = "end_turn"

    while True:
        if limited:
            history.append({"role": "system", "content": limit_reached_note(lang)})
        kwargs: Dict[str, Any] = {
            "model": config.LLM_MODEL,
            "max_tokens": _MAX_TOKENS,
            "system": system,
            "tools": [] if limited else tools,
            "messages": list(history),  # snapshot: the list keeps growing after the call
            "thinking": {"type": "adaptive"},
            "output_config": {
                "effort": config.AGENT_EFFORT,
                "task_budget": {"type": "tokens", "total": config.AGENT_TASK_BUDGET_TOKENS},
            },
            "betas": [_FALLBACK_BETA, _TASK_BUDGET_BETA],
            "fallbacks": "default",
        }
        if _estimate_tokens(history) > config.AGENT_COMPACT_TOKENS:
            kwargs["context_management"] = {"edits": [{"type": "compact_20260112"}]}
            kwargs["betas"] = kwargs["betas"] + [_COMPACT_BETA]

        pieces: List[str] = []
        try:
            with client.beta.messages.stream(**kwargs) as stream:
                for delta in stream.text_stream:
                    pieces.append(delta)
                    emit(TurnEvent("text", {"delta": delta}))
                final = stream.get_final_message()
        except Exception as exc:  # translate SDK errors into messages the user can act on
            raise _map_api_error(exc) from exc
        model_calls += 1
        _add_usage(totals, final.usage)
        history.append({"role": "assistant", "content": [_block_to_dict(b) for b in final.content]})
        stop_reason = final.stop_reason

        if stop_reason == "refusal":
            raise AIServiceError("El modelo no procesó esta pregunta.")

        tool_uses = [b for b in final.content if getattr(b, "type", None) == "tool_use"]
        if stop_reason == "tool_use" and tool_uses:
            over_tools = tool_calls + len(tool_uses) > config.AGENT_MAX_TOOL_CALLS
            over_calls = model_calls >= config.AGENT_MAX_MODEL_CALLS - 1
            if limited or over_tools or over_calls:
                history.append({"role": "user", "content": _budget_exhausted_results(tool_uses)})
                limited = True
                continue
            history.append({"role": "user", "content": _run_tools(session, tshark_path, tool_uses, emit)})
            tool_calls += len(tool_uses)
            continue

        final_text = "".join(pieces) or "".join(
            getattr(b, "text", "") for b in final.content if getattr(b, "type", None) == "text"
        )
        if stop_reason == "max_tokens" and not continued:
            continued = True
            history.append({"role": "user", "content": "Continue exactly where you stopped."})
            continue
        break

    session.messages = history
    session.usage.input_tokens += totals["input_tokens"]
    session.usage.output_tokens += totals["output_tokens"]
    session.usage.cache_read_tokens += totals["cache_read_tokens"]
    session.usage.cache_write_tokens += totals["cache_write_tokens"]
    session.usage.questions += 1
    usage_event = dict(totals)
    usage_event["session_total_tokens"] = session.usage.input_tokens + session.usage.output_tokens
    emit(TurnEvent("usage", usage_event))
    emit(TurnEvent("done", {"stop_reason": stop_reason, "limited": limited}))
    return TurnResult(text=final_text, stop_reason=stop_reason, limited=limited, usage=usage_event)
