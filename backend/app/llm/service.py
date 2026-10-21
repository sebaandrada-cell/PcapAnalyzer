"""Calls to the Anthropic API for diagnosis and NL -> filter translation."""
from __future__ import annotations

import json
from typing import Any, Dict

from .. import config
from ..models import AnalysisResult
from .context import build_llm_context
from .prompts import QUERY_OUTPUT_SCHEMA, diagnosis_system, query_system


class AIUnavailableError(RuntimeError):
    """No credentials configured for the AI layer."""


class AIServiceError(RuntimeError):
    """The API call failed or returned an unusable response."""

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


def _require_client():
    from .client import availability, get_client

    client = get_client()
    if client is None:
        raise AIUnavailableError(availability()["hint"])
    return client


def _call(client, *, system: str, user_content: str, output_schema=None):
    """One messages.create call with the shared error handling."""
    import anthropic

    kwargs: Dict[str, Any] = {
        "model": config.LLM_MODEL,
        "max_tokens": config.LLM_MAX_TOKENS,
        "system": system,
        "thinking": {"type": "adaptive"},
        "messages": [{"role": "user", "content": user_content}],
    }
    if output_schema is not None:
        kwargs["output_config"] = {
            "format": {"type": "json_schema", "schema": output_schema}
        }
    try:
        response = client.messages.create(**kwargs)
    except TypeError as exc:
        # SDK raises TypeError at request time when no credential resolved.
        if "authentication" in str(exc).lower():
            from .client import availability

            raise AIUnavailableError(availability()["hint"])
        raise
    except anthropic.RateLimitError:
        raise AIServiceError(
            "Límite de peticiones de la API de Anthropic alcanzado; "
            "inténtalo de nuevo en unos segundos.",
            status_code=429,
        )
    except anthropic.APIStatusError as exc:
        raise AIServiceError("Error de la API de Anthropic (%s)." % exc.status_code)
    except anthropic.APIConnectionError:
        raise AIServiceError("No se pudo conectar con la API de Anthropic.")

    if response.stop_reason == "refusal":
        raise AIServiceError("El modelo declinó procesar esta petición.")
    if response.stop_reason == "max_tokens":
        raise AIServiceError("La respuesta del modelo se truncó; inténtalo de nuevo.")

    text = next((b.text for b in response.content if b.type == "text"), None)
    if not text:
        raise AIServiceError("El modelo no devolvió texto.")
    return text, response


def diagnose(analysis: AnalysisResult, lang: str = "es") -> Dict[str, Any]:
    if config.LLM_DEMO:
        from .demo import demo_diagnosis

        return demo_diagnosis(analysis, lang)
    client = _require_client()
    context = build_llm_context(analysis)
    user_content = (
        "Analyze this capture summary and produce the diagnosis:\n\n"
        + json.dumps(context, ensure_ascii=False)
    )
    text, response = _call(client, system=diagnosis_system(lang), user_content=user_content)
    return {
        "diagnosis": text.strip(),
        "model": response.model,
        "usage": {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
        },
    }


def translate_query(question: str, analysis: AnalysisResult, lang: str = "es") -> Dict[str, Any]:
    if config.LLM_DEMO:
        from .demo import demo_query

        return demo_query(question, analysis, lang)
    client = _require_client()
    context = build_llm_context(analysis)
    user_content = (
        "Question: %s\n\nCapture summary JSON:\n%s"
        % (question, json.dumps(context, ensure_ascii=False))
    )
    text, response = _call(
        client,
        system=query_system(lang),
        user_content=user_content,
        output_schema=QUERY_OUTPUT_SCHEMA,
    )
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        raise AIServiceError("El modelo devolvió una respuesta no parseable.")

    valid_streams = {c.stream_id for c in analysis.conversations.tcp}
    valid_issues = {i.id for i in analysis.issues}
    matched_issue_ids = [
        i for i in data["matched_issue_ids"] if i in valid_issues
    ]
    issue_streams = {
        int(issue.evidence[key])
        for issue in analysis.issues
        if issue.id in matched_issue_ids
        for key in ("stream_id", "tcp_stream")
        if isinstance(issue.evidence.get(key), int)
    }
    return {
        "filter": data["filter"],
        "explanation": data["explanation"],
        "matched_tcp_streams": sorted(
            set(s for s in data["matched_tcp_streams"] if s in valid_streams)
            | (issue_streams & valid_streams)
        ),
        "matched_issue_ids": matched_issue_ids,
        "model": response.model,
    }
