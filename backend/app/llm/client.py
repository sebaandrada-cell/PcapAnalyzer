"""Anthropic client construction and availability checks.

Credentials resolve from the environment (ANTHROPIC_API_KEY,
ANTHROPIC_AUTH_TOKEN or an `ant auth login` profile) — never hardcoded.
"""
from __future__ import annotations

from typing import Optional

from .. import config

_client = None
_client_error: Optional[str] = None


def get_client():
    """Return a cached Anthropic client, or None when no credentials exist."""
    global _client, _client_error
    if _client is not None or _client_error is not None:
        return _client
    try:
        import anthropic

        candidate = anthropic.Anthropic(timeout=config.LLM_TIMEOUT_S, max_retries=1)
        # The SDK constructs fine without credentials and only fails at
        # request time — verify a credential source actually resolved.
        # Truthiness matters: an empty ANTHROPIC_API_KEY= in .env must not
        # count as configured.
        has_credentials = bool(
            candidate.api_key
            or candidate.auth_token
            or getattr(candidate, "credentials", None)
        )
        if not has_credentials:
            _client_error = "no credentials"
            return None
        _client = candidate
    except Exception as exc:  # missing package or broken environment
        _client_error = str(exc)
        _client = None
    return _client


def availability() -> dict:
    if config.LLM_DEMO:
        return {"available": True, "model": "demo", "hint": None}
    client = get_client()
    return {
        "available": client is not None,
        "model": config.LLM_MODEL if client is not None else None,
        "hint": None if client is not None else (
            "La capa IA no está configurada: define ANTHROPIC_API_KEY en el "
            "entorno del backend (o inicia sesión con 'ant auth login') y "
            "reinicia el servidor."
        ),
    }


def reset_client() -> None:
    """Testing hook: drop the cached client so availability is re-evaluated."""
    global _client, _client_error
    _client = None
    _client_error = None
