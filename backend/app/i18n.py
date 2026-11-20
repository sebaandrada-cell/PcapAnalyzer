"""Language of user-facing API messages.

The web app sends ``Accept-Language: es|en``; a middleware stores it in a
context variable for the request, and ``tr(es, en)`` picks the right text.
Without the header the API keeps answering in Spanish, as it always did.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Literal, Optional

Lang = Literal["es", "en"]

_current: ContextVar[str] = ContextVar("api_lang", default="es")


def lang_from_header(value: Optional[str]) -> Lang:
    """First language tag of an Accept-Language header: English or Spanish."""
    if not value:
        return "es"
    first = value.split(",", 1)[0].strip().lower()
    return "en" if first.startswith("en") else "es"


def current_lang() -> Lang:
    return "en" if _current.get() == "en" else "es"


def set_lang(lang: str):
    """Set the language for the current context; returns the reset token."""
    return _current.set("en" if lang == "en" else "es")


def reset_lang(token) -> None:
    _current.reset(token)


@contextmanager
def use_lang(lang: str) -> Iterator[None]:
    token = set_lang(lang)
    try:
        yield
    finally:
        _current.reset(token)


def tr(es: str, en: str) -> str:
    return en if current_lang() == "en" else es
