"""Cost and abuse guards: per-IP throttling and hard daily caps on paid AI calls."""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque, Dict

from fastapi import HTTPException, Request

from . import config
from .i18n import tr

_WINDOW_SECONDS = 60.0
_MAX_TRACKED_KEYS = 10000


def client_ip(request: Request) -> str:
    """Best-effort client IP behind reverse proxies.

    Every trusted proxy appends the address it saw to X-Forwarded-For, so we
    skip ``TRUSTED_PROXY_HOPS`` entries from the right and take the next one;
    entries further left are client-supplied and spoofable. With fewer entries
    than expected we fall back to the rightmost one (shared bucket, never
    spoofable), so a short or malformed header never raises.
    """
    entries = [
        e.strip()
        for e in request.headers.get("x-forwarded-for", "").split(",")
        if e.strip()
    ]
    if entries:
        index = len(entries) - 1 - config.TRUSTED_PROXY_HOPS
        return entries[index] if index >= 0 else entries[-1]
    return request.client.host if request.client else "unknown"


class IpRateLimiter:
    """Sliding-window limiter with a bounded key table (no unbounded memory)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: Dict[str, Deque[float]] = {}

    def check(self, key: str, limit: int) -> None:
        if limit <= 0:
            return
        now = time.monotonic()
        with self._lock:
            if key not in self._hits and len(self._hits) >= _MAX_TRACKED_KEYS:
                self._evict(now)
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= _WINDOW_SECONDS:
                hits.popleft()
            if len(hits) >= limit:
                retry = max(1, int(_WINDOW_SECONDS - (now - hits[0])))
                raise HTTPException(
                    status_code=429,
                    detail=tr("Demasiadas solicitudes desde esta IP. Inténtalo en unos segundos.", "Too many requests from this IP. Try again in a few seconds."),
                    headers={"Retry-After": str(retry)},
                )
            hits.append(now)

    def _evict(self, now: float) -> None:
        for key in [k for k, v in self._hits.items() if not v or now - v[-1] >= _WINDOW_SECONDS]:
            del self._hits[key]
        if len(self._hits) >= _MAX_TRACKED_KEYS:
            self._hits.clear()  # under a flood, fail open on memory, not on cost


class DailyBudget:
    """Hard cap on paid calls per principal and globally, reset every 24 h."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._day = int(time.time() // 86400)
        self._per_principal: Dict[str, int] = {}
        self._global = 0

    def consume(self, principal: str) -> None:
        with self._lock:
            today = int(time.time() // 86400)
            if today != self._day:
                self._day = today
                self._per_principal.clear()
                self._global = 0
            if config.LLM_MAX_CALLS_PER_DAY_GLOBAL and self._global >= config.LLM_MAX_CALLS_PER_DAY_GLOBAL:
                raise HTTPException(
                    status_code=429,
                    detail=tr("Límite diario global de diagnósticos IA alcanzado. Vuelve mañana.", "The global daily AI limit was reached. Come back tomorrow."),
                )
            used = self._per_principal.get(principal, 0)
            if config.LLM_MAX_CALLS_PER_DAY and used >= config.LLM_MAX_CALLS_PER_DAY:
                raise HTTPException(
                    status_code=429,
                    detail=tr("Has alcanzado el límite diario de consultas IA.", "You reached your daily AI limit."),
                )
            self._per_principal[principal] = used + 1
            self._global += 1


ip_limiter = IpRateLimiter()
llm_budget = DailyBudget()
