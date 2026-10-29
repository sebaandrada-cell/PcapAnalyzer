"""Cost and abuse guards: per-IP throttling and hard daily caps on paid AI calls."""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque, Dict

from fastapi import HTTPException, Request

from . import config

_WINDOW_SECONDS = 60.0
_MAX_TRACKED_KEYS = 10000


def client_ip(request: Request) -> str:
    """Best-effort client IP behind a reverse proxy.

    Render/nginx append the connecting address to X-Forwarded-For, so the last
    entry is the one our own proxy saw; earlier entries are client-supplied and
    spoofable.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        last = forwarded.split(",")[-1].strip()
        if last:
            return last
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
                    detail="Demasiadas solicitudes desde esta IP. Inténtalo en unos segundos.",
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
                    detail="Límite diario global de diagnósticos IA alcanzado. Vuelve mañana.",
                )
            used = self._per_principal.get(principal, 0)
            if config.LLM_MAX_CALLS_PER_DAY and used >= config.LLM_MAX_CALLS_PER_DAY:
                raise HTTPException(
                    status_code=429,
                    detail="Has alcanzado el límite diario de consultas IA.",
                )
            self._per_principal[principal] = used + 1
            self._global += 1


ip_limiter = IpRateLimiter()
llm_budget = DailyBudget()
