"""Bearer-token authentication and per-token request quotas."""
from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional
from urllib.error import URLError

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError, PyJWTError
from jwt import PyJWKClient

from . import config
from . import shared_db

_bearer = HTTPBearer(auto_error=False)
_WINDOW_SECONDS = 60.0


class RequestQuota:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: Dict[str, Deque[float]] = defaultdict(deque)

    def consume(self, principal: str) -> None:
        now = time.monotonic()
        with self._lock:
            requests = self._requests[principal]
            while requests and now - requests[0] >= _WINDOW_SECONDS:
                requests.popleft()
            if len(requests) >= config.API_MAX_REQUESTS_PER_MINUTE:
                raise HTTPException(
                    status_code=429,
                    detail="Se alcanzó el límite de solicitudes por minuto para este token.",
                    headers={"Retry-After": str(max(1, int(_WINDOW_SECONDS - (now - requests[0]))))},
                )
            requests.append(now)
            if not requests:
                self._requests.pop(principal, None)


_request_quota = RequestQuota()
_jwks_client: Optional[PyJWKClient] = None


@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    auth_mode: str


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail="Token no válido o expirado.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_api_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Principal:
    cached = getattr(request.state, "principal", None)
    if isinstance(cached, Principal):
        return cached
    return _authenticate(credentials, charge=True)


def require_api_token_no_rate_limit(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Principal:
    cached = getattr(request.state, "principal", None)
    if isinstance(cached, Principal):
        return cached
    return _authenticate(credentials, charge=False)


def authenticate_authorization_header(
    authorization: Optional[str],
    *,
    charge: bool,
) -> Principal:
    if not authorization:
        return _authenticate(None, charge=charge)
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token:
        return _authenticate(None, charge=charge)
    return _validate_token(token, charge=charge)


def _authenticate(
    credentials: Optional[HTTPAuthorizationCredentials],
    *,
    charge: bool,
) -> Principal:
    if config.SUPABASE_ENABLED:
        if credentials is None:
            raise _unauthorized()
        principal = _validate_supabase_token(credentials.credentials)
        if charge:
            shared_db.consume_request_quota(principal.tenant_id)
        return principal

    if not config.API_TOKENS:
        raise HTTPException(
            status_code=503,
            detail="La API requiere configuración: define API_TOKENS en el backend.",
        )
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Se requiere un token Bearer para usar esta API.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return _validate_token(credentials.credentials, charge=charge)


def _validate_token(candidate: str, *, charge: bool = False) -> Principal:
    if not config.API_TOKENS:
        raise HTTPException(
            status_code=503,
            detail="La API requiere configuración: define API_TOKENS en el backend.",
        )
    candidate_bytes = candidate.encode("utf-8")
    valid = False
    for token in config.API_TOKENS:
        valid = hmac.compare_digest(
            candidate_bytes, token.encode("utf-8")
        ) | valid
    if not valid:
        raise HTTPException(
            status_code=401,
            detail="Token Bearer inválido.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    principal_id = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
    if charge:
        _request_quota.consume(principal_id)
    return Principal(
        user_id=principal_id,
        tenant_id=principal_id,
        auth_mode="token",
    )


def _validate_supabase_token(candidate: str) -> Principal:
    global _jwks_client
    if not config.SUPABASE_URL or not config.SUPABASE_ANON_KEY:
        raise HTTPException(
            status_code=503,
            detail="Configura SUPABASE_URL y SUPABASE_ANON_KEY para la autenticación.",
        )

    issuer = "%s/auth/v1" % config.SUPABASE_URL
    try:
        header = jwt.get_unverified_header(candidate)
        if header.get("alg") == "HS256" and config.SUPABASE_JWT_SECRET:
            claims = jwt.decode(
                candidate,
                config.SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                audience="authenticated",
                issuer=issuer,
                options={"require": ["exp", "sub", "iss", "aud"]},
            )
        else:
            if header.get("alg") not in {"ES256", "RS256"}:
                raise _unauthorized()
            if _jwks_client is None:
                _jwks_client = PyJWKClient(
                    "%s/.well-known/jwks.json" % issuer,
                    timeout=5,
                    cache_keys=True,
                )
            signing_key = _jwks_client.get_signing_key_from_jwt(candidate)
            claims = jwt.decode(
                candidate,
                signing_key.key,
                algorithms=["ES256", "RS256"],
                audience="authenticated",
                issuer=issuer,
                options={"require": ["exp", "sub", "iss", "aud"]},
            )
    except PyJWKClientConnectionError as exc:
        raise HTTPException(
            status_code=503,
            detail="No se pudieron verificar las claves de autenticación de Supabase.",
        ) from exc
    except (PyJWTError, PyJWKClientError, URLError, TimeoutError) as exc:
        raise _unauthorized() from exc

    user_id = claims.get("sub")
    if (
        not isinstance(user_id, str)
        or not user_id
        or claims.get("role") != "authenticated"
    ):
        raise _unauthorized()
    return Principal(
        user_id=user_id,
        tenant_id=shared_db.resolve_tenant_id(user_id),
        auth_mode="supabase",
    )


class AnalysisConcurrency:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: Dict[str, int] = defaultdict(int)

    def acquire(self, principal: str) -> None:
        with self._lock:
            if self._active[principal] >= config.API_MAX_JOBS_PER_TOKEN:
                raise HTTPException(
                    status_code=429,
                    detail="Este token ya alcanzó el máximo de análisis simultáneos.",
                )
            self._active[principal] += 1

    def release(self, principal: str) -> None:
        with self._lock:
            self._active[principal] -= 1
            if self._active[principal] <= 0:
                self._active.pop(principal, None)


analysis_concurrency = AnalysisConcurrency()
