"""HTTP surface of investigation sessions (and, later, the agent chat)."""
from __future__ import annotations

from dataclasses import asdict
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from ..auth import Principal, require_api_token_no_rate_limit
from ..sessions import Session, session_store

router = APIRouter()


class SessionPatch(BaseModel):
    content_allowed: bool


class SessionStatus(BaseModel):
    id: str
    expires_at: float
    ttl_minutes: int
    content_allowed: bool
    usage: Dict[str, int]
    messages: int


def _not_found() -> HTTPException:
    # 404 for foreign sessions too: do not reveal that the id exists.
    return HTTPException(status_code=404, detail="Sesión no encontrada o caducada.")


def _status(session: Session) -> SessionStatus:
    from .. import config

    return SessionStatus(
        id=session.id,
        expires_at=session.expires_at(),
        ttl_minutes=config.SESSION_TTL_MINUTES,
        content_allowed=session.content_allowed,
        usage=asdict(session.usage),
        messages=sum(1 for m in session.messages if m.get("role") == "user"),
    )


@router.get("/sessions/{session_id}", response_model=SessionStatus)
def session_status(
    session_id: str,
    principal: Principal = Depends(require_api_token_no_rate_limit),
) -> SessionStatus:
    session = session_store.peek(session_id, principal.tenant_id)  # status checks do not renew the TTL
    if session is None:
        raise _not_found()
    return _status(session)


@router.patch("/sessions/{session_id}", response_model=SessionStatus)
def session_patch(
    session_id: str,
    patch: SessionPatch,
    principal: Principal = Depends(require_api_token_no_rate_limit),
) -> SessionStatus:
    session = session_store.get(session_id, principal.tenant_id)
    if session is None:
        raise _not_found()
    session.content_allowed = patch.content_allowed
    return _status(session)


@router.delete("/sessions/{session_id}", status_code=204, response_class=Response)
def session_delete(
    session_id: str,
    principal: Principal = Depends(require_api_token_no_rate_limit),
) -> Response:
    if not session_store.delete(session_id, principal.tenant_id):
        raise _not_found()
    return Response(status_code=204)
