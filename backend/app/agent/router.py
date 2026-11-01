"""HTTP surface of investigation sessions and the agent chat (SSE)."""
from __future__ import annotations

import json
import logging
import queue
import threading
from dataclasses import asdict
from typing import Dict, Iterator

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from starlette.responses import StreamingResponse

try:
    from typing import Literal
except ImportError:  # pragma: no cover
    from typing_extensions import Literal

from .. import config
from ..auth import Principal, require_api_token_no_rate_limit
from ..guards import llm_budget
from ..llm.client import availability, get_client
from ..llm.service import AIServiceError, AIUnavailableError
from ..sessions import Session, session_store
from ..tshark import find_tshark, install_instructions
from .demo import DEMO_CHAT_REPLY, demo_investigation
from .prompts import INVESTIGATE_SENTINEL
from .runner import AgentLimitError, SessionGoneError, TurnCancelled, TurnEvent, run_turn

logger = logging.getLogger("pcapanalyzer.agent")
router = APIRouter()
_workers = threading.BoundedSemaphore(max(1, config.AGENT_WORKERS))


def ai_available() -> bool:  # module attribute so tests can swap it
    return get_client() is not None


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


# ---- chat --------------------------------------------------------------------------
class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    lang: Literal["es", "en"] = "es"


_SSE_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}


def _sse(event: str, data: dict) -> str:
    return "event: %s\ndata: %s\n\n" % (event, json.dumps(data, ensure_ascii=False))


_GENERIC_ERROR = "La investigación falló; inténtalo de nuevo."
_SESSION_GONE = "La captura ya no está disponible; vuelve a analizarla."


def _demo_stream(session: Session, request: ChatRequest) -> Iterator[str]:
    try:
        if request.message == INVESTIGATE_SENTINEL:
            text = demo_investigation(session.analysis, request.lang)
            session.messages.append({"role": "user", "content": request.message})
            session.messages.append({"role": "assistant", "content": [{"type": "text", "text": text}]})
        else:
            text = DEMO_CHAT_REPLY.get(request.lang, DEMO_CHAT_REPLY["es"])
        for paragraph in text.split("\n\n"):
            yield _sse("text", {"delta": paragraph + "\n\n"})
        yield _sse("done", {"stop_reason": "end_turn", "limited": False, "demo": True})
    finally:
        session.lock.release()


class _TurnStream:
    """Iterable of SSE frames for one turn.

    The worker thread owns the session lock and the worker slot and releases
    them itself when the turn ends. Closing (or dropping) this stream only sets
    the cancel flag: the turn stops at its next event and is not persisted.
    """

    def __init__(self) -> None:
        self.events: "queue.Queue[object]" = queue.Queue()
        self.finished = object()
        self.cancel = threading.Event()

    def __iter__(self) -> Iterator[str]:
        try:
            while True:
                item = self.events.get()
                if item is self.finished:
                    break
                assert isinstance(item, TurnEvent)
                yield _sse(item.type, item.data)
        finally:
            self.cancel.set()

    def close(self) -> None:
        self.cancel.set()

    def __del__(self) -> None:  # the client went away without consuming the stream
        self.cancel.set()


def _start_turn(session: Session, request: ChatRequest, tshark_path: str) -> _TurnStream:
    """Acquire the session lock and a worker slot, hand them to the worker thread."""
    if not session.lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Hay una investigación en curso en esta sesión.")
    if not _workers.acquire(blocking=False):
        session.lock.release()
        raise HTTPException(status_code=429, detail="Hay demasiadas investigaciones en curso; inténtalo en un momento.")
    stream = _TurnStream()
    events, finished, cancel = stream.events, stream.finished, stream.cancel

    def worker() -> None:
        try:
            run_turn(session, request.message, request.lang, tshark_path, events.put, cancel=cancel)
        except TurnCancelled:
            pass
        except SessionGoneError:
            events.put(TurnEvent("error", {"code": "session_expired", "message": _SESSION_GONE}))
        except AgentLimitError as exc:
            events.put(TurnEvent("error", {"code": "session_tokens", "message": str(exc)}))
        except (AIServiceError, AIUnavailableError) as exc:
            events.put(TurnEvent("error", {"code": "model", "message": str(exc)}))
        except Exception:
            logger.exception("Investigation turn failed")
            events.put(TurnEvent("error", {"code": "internal", "message": _GENERIC_ERROR}))
        finally:
            _workers.release()
            session.lock.release()
            events.put(finished)

    threading.Thread(target=worker, name="agent-turn", daemon=True).start()
    return stream


@router.post("/sessions/{session_id}/chat")
def session_chat(
    session_id: str,
    request: ChatRequest,
    principal: Principal = Depends(require_api_token_no_rate_limit),
) -> StreamingResponse:
    session = session_store.get(session_id, principal.tenant_id)
    if session is None:
        raise _not_found()
    if request.message == INVESTIGATE_SENTINEL and session.messages:
        raise HTTPException(status_code=409, detail="La investigación inicial ya se hizo en esta sesión.")
    if session.lock.locked():
        raise HTTPException(status_code=409, detail="Hay una investigación en curso en esta sesión.")
    if config.LLM_DEMO:
        if not session.lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="Hay una investigación en curso en esta sesión.")
        return StreamingResponse(_demo_stream(session, request), media_type="text/event-stream", headers=_SSE_HEADERS)
    if not ai_available():
        raise HTTPException(status_code=503, detail=availability()["hint"])
    tshark_path = find_tshark()
    if tshark_path is None:
        raise HTTPException(status_code=503, detail=install_instructions())
    llm_budget.consume(principal.tenant_id)  # one question = one paid call for the daily caps
    return StreamingResponse(_start_turn(session, request, tshark_path), media_type="text/event-stream", headers=_SSE_HEADERS)
