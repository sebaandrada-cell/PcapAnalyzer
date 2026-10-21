"""HTTP endpoints for the AI layer (Fase 3)."""
from __future__ import annotations

from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

try:
    from typing import Literal
except ImportError:  # pragma: no cover
    from typing_extensions import Literal

from ..models import AnalysisResult
from ..auth import require_api_token_no_rate_limit
from .service import AIServiceError, AIUnavailableError, diagnose, translate_query

router = APIRouter(dependencies=[Depends(require_api_token_no_rate_limit)])

Lang = Literal["es", "en"]


class DiagnoseRequest(BaseModel):
    analysis: AnalysisResult
    lang: Lang = "es"


class DiagnoseResponse(BaseModel):
    diagnosis: str
    model: str
    usage: Dict[str, int]


class QueryRequest(BaseModel):
    question: str = Field(min_length=3, max_length=500)
    analysis: AnalysisResult
    lang: Lang = "es"


class QueryResponse(BaseModel):
    filter: str
    explanation: str
    matched_tcp_streams: List[int]
    matched_issue_ids: List[str]
    model: str


def _handle(callable_, *args):
    try:
        return callable_(*args)
    except AIUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except AIServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))


@router.post("/diagnose", response_model=DiagnoseResponse)
def diagnose_endpoint(request: DiagnoseRequest) -> DiagnoseResponse:
    return DiagnoseResponse(**_handle(diagnose, request.analysis, request.lang))


@router.post("/query", response_model=QueryResponse)
def query_endpoint(request: QueryRequest) -> QueryResponse:
    return QueryResponse(
        **_handle(translate_query, request.question, request.analysis, request.lang)
    )
