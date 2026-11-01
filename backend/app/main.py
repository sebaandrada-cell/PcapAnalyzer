"""FastAPI application: HTTP layer over the analysis engine.

Kept deliberately thin — all analysis logic lives in ``app.analysis`` so the
future LLM layer (and any CLI) can reuse it without going through HTTP.
"""
from __future__ import annotations

import logging
import os
import re
import tempfile
import gzip
import zlib
from contextlib import asynccontextmanager
from typing import Awaitable, Callable, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import __version__, config
from .analysis import analyze_pcap
from .auth import (
    Principal,
    analysis_concurrency,
    authenticate_authorization_header,
    require_api_token_no_rate_limit,
)
from .guards import client_ip, ip_limiter
from .jobs import JobCapacityError, job_store
from .llm.client import availability as ai_availability
from .llm.router import router as ai_router
from .models import AnalysisResult
from .report import build_report
from .supabase_jobs import shared_job_store
from .tshark import (
    TsharkError,
    TsharkTimeoutError,
    find_tshark,
    install_instructions,
    tshark_version,
)

# Accepted capture magic numbers. Kept as an allowlist on purpose: it is a
# cheap defense-in-depth gate in front of tshark's dissector attack surface,
# so an obviously-wrong upload (an image, a PDF) is rejected before tshark ever
# parses it. tshark itself remains the authority on whether the bytes are a
# real capture.
#   - classic pcap, micro/nanosecond resolution, both endians
#   - pcapng section header block
#   - gzip: tshark reads .pcap.gz / .pcapng.gz natively (very common export)
# zstd (b"\x28\xb5\x2f\xfd") and lz4 are only supported by newer Wireshark
# builds — add them once the minimum tshark version is pinned (verificar).
_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
    b"\x0a\x0d\x0d\x0a",  # pcapng section header block
    b"\x1f\x8b\x08\x00",  # gzip (deflate, no flags) — e.g. capture.pcap.gz
}

# gzip only pins the first two bytes + method; the 4th byte (flags) varies, so
# match on the 3-byte prefix for the gzip case.
_GZIP_PREFIX = b"\x1f\x8b\x08"


def _looks_like_capture(head: bytes) -> bool:
    return head[:4] in _PCAP_MAGICS or head[:3] == _GZIP_PREFIX

@asynccontextmanager
async def lifespan(_: FastAPI):
    """Fail loudly (in logs) at startup when tshark is missing (CLAUDE.md)."""
    logger = logging.getLogger("uvicorn.error")
    tshark_path = find_tshark()
    if tshark_path is None:
        logger.error("tshark NO detectado — /analyze devolverá 503. %s",
                     install_instructions())
    else:
        logger.info("tshark detectado en %s", tshark_path)
    yield


app = FastAPI(
    title="PCAP Analyzer API",
    version=__version__,
    description="Análisis de capturas .pcap/.pcapng basado en tshark.",
    lifespan=lifespan,
    docs_url="/docs" if config.DOCS_ENABLED else None,
    redoc_url="/redoc" if config.DOCS_ENABLED else None,
    openapi_url="/openapi.json" if config.DOCS_ENABLED else None,
)

app.include_router(ai_router)


@app.middleware("http")
async def authenticate_api_requests(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Reject unauthenticated uploads before FastAPI parses multipart bodies."""
    path = request.url.path
    protected = (
        path in {"/analyze", "/analyze/async", "/report", "/diagnose", "/query"}
        or path.startswith("/jobs/")
    )
    if protected and request.method in {"GET", "POST"}:
        try:
            request.state.principal = authenticate_authorization_header(
                request.headers.get("authorization"),
                charge=not path.startswith("/jobs/"),
            )
        except HTTPException as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers=exc.headers,
            )
    return await call_next(request)


@app.middleware("http")
async def throttle_and_cap_body(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Per-IP throttle and body-size cap, applied before auth and parsing.

    Registered after ``authenticate_api_requests`` so it runs first (Starlette
    runs the last-added middleware outermost). Bots hitting any route are
    stopped here at no database or egress cost.
    """
    if request.method == "OPTIONS":
        return await call_next(request)
    ip = client_ip(request)
    path = request.url.path
    if os.getenv("DEBUG_CLIENT_IP_HEADERS") == "1" and path == "/health":
        # Temporary, opt-in: only IP-related headers, never cookies or auth.
        logging.getLogger("uvicorn.error").info(
            "client-ip debug: xff=%r cf=%r real=%r peer=%r chosen=%r",
            request.headers.get("x-forwarded-for"),
            request.headers.get("cf-connecting-ip"),
            request.headers.get("x-real-ip"),
            request.client.host if request.client else None,
            ip,
        )
    try:
        ip_limiter.check("all:" + ip, config.IP_MAX_REQUESTS_PER_MINUTE)
        if path in {"/analyze", "/analyze/async"}:
            ip_limiter.check("up:" + ip, config.IP_MAX_UPLOADS_PER_MINUTE)
    except HTTPException as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers,
        )
    # Uploads may be MAX_UPLOAD_MB (+ multipart overhead); everything else is JSON.
    limit = (
        (config.MAX_UPLOAD_MB + 1) * 1024 * 1024
        if path in {"/analyze", "/analyze/async"}
        else 4 * 1024 * 1024
    )
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            too_big = int(declared) > limit
        except ValueError:
            too_big = True
        if too_big:
            return JSONResponse(
                status_code=413,
                content={"detail": "Cuerpo de la solicitud demasiado grande."},
            )
    elif request.method in {"POST", "PUT", "PATCH"}:
        return JSONResponse(
            status_code=411,
            content={"detail": "Se requiere Content-Length."},
        )
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.get("/health")
def health() -> dict:
    tshark_path = find_tshark()
    return {
        "status": "ok",
        "version": __version__,
        "tshark": {
            "available": tshark_path is not None,
            "path": tshark_path,
            "version": tshark_version(tshark_path) if tshark_path else None,
            "install_hint": None if tshark_path else install_instructions(),
        },
        "ai": ai_availability(),
        "auth": {
            "enabled": config.SUPABASE_ENABLED or bool(config.API_TOKENS),
            "mode": config.AUTH_MODE,
        },
        "shared_queue": config.SUPABASE_ENABLED,
        "max_upload_mb": config.MAX_UPLOAD_MB,
        "max_decompressed_mb": config.MAX_DECOMPRESSED_MB,
    }


def _save_upload(file: UploadFile) -> str:
    """Stream the upload to a temp file enforcing size and magic checks."""
    max_bytes = config.MAX_UPLOAD_MB * 1024 * 1024
    total = 0
    is_gzip = False
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    try:
        first_chunk = True
        while True:
            chunk = file.file.read(1024 * 1024)
            if not chunk:
                break
            if first_chunk:
                if not _looks_like_capture(chunk):
                    raise HTTPException(
                        status_code=400,
                        detail="El archivo no parece una captura válida. Se "
                        "aceptan .pcap, .pcapng y sus versiones comprimidas "
                        "con gzip (.pcap.gz / .pcapng.gz).",
                    )
                is_gzip = chunk[:3] == _GZIP_PREFIX
                first_chunk = False
            total += len(chunk)
            if total > max_bytes:
                raise HTTPException(
                    status_code=413,
                    detail="El archivo supera el máximo de %d MB." % config.MAX_UPLOAD_MB,
                )
            tmp.write(chunk)
        if total == 0:
            raise HTTPException(status_code=400, detail="El archivo está vacío.")
        tmp.close()
        if is_gzip:
            expanded = 0
            max_expanded = config.MAX_DECOMPRESSED_MB * 1024 * 1024
            try:
                with gzip.open(tmp.name, "rb") as capture:
                    while chunk := capture.read(1024 * 1024):
                        expanded += len(chunk)
                        if expanded > max_expanded:
                            raise HTTPException(
                                status_code=413,
                                detail="La captura gzip supera el máximo descomprimido de %d MB."
                                % config.MAX_DECOMPRESSED_MB,
                            )
            except (OSError, EOFError, zlib.error) as exc:
                raise HTTPException(
                    status_code=400,
                    detail="El archivo gzip no contiene una captura comprimida válida.",
                ) from exc
        return tmp.name
    except Exception:
        tmp.close()
        os.unlink(tmp.name)
        raise


@app.post("/analyze", response_model=AnalysisResult)
def analyze(
    file: UploadFile = File(...),
    principal: Principal = Depends(require_api_token_no_rate_limit),
) -> AnalysisResult:
    tmp_path = None
    shared_lease_id = None
    local_slot_acquired = False
    try:
        tshark_path = find_tshark()
        if tshark_path is None:
            raise HTTPException(status_code=503, detail=install_instructions())
        tmp_path = _save_upload(file)
        if principal.auth_mode == "supabase":
            if shared_job_store is None:
                raise HTTPException(
                    status_code=503,
                    detail="La cola compartida no está configurada.",
                )
            shared_lease_id = shared_job_store.acquire_sync_slot(principal.tenant_id)
        else:
            analysis_concurrency.acquire(principal.tenant_id)
            local_slot_acquired = True
        size_bytes = os.path.getsize(tmp_path)
        return analyze_pcap(
            tshark_path=tshark_path,
            pcap_path=tmp_path,
            original_filename=file.filename or "capture.pcap",
            size_bytes=size_bytes,
        )
    except TsharkTimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc))
    except TsharkError as exc:
        raise HTTPException(
            status_code=422,
            detail="tshark no pudo procesar el archivo: %s" % exc,
        )
    finally:
        if tmp_path is not None and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        if shared_lease_id is not None and shared_job_store is not None:
            shared_job_store.release_sync_slot(shared_lease_id)
        if local_slot_acquired:
            analysis_concurrency.release(principal.tenant_id)


@app.post("/analyze/async", status_code=202)
def analyze_async(
    file: UploadFile = File(...),
    principal: Principal = Depends(require_api_token_no_rate_limit),
) -> dict:
    """Queue a capture for background analysis (large files)."""
    tshark_path = find_tshark()
    if tshark_path is None:
        raise HTTPException(status_code=503, detail=install_instructions())

    tmp_path = _save_upload(file)
    try:
        if principal.auth_mode == "supabase":
            if shared_job_store is None:
                raise HTTPException(
                    status_code=503,
                    detail="La cola compartida no está configurada.",
                )
            job = shared_job_store.submit(
                local_path=tmp_path,
                filename=file.filename or "capture.pcap",
                size_bytes=os.path.getsize(tmp_path),
                owner_id=principal.user_id,
                tenant_id=principal.tenant_id,
            )
            try:
                os.unlink(tmp_path)
                tmp_path = None
            except OSError:
                logging.getLogger("uvicorn.error").error(
                    "No se pudo borrar la copia temporal tras almacenarla en Supabase."
                )
        else:
            job = job_store.submit(
                tshark_path=tshark_path,
                pcap_path=tmp_path,
                filename=file.filename or "capture.pcap",
                size_bytes=os.path.getsize(tmp_path),
                owner_id=principal.tenant_id,
            )
    except JobCapacityError as exc:
        os.unlink(tmp_path)
        raise HTTPException(status_code=429, detail=str(exc))
    except Exception:
        os.unlink(tmp_path)
        raise
    return {"job_id": job.id, "status": job.status}


@app.get("/jobs/{job_id}")
def job_status(
    job_id: str,
    principal: Principal = Depends(require_api_token_no_rate_limit),
) -> dict:
    if principal.auth_mode == "supabase":
        job = (
            shared_job_store.get(job_id, tenant_id=principal.tenant_id)
            if shared_job_store is not None
            else None
        )
    else:
        job = job_store.get(job_id, owner_id=principal.tenant_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Trabajo no encontrado o expirado.")
    payload = {"job_id": job.id, "status": job.status, "filename": job.filename}
    if job.status == "done" and job.result is not None:
        payload["result"] = job.result.model_dump()
    elif job.status == "error":
        payload["error"] = job.error
    return payload


class ReportRequest(BaseModel):
    analysis: AnalysisResult
    diagnosis: Optional[str] = None


@app.post("/report")
def report(
    request: ReportRequest,
    _principal: Principal = Depends(require_api_token_no_rate_limit),
) -> Response:
    """Build the downloadable PDF report (Fase 4)."""
    pdf_bytes = build_report(request.analysis, request.diagnosis)
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", request.analysis.file.name)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="informe-%s.pdf"' % safe_name
        },
    )
