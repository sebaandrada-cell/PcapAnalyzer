"""In-process job queue for large captures (Fase 4).

Deliberately broker-less to keep the on-premise deployment a single container:
a small thread pool analyzes queued pcaps and results are kept in memory with
a TTL. The uploaded file is deleted as soon as its analysis finishes.
"""
from __future__ import annotations

import contextvars
import logging
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, Optional

from . import config
from .analysis import analyze_pcap
from .models import AnalysisResult
from .i18n import tr


@dataclass
class Job:
    id: str
    filename: str
    owner_id: str
    size_bytes: int = 0
    status: str = "queued"  # queued | running | done | error
    created_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    result: Optional[AnalysisResult] = None
    error: Optional[str] = None


class JobCapacityError(RuntimeError):
    pass


class JobStore:
    def __init__(
        self,
        workers: int,
        ttl_s: int,
        max_queued: int,
        max_per_token: int,
        max_pending_bytes: int,
        max_retained_jobs: int,
    ):
        self._jobs: Dict[str, Job] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=workers)
        self._ttl_s = ttl_s
        self._max_queued = max_queued
        self._max_per_token = max_per_token
        self._max_pending_bytes = max_pending_bytes
        self._max_retained_jobs = max_retained_jobs

    def submit(self, tshark_path: str, pcap_path: str, filename: str,
               size_bytes: int, owner_id: str) -> Job:
        job = Job(
            id=uuid.uuid4().hex,
            filename=filename,
            owner_id=owner_id,
            size_bytes=size_bytes,
        )
        with self._lock:
            self._cleanup_locked()
            outstanding = [
                existing for existing in self._jobs.values()
                if existing.status in ("queued", "running")
            ]
            owner_outstanding = sum(
                existing.owner_id == owner_id for existing in outstanding
            )
            queued = sum(existing.status == "queued" for existing in outstanding)
            if owner_outstanding >= self._max_per_token:
                raise JobCapacityError(
                    tr("Este token ya alcanzó el máximo de análisis simultáneos.", "This token already reached its maximum of concurrent analyses.")
                )
            if queued >= self._max_queued:
                raise JobCapacityError(
                    tr("La cola de análisis está llena; inténtalo de nuevo más tarde.", "The analysis queue is full; try again later.")
                )
            pending_bytes = sum(existing.size_bytes for existing in outstanding)
            if pending_bytes + size_bytes > self._max_pending_bytes:
                raise JobCapacityError(
                    tr("La capacidad reservada para capturas en espera está llena.", "The space reserved for waiting captures is full.")
                )
            self._jobs[job.id] = job
            try:
                # Run in a copy of the request context so job errors use the
                # language the upload asked for.
                self._executor.submit(contextvars.copy_context().run, self._run, job,
                                      tshark_path, pcap_path, filename, size_bytes)
            except Exception:
                del self._jobs[job.id]
                raise
        return job

    def get(self, job_id: str, owner_id: str) -> Optional[Job]:
        with self._lock:
            self._cleanup_locked()
            job = self._jobs.get(job_id)
            if job is None or job.owner_id != owner_id:
                return None
            return job

    def _run(self, job: Job, tshark_path: str, pcap_path: str,
             filename: str, size_bytes: int) -> None:
        with self._lock:
            job.status = "running"
        result: Optional[AnalysisResult] = None
        error: Optional[str] = None
        try:
            result = analyze_pcap(
                tshark_path=tshark_path, pcap_path=pcap_path,
                original_filename=filename, size_bytes=size_bytes,
            )
            self._attach_session(result, job.owner_id, pcap_path, filename)
        except Exception as exc:
            error = str(exc)
        finally:
            try:
                os.unlink(pcap_path)
            except OSError:
                logging.getLogger("uvicorn.error").error(
                    "No se pudo borrar una captura temporal al finalizar el trabajo."
                )
            with self._lock:
                job.result = result
                job.error = error
                job.status = "error" if error is not None else "done"
                job.finished_at = time.time()
                self._cleanup_locked()

    @staticmethod
    def _attach_session(result: AnalysisResult, owner_id: str, pcap_path: str,
                        filename: str) -> None:
        """Local queue only: keep the capture for the investigation session."""
        if not config.SESSIONS_ENABLED:
            return
        from .sessions import session_info, session_store

        try:
            session = session_store.create(owner_id, pcap_path, filename, result)
        except Exception:
            logging.getLogger("uvicorn.error").warning(
                "No se pudo crear la sesión de investigación para el trabajo.",
                exc_info=True,
            )
            return
        result.session = session_info(session)

    def _cleanup_locked(self) -> None:
        now = time.time()
        expired = [
            job_id for job_id, job in self._jobs.items()
            if job.finished_at is not None and now - job.finished_at > self._ttl_s
        ]
        for job_id in expired:
            del self._jobs[job_id]
        completed = sorted(
            (
                job for job in self._jobs.values()
                if job.finished_at is not None
            ),
            key=lambda job: job.finished_at or 0,
        )
        while len(completed) > self._max_retained_jobs:
            oldest = completed.pop(0)
            self._jobs.pop(oldest.id, None)


job_store = JobStore(
    workers=config.ANALYZE_WORKERS,
    ttl_s=config.JOB_TTL_S,
    max_queued=config.MAX_QUEUED_JOBS,
    max_per_token=config.API_MAX_JOBS_PER_TOKEN,
    max_pending_bytes=config.MAX_PENDING_CAPTURE_BYTES,
    max_retained_jobs=config.MAX_RETAINED_JOBS,
)
