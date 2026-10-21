"""Postgres-backed tenant queue with private Supabase Storage for captures."""
from __future__ import annotations

import logging
import os
import tempfile
import uuid
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import quote

import httpx
import psycopg
from fastapi import HTTPException
from psycopg.types.json import Jsonb

from . import config, shared_db
from .jobs import JobCapacityError
from .models import AnalysisResult

logger = logging.getLogger("uvicorn.error")
_UPLOAD_RESERVATION_SECONDS = 15 * 60


@dataclass
class SharedJob:
    id: str
    filename: str
    owner_id: str
    tenant_id: str
    size_bytes: int
    status: str
    finished_at: Optional[float] = None
    result: Optional[AnalysisResult] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class ClaimedJob:
    id: str
    tenant_id: str
    owner_id: str
    filename: str
    storage_key: str
    size_bytes: int


class SupabaseJobStore:
    def __init__(self) -> None:
        if not (
            config.SUPABASE_URL
            and config.SUPABASE_ANON_KEY
            and config.SUPABASE_SERVICE_ROLE_KEY
            and config.SUPABASE_DB_URL
        ):
            raise RuntimeError(
                "Supabase mode requires SUPABASE_URL, "
                "SUPABASE_SERVICE_ROLE_KEY, and SUPABASE_DB_URL."
            )
        self._storage_url = "%s/storage/v1/object" % config.SUPABASE_URL

    def _storage_headers(self) -> Dict[str, str]:
        return {
            "apikey": config.SUPABASE_SERVICE_ROLE_KEY,
            "Authorization": "Bearer %s" % config.SUPABASE_SERVICE_ROLE_KEY,
        }

    def _object_url(self, storage_key: str) -> str:
        bucket = quote(config.SUPABASE_STORAGE_BUCKET, safe="")
        key = quote(storage_key, safe="/")
        return "%s/%s/%s" % (self._storage_url, bucket, key)

    def _upload_capture(self, local_path: str, storage_key: str, size_bytes: int) -> None:
        headers = self._storage_headers()
        headers["Content-Type"] = "application/octet-stream"
        headers["Content-Length"] = str(size_bytes)
        headers["x-upsert"] = "false"
        try:
            with open(local_path, "rb") as capture:
                response = httpx.post(
                    self._object_url(storage_key),
                    headers=headers,
                    content=iter(lambda: capture.read(1024 * 1024), b""),
                    timeout=httpx.Timeout(120, connect=10),
                )
        except (OSError, httpx.HTTPError) as exc:
            raise HTTPException(
                status_code=503,
                detail="No se pudo almacenar la captura en Supabase Storage.",
            ) from exc
        if response.status_code not in (200, 201):
            raise HTTPException(
                status_code=502,
                detail="Supabase Storage rechazó la captura.",
            )

    def delete_capture(self, storage_key: str) -> bool:
        bucket = quote(config.SUPABASE_STORAGE_BUCKET, safe="")
        try:
            response = httpx.delete(
                "%s/%s" % (self._storage_url, bucket),
                headers={
                    **self._storage_headers(),
                    "Content-Type": "application/json",
                },
                json={"prefixes": [storage_key]},
                timeout=httpx.Timeout(30, connect=5),
            )
        except httpx.HTTPError:
            return False
        return response.status_code in (200, 204, 404)

    def _mark_capture_deleted(self, storage_key: str) -> None:
        with shared_db.connection() as connection:
            connection.execute(
                """
                UPDATE public.analysis_jobs
                SET capture_deleted_at = COALESCE(capture_deleted_at, now())
                WHERE storage_key = %s
                """,
                (storage_key,),
            )

    def submit(
        self,
        *,
        local_path: str,
        filename: str,
        size_bytes: int,
        owner_id: str,
        tenant_id: str,
    ) -> SharedJob:
        job_id = str(uuid.uuid4())
        storage_key = "%s/%s/capture.pcap" % (tenant_id, job_id)
        with shared_db.connection() as connection:
            connection.execute(
                "SELECT singleton FROM public.queue_capacity_lock "
                "WHERE singleton = true FOR UPDATE"
            )
            connection.execute(
                "SELECT id FROM public.tenants WHERE id = %s FOR UPDATE",
                (tenant_id,),
            )
            connection.execute(
                """
                UPDATE public.analysis_jobs
                SET status = 'error',
                    error = 'La carga de la captura expiró antes de completarse.',
                    finished_at = now(),
                    lease_expires_at = NULL
                WHERE status = 'uploading' AND lease_expires_at <= now()
                """
            )
            connection.execute(
                """
                UPDATE public.analysis_jobs
                SET status = 'queued', started_at = NULL, lease_expires_at = NULL
                WHERE status = 'running' AND lease_expires_at <= now()
                """
            )
            connection.execute(
                "DELETE FROM public.analysis_leases WHERE expires_at <= now()"
            )
            active = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM public.analysis_jobs
                WHERE tenant_id = %s
                  AND status IN ('uploading', 'queued', 'running')
                """,
                (tenant_id,),
            ).fetchone()["count"]
            leases = connection.execute(
                """
                SELECT COUNT(*) AS count FROM public.analysis_leases
                WHERE tenant_id = %s AND expires_at > now()
                """,
                (tenant_id,),
            ).fetchone()["count"]
            if active + leases >= config.API_MAX_JOBS_PER_TOKEN:
                raise JobCapacityError(
                    "Este espacio de trabajo ya alcanzó el máximo de análisis simultáneos."
                )

            queued = connection.execute(
                "SELECT COUNT(*) AS count FROM public.analysis_jobs "
                "WHERE status IN ('uploading', 'queued')"
            ).fetchone()["count"]
            if queued >= config.MAX_QUEUED_JOBS:
                raise JobCapacityError(
                    "La cola compartida está llena; inténtalo de nuevo más tarde."
                )
            pending_bytes = connection.execute(
                """
                SELECT COALESCE(SUM(size_bytes), 0) AS bytes
                FROM public.analysis_jobs
                WHERE status IN ('uploading', 'queued', 'running')
                """
            ).fetchone()["bytes"]
            if pending_bytes + size_bytes > config.MAX_PENDING_CAPTURE_BYTES:
                raise JobCapacityError(
                    "La capacidad compartida para capturas pendientes está llena."
                )

            connection.execute(
                """
                INSERT INTO public.analysis_jobs
                    (id, tenant_id, owner_id, filename, storage_key, size_bytes,
                     status, lease_expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, 'uploading',
                        now() + (%s * INTERVAL '1 second'))
                """,
                (
                    job_id,
                    tenant_id,
                    owner_id,
                    filename,
                    storage_key,
                    size_bytes,
                    _UPLOAD_RESERVATION_SECONDS,
                ),
            )

        try:
            self._upload_capture(local_path, storage_key, size_bytes)
            with shared_db.connection() as connection:
                queued_job = connection.execute(
                    """
                    UPDATE public.analysis_jobs
                    SET status = 'queued', lease_expires_at = NULL
                    WHERE id = %s AND status = 'uploading'
                      AND lease_expires_at > now()
                    RETURNING id
                    """,
                    (job_id,),
                ).fetchone()
            if queued_job is None:
                raise HTTPException(
                    status_code=503,
                    detail="La reserva del análisis expiró antes de completar la carga.",
                )
        except Exception:
            try:
                self.cleanup_capture(storage_key)
            except HTTPException:
                logger.exception("No se pudo limpiar la captura de una carga fallida.")
            try:
                with shared_db.connection() as connection:
                    connection.execute(
                        """
                        UPDATE public.analysis_jobs
                        SET status = 'error',
                            error = 'No se pudo completar la carga de la captura.',
                            finished_at = now(),
                            lease_expires_at = NULL
                        WHERE id = %s AND status = 'uploading'
                        """,
                        (job_id,),
                    )
            except HTTPException:
                logger.exception("No se pudo registrar una carga fallida.")
            raise

        return SharedJob(
            id=job_id,
            filename=filename,
            owner_id=owner_id,
            tenant_id=tenant_id,
            size_bytes=size_bytes,
            status="queued",
        )

    def get(self, job_id: str, tenant_id: str) -> Optional[SharedJob]:
        try:
            normalized_job_id = str(uuid.UUID(job_id))
        except (ValueError, AttributeError):
            return None
        try:
            with shared_db.connection() as connection:
                row = connection.execute(
                    """
                    SELECT id, filename, owner_id, tenant_id, size_bytes, status,
                           result, error, finished_at
                    FROM public.analysis_jobs
                    WHERE id = %s AND tenant_id = %s
                      AND (
                          finished_at IS NULL
                          OR finished_at > now() - (%s * INTERVAL '1 second')
                      )
                    """,
                    (normalized_job_id, tenant_id, config.JOB_TTL_S),
                ).fetchone()
        except HTTPException:
            raise
        except psycopg.Error as exc:
            raise HTTPException(
                status_code=503,
                detail="No se pudo consultar el estado del trabajo.",
            ) from exc
        if row is None:
            return None
        result = row["result"]
        return SharedJob(
            id=str(row["id"]),
            filename=row["filename"],
            owner_id=str(row["owner_id"]),
            tenant_id=str(row["tenant_id"]),
            size_bytes=row["size_bytes"],
            status=row["status"],
            finished_at=row["finished_at"].timestamp() if row["finished_at"] else None,
            result=AnalysisResult.model_validate(result) if result is not None else None,
            error=row["error"],
        )

    def acquire_sync_slot(self, tenant_id: str) -> str:
        lease_id = str(uuid.uuid4())
        with shared_db.connection() as connection:
            connection.execute(
                "SELECT id FROM public.tenants WHERE id = %s FOR UPDATE",
                (tenant_id,),
            )
            connection.execute(
                "DELETE FROM public.analysis_leases WHERE expires_at <= now()"
            )
            active = connection.execute(
                """
                SELECT COUNT(*) AS count FROM public.analysis_jobs
                WHERE tenant_id = %s
                  AND status IN ('uploading', 'queued', 'running')
                """,
                (tenant_id,),
            ).fetchone()["count"]
            leases = connection.execute(
                """
                SELECT COUNT(*) AS count FROM public.analysis_leases
                WHERE tenant_id = %s AND expires_at > now()
                """,
                (tenant_id,),
            ).fetchone()["count"]
            if active + leases >= config.API_MAX_JOBS_PER_TOKEN:
                raise JobCapacityError(
                    "Este espacio de trabajo ya alcanzó el máximo de análisis simultáneos."
                )
            connection.execute(
                """
                INSERT INTO public.analysis_leases (id, tenant_id, expires_at)
                VALUES (%s, %s, now() + (%s * INTERVAL '1 second'))
                """,
                (lease_id, tenant_id, config.TSHARK_TIMEOUT_S + 60),
            )
        return lease_id

    def release_sync_slot(self, lease_id: str) -> None:
        with shared_db.connection() as connection:
            connection.execute(
                "DELETE FROM public.analysis_leases WHERE id = %s",
                (lease_id,),
            )

    def claim_next(self) -> Optional[ClaimedJob]:
        with shared_db.connection() as connection:
            connection.execute(
                """
                UPDATE public.analysis_jobs
                SET status = 'error',
                    error = 'La carga de la captura expiró antes de completarse.',
                    finished_at = now(),
                    lease_expires_at = NULL
                WHERE status = 'uploading' AND lease_expires_at <= now()
                """
            )
            connection.execute(
                """
                UPDATE public.analysis_jobs
                SET status = 'error',
                    error = 'El trabajo expiró antes de que un worker lo procesara.',
                    finished_at = now(),
                    lease_expires_at = NULL
                WHERE status = 'queued'
                  AND created_at <= now() - (%s * INTERVAL '1 second')
                """,
                (config.JOB_TTL_S,),
            )
            connection.execute(
                """
                UPDATE public.analysis_jobs
                SET status = 'queued', started_at = NULL, lease_expires_at = NULL
                WHERE status = 'running' AND lease_expires_at <= now()
                """
            )
            candidates = connection.execute(
                """
                SELECT id, tenant_id, owner_id, filename, storage_key, size_bytes
                FROM public.analysis_jobs
                WHERE status = 'queued'
                ORDER BY created_at
                LIMIT %s
                FOR UPDATE SKIP LOCKED
                """,
                (max(1, config.MAX_QUEUED_JOBS),),
            ).fetchall()
            for row in candidates:
                tenant_id = str(row["tenant_id"])
                connection.execute(
                    "SELECT id FROM public.tenants WHERE id = %s FOR UPDATE",
                    (tenant_id,),
                )
                leases = connection.execute(
                    """
                    SELECT COUNT(*) AS count FROM public.analysis_leases
                    WHERE tenant_id = %s AND expires_at > now()
                    """,
                    (tenant_id,),
                ).fetchone()["count"]
                running = connection.execute(
                    """
                    SELECT COUNT(*) AS count FROM public.analysis_jobs
                    WHERE tenant_id = %s AND status = 'running'
                    """,
                    (tenant_id,),
                ).fetchone()["count"]
                if running + leases >= config.API_MAX_JOBS_PER_TOKEN:
                    continue
                connection.execute(
                    """
                    UPDATE public.analysis_jobs
                    SET status = 'running',
                        started_at = now(),
                        lease_expires_at = now() + (%s * INTERVAL '1 second')
                    WHERE id = %s
                    """,
                    (config.TSHARK_TIMEOUT_S + 60, row["id"]),
                )
                return ClaimedJob(
                    id=str(row["id"]),
                    tenant_id=tenant_id,
                    owner_id=str(row["owner_id"]),
                    filename=row["filename"],
                    storage_key=row["storage_key"],
                    size_bytes=row["size_bytes"],
                )
        return None

    def download_capture(self, job: ClaimedJob, local_path: str) -> None:
        try:
            with httpx.stream(
                "GET",
                self._object_url(job.storage_key),
                headers=self._storage_headers(),
                timeout=httpx.Timeout(120, connect=10),
            ) as response:
                response.raise_for_status()
                written = 0
                with open(local_path, "wb") as capture:
                    for chunk in response.iter_bytes(1024 * 1024):
                        written += len(chunk)
                        if written > config.MAX_UPLOAD_MB * 1024 * 1024:
                            raise ValueError("El objeto almacenado supera el límite configurado.")
                        capture.write(chunk)
        except (OSError, httpx.HTTPError) as exc:
            raise RuntimeError(
                "No se pudo recuperar la captura desde el almacenamiento compartido."
            ) from exc
        if written != job.size_bytes:
            raise RuntimeError("El tamaño de la captura almacenada no coincide.")

    def finish(
        self,
        job: ClaimedJob,
        result: Optional[AnalysisResult],
        error: Optional[str],
    ) -> None:
        with shared_db.connection() as connection:
            connection.execute(
                """
                UPDATE public.analysis_jobs
                SET status = %s, result = %s, error = %s,
                    finished_at = now(), lease_expires_at = NULL
                WHERE id = %s AND status = 'running'
                """,
                (
                    "error" if error is not None else "done",
                    Jsonb(result.model_dump(mode="json")) if result is not None else None,
                    error,
                    job.id,
                ),
            )
        self.cleanup_capture(job.storage_key)
        self.prune_completed(job.tenant_id)

    def cleanup_capture(self, storage_key: str) -> bool:
        if not self.delete_capture(storage_key):
            logger.error("No se pudo borrar una captura procesada de Supabase Storage.")
            return False
        try:
            self._mark_capture_deleted(storage_key)
        except HTTPException:
            logger.error("No se pudo registrar la eliminación de una captura procesada.")
            return False
        return True

    def cleanup_pending_captures(self) -> None:
        with shared_db.connection() as connection:
            rows = connection.execute(
                """
                SELECT storage_key FROM public.analysis_jobs
                WHERE status IN ('done', 'error') AND capture_deleted_at IS NULL
                LIMIT 100
                """
            ).fetchall()
        for row in rows:
            self.cleanup_capture(row["storage_key"])

    def prune_completed(self, tenant_id: Optional[str] = None) -> None:
        with shared_db.connection() as connection:
            rows = connection.execute(
                """
                SELECT id FROM (
                    SELECT id,
                           ROW_NUMBER() OVER (
                               PARTITION BY tenant_id
                               ORDER BY finished_at DESC
                           ) AS position,
                           finished_at
                    FROM public.analysis_jobs
                    WHERE status IN ('done', 'error')
                      AND capture_deleted_at IS NOT NULL
                      AND (%s::uuid IS NULL OR tenant_id = %s)
                ) completed
                WHERE position > %s
                   OR finished_at <= now() - (%s * INTERVAL '1 second')
                """,
                (tenant_id, tenant_id, config.MAX_RETAINED_JOBS, config.JOB_TTL_S),
            ).fetchall()
            if rows:
                connection.execute(
                    "DELETE FROM public.analysis_jobs WHERE id = ANY(%s)",
                    ([row["id"] for row in rows],),
                )

    def process_one(self, tshark_path: str) -> bool:
        from .analysis import analyze_pcap

        job = self.claim_next()
        if job is None:
            return False
        result: Optional[AnalysisResult] = None
        error: Optional[str] = None
        local_path: Optional[str] = None
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".pcap", delete=False, dir=os.environ.get("TMPDIR")
            ) as capture:
                local_path = capture.name
            self.download_capture(job, local_path)
            result = analyze_pcap(
                tshark_path=tshark_path,
                pcap_path=local_path,
                original_filename=job.filename,
                size_bytes=job.size_bytes,
            )
        except Exception as exc:
            error = str(exc)
        finally:
            if local_path and os.path.exists(local_path):
                try:
                    os.unlink(local_path)
                except OSError:
                    logger.error("No se pudo borrar una captura temporal del worker.")
        self.finish(job, result, error)
        return True


shared_job_store: Optional[SupabaseJobStore] = (
    SupabaseJobStore() if config.SUPABASE_ENABLED else None
)
