"""Shared Supabase Postgres access for tenant identity, quotas, and jobs."""
from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator, Optional

import psycopg
from fastapi import HTTPException
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool, PoolTimeout
from psycopg import Connection

from . import config

_pool: Optional[ConnectionPool] = None
_pool_lock = threading.Lock()


def _get_pool() -> ConnectionPool:
    global _pool
    if not config.SUPABASE_DB_URL:
        raise HTTPException(
            status_code=503,
            detail="Falta SUPABASE_DB_URL para usar el modo multi-tenant.",
        )
    with _pool_lock:
        if _pool is None:
            try:
                _pool = ConnectionPool(
                    conninfo=config.SUPABASE_DB_URL,
                    min_size=0,
                    max_size=5,
                    timeout=5,
                    kwargs={
                        "row_factory": dict_row,
                        "prepare_threshold": None,
                    },
                    open=False,
                )
                _pool.open(wait=True, timeout=5)
            except (psycopg.Error, PoolTimeout, TimeoutError) as exc:
                _pool = None
                raise HTTPException(
                    status_code=503,
                    detail="No se pudo conectar a la base de datos compartida.",
                ) from exc
        return _pool


@contextmanager
def connection() -> Iterator[Connection]:
    try:
        with _get_pool().connection() as database_connection:
            yield database_connection
    except (psycopg.Error, PoolTimeout, TimeoutError) as exc:
        raise HTTPException(
            status_code=503,
            detail="El servicio de datos compartido no está disponible.",
        ) from exc


def resolve_tenant_id(user_id: str) -> str:
    try:
        with connection() as database_connection:
            row = database_connection.execute(
                """
                SELECT tenant_id
                FROM public.tenant_memberships
                WHERE user_id = %s AND status = 'active'
                ORDER BY created_at
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()
    except HTTPException as exc:
        if exc.status_code == 503:
            raise HTTPException(
                status_code=503,
                detail="No se pudo consultar el espacio de trabajo.",
            ) from exc
        raise
    if row is None:
        raise HTTPException(
            status_code=403,
            detail="La cuenta no tiene un espacio de trabajo activo.",
        )
    return str(row["tenant_id"])


def consume_request_quota(tenant_id: str) -> None:
    try:
        with connection() as database_connection:
            database_connection.execute(
                "SELECT id FROM public.tenants WHERE id = %s FOR UPDATE",
                (tenant_id,),
            )
            row = database_connection.execute(
                """
                SELECT COUNT(*) AS request_count,
                       MIN(occurred_at) AS oldest_request,
                       GREATEST(
                           1,
                           CEIL(EXTRACT(EPOCH FROM
                               (MIN(occurred_at) + INTERVAL '1 minute' - clock_timestamp())
                           ))::integer
                       ) AS retry_after
                FROM public.api_request_events
                WHERE tenant_id = %s
                  AND occurred_at > clock_timestamp() - INTERVAL '1 minute'
                """,
                (tenant_id,),
            ).fetchone()
            if row["request_count"] < config.API_MAX_REQUESTS_PER_MINUTE:
                database_connection.execute(
                    """
                    INSERT INTO public.api_request_events (tenant_id)
                    VALUES (%s)
                    """,
                    (tenant_id,),
                )
    except HTTPException as exc:
        if exc.status_code == 503:
            raise HTTPException(
                status_code=503,
                detail="No se pudo verificar la cuota compartida.",
            ) from exc
        raise
    if row["request_count"] >= config.API_MAX_REQUESTS_PER_MINUTE:
        raise HTTPException(
            status_code=429,
            detail="El espacio de trabajo alcanzó su límite de solicitudes por minuto.",
            headers={"Retry-After": str(row["retry_after"])},
        )


def prune_request_events() -> None:
    with connection() as database_connection:
        database_connection.execute(
            "DELETE FROM public.api_request_events "
            "WHERE occurred_at < now() - INTERVAL '2 hours'"
        )
