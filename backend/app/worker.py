"""Shared Supabase queue worker entry point."""
from __future__ import annotations

import logging
import time

import psycopg
from fastapi import HTTPException

from . import config
from . import shared_db
from .supabase_jobs import shared_job_store
from .tshark import find_tshark, install_instructions

logger = logging.getLogger("pcapanalyzer.worker")


def main() -> None:
    if not config.SUPABASE_ENABLED or shared_job_store is None:
        raise SystemExit(
            "The queue worker requires AUTH_MODE=supabase and valid Supabase settings."
        )
    tshark_path = find_tshark()
    if tshark_path is None:
        raise SystemExit("tshark is required by the queue worker. %s" % install_instructions())
    logger.info("Supabase queue worker started; tshark=%s", tshark_path)
    next_maintenance = 0.0
    while True:
        try:
            if time.monotonic() >= next_maintenance:
                shared_job_store.cleanup_pending_captures()
                shared_job_store.prune_completed()
                shared_db.prune_request_events()
                next_maintenance = time.monotonic() + 60
            if not shared_job_store.process_one(tshark_path):
                time.sleep(1)
        except HTTPException as exc:
            logger.error("Shared queue unavailable (%s).", exc.status_code)
            time.sleep(5)
        except psycopg.Error:
            logger.exception("Database error in the shared queue worker.")
            time.sleep(5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
