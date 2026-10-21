"""Run the API and shared-queue worker in one Render web service."""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
from typing import Optional

from . import config
from .supabase_jobs import shared_job_store
from .tshark import find_tshark, install_instructions

logger = logging.getLogger("pcapanalyzer.render")


def _stop_process(process: Optional[subprocess.Popen[bytes]]) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def main() -> int:
    if not config.SUPABASE_ENABLED or shared_job_store is None:
        logger.error("Render deployment requires configured Supabase services.")
        return 1
    if find_tshark() is None:
        logger.error("tshark is required. %s", install_instructions())
        return 1

    stopping = threading.Event()
    worker: Optional[subprocess.Popen[bytes]] = None
    api: Optional[subprocess.Popen[bytes]] = None

    def request_shutdown(_signum: int, _frame: object) -> None:
        stopping.set()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)

    try:
        worker = subprocess.Popen([sys.executable, "-m", "app.worker"])
        api = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "0.0.0.0",
                "--port",
                os.environ.get("PORT", "8000"),
            ]
        )
        logger.info("Render service started API and Supabase queue worker.")

        while not stopping.wait(1):
            if api.poll() is not None:
                logger.error("API process exited with status %s.", api.returncode)
                return api.returncode or 0
            if worker.poll() is not None:
                logger.error("Queue worker exited with status %s.", worker.returncode)
                return worker.returncode or 1
        return 0
    finally:
        _stop_process(api)
        _stop_process(worker)


if __name__ == "__main__":
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    raise SystemExit(main())
