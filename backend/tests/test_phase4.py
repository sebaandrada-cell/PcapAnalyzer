"""Fase 4 tests: PDF report and async analysis queue."""
from __future__ import annotations

import io
import time

import pytest
from pypdf import PdfReader

from app.report import build_report
from app.tshark import find_tshark
from tests.test_llm import make_analysis

requires_tshark = pytest.mark.skipif(
    find_tshark() is None, reason="tshark no está instalado"
)


def _pdf_text(pdf_bytes: bytes) -> str:
    reader = PdfReader(io.BytesIO(pdf_bytes))
    return "\n".join(page.extract_text() for page in reader.pages)


class TestReport:
    def test_builds_valid_pdf_with_sections(self):
        pdf = build_report(make_analysis())
        assert pdf.startswith(b"%PDF")
        text = _pdf_text(pdf)
        for expected in ("Informe de análisis de captura", "sample.pcap",
                         "Problemas detectados", "Top talkers",
                         "Conversaciones TCP"):
            assert expected in text, "falta '%s' en el PDF" % expected
        assert "Diagnóstico asistido" not in text  # not provided

    def test_includes_diagnosis_when_given(self):
        pdf = build_report(
            make_analysis(),
            diagnosis="**Qué está pasando**: retransmisiones altas hacia 10.0.0.2.",
        )
        text = _pdf_text(pdf)
        assert "Diagnóstico asistido" in text
        assert "retransmisiones altas" in text

    def test_escapes_untrusted_strings(self):
        analysis = make_analysis()
        analysis.issues[0].title = "<script>alert('x')</script>"
        pdf = build_report(analysis)  # must not raise on markup-like input
        assert pdf.startswith(b"%PDF")

    def test_report_endpoint_downloads_pdf(self, client):
        response = client.post(
            "/report",
            json={"analysis": make_analysis().model_dump(),
                  "diagnosis": "**Qué está pasando**: prueba."},
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert "informe-sample.pcap.pdf" in response.headers["content-disposition"]
        assert response.content.startswith(b"%PDF")


class TestAsyncQueue:
    @requires_tshark
    def test_async_analysis_completes(self, client, sample_pcap):
        with open(sample_pcap, "rb") as fh:
            response = client.post(
                "/analyze/async",
                files={"file": ("sample.pcap", fh, "application/octet-stream")},
            )
        assert response.status_code == 202
        job_id = response.json()["job_id"]

        deadline = time.time() + 60
        status = None
        while time.time() < deadline:
            data = client.get("/jobs/%s" % job_id).json()
            status = data["status"]
            if status in ("done", "error"):
                break
            time.sleep(0.2)

        from tests.pcap_builder import build_sample_packets

        assert status == "done", data.get("error")
        assert data["result"]["summary"]["packets"] == len(build_sample_packets())
        assert data["filename"] == "sample.pcap"

    def test_unknown_job_returns_404(self, client):
        response = client.get("/jobs/nonexistent")
        assert response.status_code == 404

    def test_queue_rejects_when_pending_capacity_is_zero(self, tmp_path):
        from app.jobs import JobCapacityError, JobStore

        capture = tmp_path / "capture.pcap"
        capture.write_bytes(b"pcap")
        store = JobStore(
            workers=1, ttl_s=10, max_queued=0, max_per_token=1,
            max_pending_bytes=1024, max_retained_jobs=2,
        )
        try:
            with pytest.raises(JobCapacityError):
                store.submit(
                    tshark_path="tshark",
                    pcap_path=str(capture),
                    filename="capture.pcap",
                    size_bytes=4,
                    owner_id="principal",
                )
        finally:
            store._executor.shutdown(wait=True)
        assert capture.exists()

    def test_queue_rejects_when_pending_bytes_are_exhausted(self, tmp_path, monkeypatch):
        import threading
        from app import jobs as jobs_module
        from app.jobs import JobCapacityError, JobStore

        started = threading.Event()
        release = threading.Event()

        def hold_analysis(**kwargs):
            started.set()
            release.wait(timeout=5)

        monkeypatch.setattr(jobs_module, "analyze_pcap", hold_analysis)
        first_capture = tmp_path / "first.pcap"
        second_capture = tmp_path / "second.pcap"
        first_capture.write_bytes(b"first")
        second_capture.write_bytes(b"second")
        store = JobStore(
            workers=1, ttl_s=10, max_queued=2, max_per_token=2,
            max_pending_bytes=8, max_retained_jobs=2,
        )
        try:
            store.submit(
                tshark_path="tshark", pcap_path=str(first_capture),
                filename="first.pcap", size_bytes=5, owner_id="principal-a",
            )
            assert started.wait(timeout=5)
            with pytest.raises(JobCapacityError, match="capacidad"):
                store.submit(
                    tshark_path="tshark", pcap_path=str(second_capture),
                    filename="second.pcap", size_bytes=4,
                    owner_id="principal-b",
                )
        finally:
            release.set()
            store._executor.shutdown(wait=True)

    def test_completed_jobs_are_capped(self):
        import time
        from app.jobs import Job, JobStore

        store = JobStore(
            workers=1, ttl_s=3600, max_queued=1, max_per_token=1,
            max_pending_bytes=1024, max_retained_jobs=2,
        )
        try:
            with store._lock:
                for index in range(3):
                    job = Job(
                        id="job-%d" % index, filename="capture.pcap",
                        owner_id="principal", status="done",
                        finished_at=time.time() + index,
                    )
                    store._jobs[job.id] = job
                store._cleanup_locked()
                assert set(store._jobs) == {"job-1", "job-2"}
        finally:
            store._executor.shutdown(wait=True)

    @requires_tshark
    def test_async_rejects_non_pcap(self, client):
        response = client.post(
            "/analyze/async",
            files={"file": ("x.txt", b"not a pcap", "text/plain")},
        )
        assert response.status_code == 400

    @requires_tshark
    def test_error_jobs_expose_message(self, client, monkeypatch, sample_pcap):
        from app import jobs as jobs_module

        def boom(**kwargs):
            raise RuntimeError("fallo simulado")

        monkeypatch.setattr(jobs_module, "analyze_pcap", boom)
        with open(sample_pcap, "rb") as fh:
            response = client.post(
                "/analyze/async",
                files={"file": ("sample.pcap", fh, "application/octet-stream")},
            )
        job_id = response.json()["job_id"]
        deadline = time.time() + 10
        while time.time() < deadline:
            data = client.get("/jobs/%s" % job_id).json()
            if data["status"] in ("done", "error"):
                break
            time.sleep(0.1)
        assert data["status"] == "error"
        assert "fallo simulado" in data["error"]