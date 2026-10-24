#!/usr/bin/env python3
"""Regenerate frontend/public/demo/demo.json, the data of the public demo.

It runs the REAL analysis engine on the sample capture (in-process, no server)
and stores what the API returns, so the demo shows exactly what the product
produces: the AnalysisResult from /analyze plus the demo-mode diagnosis from
/diagnose in Spanish and English. Nothing here is hand-written.

Run it from the repository root with the backend virtualenv (needs tshark):

    backend/.venv/bin/python scripts/make-demo-data.py

Re-run it whenever a detector, the sample capture or the demo text changes.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "frontend" / "public" / "sample.pcap"
OUT = ROOT / "frontend" / "public" / "demo" / "demo.json"
sys.path.insert(0, str(ROOT / "backend"))

from fastapi.testclient import TestClient  # noqa: E402

from app import config  # noqa: E402

# Deterministic, offline and free: never call the real model from this script,
# whatever backend/.env contains.
config.LLM_DEMO = True
config.AUTH_MODE = "token"
config.SUPABASE_ENABLED = False
config.API_TOKENS = ["make-demo-data"]
config.API_MAX_REQUESTS_PER_MINUTE = 10_000

from app.main import app  # noqa: E402  (after config is pinned)

# The demo diagnosis ends with a footer written for someone running the product
# ("set ANTHROPIC_API_KEY"). In a public demo it must say plainly that this text
# is simulated and what the full version does instead.
FOOTERS = {
    "es": "_(Demo: texto generado a partir del propio análisis, sin IA. La versión "
          "completa usa tu propia clave de Anthropic para un diagnóstico con IA real.)_",
    "en": "_(Demo: text generated from the analysis itself, without AI. The full "
          "version uses your own Anthropic key for a real AI diagnosis.)_",
}
FOOTER_RE = re.compile(r"\n*_\((?:modo demo|demo mode)[^\n]*\)_\s*$", re.IGNORECASE)


def main() -> int:
    if not SAMPLE.is_file():
        print("No existe %s" % SAMPLE, file=sys.stderr)
        return 1
    headers = {"Authorization": "Bearer make-demo-data"}
    with TestClient(app, headers=headers) as client:
        with SAMPLE.open("rb") as fh:
            response = client.post(
                "/analyze", files={"file": ("sample.pcap", fh, "application/octet-stream")}
            )
        if response.status_code != 200:
            print("/analyze → %s: %s" % (response.status_code, response.text[:300]), file=sys.stderr)
            return 1
        analysis = response.json()

        diagnosis = {}
        for lang in ("es", "en"):
            reply = client.post("/diagnose", json={"analysis": analysis, "lang": lang})
            if reply.status_code != 200:
                print("/diagnose (%s) → %s: %s" % (lang, reply.status_code, reply.text[:300]), file=sys.stderr)
                return 1
            text = reply.json()["diagnosis"]
            if not FOOTER_RE.search(text):
                print("Aviso: no se encontró el pie de modo demo en el texto «%s»; se añade el de la demo pública." % lang)
            diagnosis[lang] = FOOTER_RE.sub("", text).rstrip() + "\n\n" + FOOTERS[lang]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps({"analysis": analysis, "diagnosis": diagnosis}, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    summary = analysis["summary"]
    print(
        "OK → %s  (%d bytes · %d paquetes · %d problemas)"
        % (OUT.relative_to(ROOT), OUT.stat().st_size, summary["packets"], len(analysis["issues"]))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
