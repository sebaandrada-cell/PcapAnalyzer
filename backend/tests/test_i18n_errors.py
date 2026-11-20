"""API error messages follow the language the web app asks for."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.i18n import lang_from_header, tr, use_lang


def test_lang_from_header():
    assert lang_from_header("en") == "en"
    assert lang_from_header("en-US,en;q=0.9") == "en"
    assert lang_from_header("es-ES,es;q=0.9,en;q=0.8") == "es"
    assert lang_from_header(None) == "es"
    assert lang_from_header("fr") == "es"


def test_tr_picks_the_current_language():
    assert tr("Hola", "Hello") == "Hola"
    with use_lang("en"):
        assert tr("Hola", "Hello") == "Hello"
    assert tr("Hola", "Hello") == "Hola"


def test_route_error_is_english_when_asked(client):
    response = client.get("/jobs/does-not-exist", headers={"Accept-Language": "en"})
    assert response.status_code == 404
    assert response.json()["detail"] == "Job not found or expired."


def test_route_error_stays_spanish_by_default(client):
    response = client.get("/jobs/does-not-exist")
    assert response.status_code == 404
    assert response.json()["detail"] == "Trabajo no encontrado o expirado."


def test_auth_error_from_middleware_is_english_when_asked(client):
    from app.main import app
    with TestClient(app) as anonymous:
        response = anonymous.post("/analyze", headers={"Accept-Language": "en"})
    assert response.status_code == 401
    assert response.json()["detail"] == "A Bearer token is required to use this API."


def test_session_error_is_english_when_asked(client):
    response = client.delete("/sessions/missing", headers={"Accept-Language": "en"})
    assert response.status_code == 404
    assert response.json()["detail"] == "Session not found or expired."
