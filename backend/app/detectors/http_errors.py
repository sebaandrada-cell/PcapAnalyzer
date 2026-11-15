"""HTTP servers answering with errors or slowly (clear-text HTTP only)."""
from __future__ import annotations

from typing import Dict, List

from .. import config
from ..models import Issue

# 401/407 are the first leg of an authentication exchange, not a failure.
_AUTH_CHALLENGES = (401, 407)


def detect(state) -> List[Issue]:
    servers: Dict[str, dict] = {}
    slow_ms = config.HTTP_SLOW_THRESHOLD_S * 1000
    for request in state.http_requests:
        if request.status is None:
            continue
        entry = servers.setdefault(request.server, {
            "responses": 0, "5xx": [], "4xx": [], "slow": 0, "max_ms": 0.0})
        entry["responses"] += 1
        if request.status >= 500:
            entry["5xx"].append(request.status)
        elif request.status >= 400 and request.status not in _AUTH_CHALLENGES:
            entry["4xx"].append(request.status)
        if request.response_ms is not None and request.response_ms >= slow_ms:
            entry["slow"] += 1
            entry["max_ms"] = max(entry["max_ms"], request.response_ms)

    issues: List[Issue] = []
    for idx, (server, entry) in enumerate(servers.items()):
        responses = entry["responses"]

        def mostly(count: int) -> bool:
            return (responses >= config.HTTP_ERROR_CRIT_MIN_RESPONSES
                    and 100.0 * count / responses >= config.HTTP_ERROR_CRIT_PCT)

        errors = entry["5xx"]
        if len(errors) >= config.HTTP_5XX_MIN:
            pct = round(100.0 * len(errors) / responses, 1)
            codes = sorted(set(errors))[:5]
            issues.append(Issue(
                id="http-5xx-%d" % idx,
                type="http_server_errors",
                severity="critical" if mostly(len(errors)) else "warning",
                title="Errores HTTP 5xx del servidor %s (%d)" % (server, len(errors)),
                detail=(
                    "El servidor %s respondió con error de servidor a %d de %d peticiones "
                    "HTTP (%s%%; códigos %s). El fallo está en la aplicación o en lo que "
                    "tiene detrás (backend, base de datos, proxy inverso), no en la red."
                    % (server, len(errors), responses, pct, ", ".join(map(str, codes)))
                ),
                title_en="HTTP 5xx errors from server %s (%d)" % (server, len(errors)),
                detail_en=(
                    "Server %s answered %d of %d HTTP requests with a server error "
                    "(%s%%; codes %s). The fault is in the application or what sits "
                    "behind it (backend, database, reverse proxy), not in the network."
                    % (server, len(errors), responses, pct, ", ".join(map(str, codes)))
                ),
                conversation=server,
                evidence={"server": server, "count": len(errors), "responses": responses,
                          "codes": codes, "error_pct": pct},
            ))

        client_errors = entry["4xx"]
        if len(client_errors) >= config.HTTP_4XX_MIN:
            pct = round(100.0 * len(client_errors) / responses, 1)
            codes = sorted(set(client_errors))[:5]
            issues.append(Issue(
                id="http-4xx-%d" % idx,
                type="http_client_errors",
                severity="warning" if mostly(len(client_errors)) else "info",
                title="Errores HTTP 4xx hacia %s (%d)" % (server, len(client_errors)),
                detail=(
                    "%d de %d respuestas HTTP de %s fueron errores de cliente (%s%%; "
                    "códigos %s). Suele ser un cliente pidiendo rutas que no existen, "
                    "credenciales o permisos incorrectos, o un límite de peticiones."
                    % (len(client_errors), responses, server, pct, ", ".join(map(str, codes)))
                ),
                title_en="HTTP 4xx errors towards %s (%d)" % (server, len(client_errors)),
                detail_en=(
                    "%d of %d HTTP responses from %s were client errors (%s%%; codes %s). "
                    "Usually a client requesting paths that do not exist, wrong "
                    "credentials or permissions, or a rate limit."
                    % (len(client_errors), responses, server, pct, ", ".join(map(str, codes)))
                ),
                conversation=server,
                evidence={"server": server, "count": len(client_errors),
                          "responses": responses, "codes": codes, "error_pct": pct},
            ))

        if entry["slow"]:
            issues.append(Issue(
                id="http-slow-%d" % idx,
                type="http_slow",
                severity="warning",
                title="Respuestas HTTP lentas de %s (máx. %.0f ms)" % (server, entry["max_ms"]),
                detail=(
                    "%d respuesta(s) HTTP de %s tardaron más de %.0f ms en empezar a "
                    "llegar desde la petición (máximo %.0f ms). Si el saludo TCP con ese "
                    "servidor es rápido, el tiempo se va en la aplicación, no en la red."
                    % (entry["slow"], server, slow_ms, entry["max_ms"])
                ),
                title_en="Slow HTTP responses from %s (max %.0f ms)" % (server, entry["max_ms"]),
                detail_en=(
                    "%d HTTP response(s) from %s took longer than %.0f ms to start "
                    "arriving after the request (maximum %.0f ms). If the TCP handshake "
                    "with that server is fast, the time is spent in the application, not "
                    "in the network."
                    % (entry["slow"], server, slow_ms, entry["max_ms"])
                ),
                conversation=server,
                evidence={"server": server, "count": entry["slow"],
                          "max_ms": round(entry["max_ms"], 1), "threshold_ms": slow_ms},
            ))
    return issues
