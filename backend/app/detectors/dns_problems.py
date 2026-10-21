"""DNS queries that never got a response or were answered too slowly."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    unanswered = (query for pending in state.dns_pending.values() for query in pending)
    for idx, query in enumerate(unanswered):
        issues.append(
            Issue(
                id="dns-unanswered-%d" % idx,
                type="dns_unanswered",
                severity="warning",
                title="Consulta DNS sin respuesta",
                detail=(
                    "No se observó respuesta en esta captura para la consulta DNS "
                    "de %s para '%s' al servidor %s. La respuesta pudo quedar fuera "
                    "del intervalo capturado o de la interfaz observada."
                    % (query.client, query.name, query.server)
                ),
                title_en="DNS query with no response",
                detail_en=(
                    "No response was observed in this capture for the DNS query "
                    "from %s for '%s' to server %s. The response may be outside "
                    "the capture interval or observed interface."
                    % (query.client, query.name, query.server)
                ),
                conversation="%s <-> %s" % (query.client, query.server),
                evidence={
                    "query_name": query.name,
                    "server": query.server,
                    "capture_boundary_possible": True,
                },
            )
        )
    for idx, exchange in enumerate(state.dns_answered):
        if exchange.latency_s <= config.DNS_SLOW_THRESHOLD_S:
            continue
        issues.append(
            Issue(
                id="dns-slow-%d" % idx,
                type="dns_slow",
                severity="warning",
                title="Respuesta DNS lenta (%.0f ms)" % (exchange.latency_s * 1000),
                detail=(
                    "La consulta DNS para '%s' tardó %.0f ms en ser respondida por %s "
                    "(umbral: %.0f ms)."
                    % (
                        exchange.name,
                        exchange.latency_s * 1000,
                        exchange.server,
                        config.DNS_SLOW_THRESHOLD_S * 1000,
                    )
                ),
                title_en="Slow DNS response (%.0f ms)" % (exchange.latency_s * 1000),
                detail_en=(
                    "The DNS query for '%s' took %.0f ms to be answered by %s "
                    "(threshold: %.0f ms)."
                    % (
                        exchange.name,
                        exchange.latency_s * 1000,
                        exchange.server,
                        config.DNS_SLOW_THRESHOLD_S * 1000,
                    )
                ),
                conversation="%s <-> %s" % (exchange.client, exchange.server),
                evidence={
                    "query_name": exchange.name,
                    "latency_ms": round(exchange.latency_s * 1000, 1),
                    "server": exchange.server,
                },
            )
        )
    return issues
