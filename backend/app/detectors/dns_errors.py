"""DNS servers answering with errors: SERVFAIL (rcode 2) and NXDOMAIN
storms (rcode 3)."""
from __future__ import annotations

from typing import Dict, List, Tuple

from .. import config
from ..models import Issue


def detect(state) -> List[Issue]:
    issues: List[Issue] = []

    servfail: Dict[str, List[str]] = {}
    nxdomain: Dict[Tuple[str, str], List[str]] = {}
    for error in state.dns_errors:
        if error.rcode == 2:
            servfail.setdefault(error.server, []).append(error.name)
        elif error.rcode == 3:
            nxdomain.setdefault((error.client, error.server), []).append(error.name)

    for idx, (server, names) in enumerate(servfail.items()):
        issues.append(
            Issue(
                id="dns-servfail-%d" % idx,
                type="dns_servfail",
                severity="warning",
                title="DNS SERVFAIL del servidor %s (%d)" % (server, len(names)),
                detail=(
                    "El servidor DNS %s respondió SERVFAIL a %d consulta(s) "
                    "(p. ej. %s). El servidor tiene problemas para resolver: "
                    "upstream caído, zona rota o DNSSEC inválido."
                    % (server, len(names), ", ".join(sorted(set(names))[:3]))
                ),
                title_en="DNS SERVFAIL from server %s (%d)" % (server, len(names)),
                detail_en=(
                    "DNS server %s answered SERVFAIL to %d query(ies) (e.g. %s). "
                    "The server has trouble resolving: upstream down, broken zone "
                    "or invalid DNSSEC."
                    % (server, len(names), ", ".join(sorted(set(names))[:3]))
                ),
                conversation=server,
                evidence={"server": server, "count": len(names),
                          "query_names": sorted(set(names))[:10]},
            )
        )

    for idx, ((client, server), names) in enumerate(nxdomain.items()):
        if len(names) < config.DNS_NXDOMAIN_MIN:
            continue
        issues.append(
            Issue(
                id="dns-nxdomain-%d" % idx,
                type="dns_nxdomain",
                severity="warning",
                title="Ráfaga de NXDOMAIN desde %s (%d)" % (client, len(names)),
                detail=(
                    "El host %s recibió %d respuestas NXDOMAIN de %s (p. ej. %s). "
                    "Puede ser un sufijo de búsqueda mal configurado, un servicio "
                    "apuntando a nombres inexistentes o actividad sospechosa (DGA)."
                    % (client, len(names), server,
                       ", ".join(sorted(set(names))[:3]))
                ),
                title_en="NXDOMAIN burst from %s (%d)" % (client, len(names)),
                detail_en=(
                    "Host %s received %d NXDOMAIN responses from %s (e.g. %s). "
                    "May be a misconfigured search suffix, a service pointing at "
                    "non-existent names, or suspicious activity (DGA)."
                    % (client, len(names), server,
                       ", ".join(sorted(set(names))[:3]))
                ),
                conversation="%s <-> %s" % (client, server),
                evidence={"client": client, "server": server,
                          "count": len(names),
                          "query_names": sorted(set(names))[:10]},
            )
        )

    return issues
