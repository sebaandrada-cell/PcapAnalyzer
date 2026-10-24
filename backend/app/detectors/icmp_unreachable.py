"""ICMP / ICMPv6 destination-unreachable messages: a router or host says "no"."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue

# (Spanish, English) names for the codes seen in practice.
_V4 = {
    0: ("red inalcanzable", "network unreachable"),
    1: ("host inalcanzable", "host unreachable"),
    2: ("protocolo inalcanzable", "protocol unreachable"),
    3: ("puerto inalcanzable", "port unreachable"),
    5: ("fallo en la ruta de origen", "source route failed"),
    6: ("red de destino desconocida", "destination network unknown"),
    7: ("host de destino desconocido", "destination host unknown"),
    9: ("red prohibida administrativamente", "network administratively prohibited"),
    10: ("host prohibido administrativamente", "host administratively prohibited"),
    13: ("comunicación prohibida administrativamente", "communication administratively prohibited"),
}
_V6 = {
    0: ("sin ruta al destino", "no route to destination"),
    1: ("comunicación prohibida administrativamente", "communication administratively prohibited"),
    2: ("más allá del ámbito de la dirección de origen", "beyond scope of source address"),
    3: ("dirección inalcanzable", "address unreachable"),
    4: ("puerto inalcanzable", "port unreachable"),
    5: ("origen rechazado por política", "source address failed policy"),
    6: ("ruta rechazada al destino", "reject route to destination"),
}
_PORT = {(4, 3), (6, 4)}
_ADMIN = {(4, 9), (4, 10), (4, 13), (6, 1), (6, 5), (6, 6)}

_HINT = {
    "port": (
        "El host contestó, pero no hay ningún servicio escuchando en ese puerto "
        "(o un firewall lo rechaza con ICMP en vez de descartarlo).",
        "The host answered, but nothing is listening on that port "
        "(or a firewall rejects it with ICMP instead of dropping it).",
    ),
    "admin": (
        "Un firewall o una ACL está rechazando el tráfico de forma explícita: "
        "responde con ICMP en vez de descartarlo en silencio.",
        "A firewall or ACL is explicitly rejecting the traffic: it replies with "
        "ICMP instead of silently dropping it.",
    ),
    "route": (
        "Un router no encuentra ruta o no resuelve el destino: host caído, ruta "
        "ausente, VLAN equivocada o ARP sin respuesta.",
        "A router cannot find a route or resolve the destination: host down, "
        "missing route, wrong VLAN or unanswered ARP.",
    ),
}


def _kind(family: int, code: int) -> str:
    if (family, code) in _PORT:
        return "port"
    if (family, code) in _ADMIN:
        return "admin"
    return "route"


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for group in state.icmp_errors.values():
        unreachable = (group.family == 4 and group.icmp_type == 3) or (
            group.family == 6 and group.icmp_type == 1)
        if not unreachable or group.count < config.ICMP_UNREACHABLE_MIN:
            continue
        names = (_V4 if group.family == 4 else _V6).get(
            group.code, ("código %d" % group.code, "code %d" % group.code))
        hint_es, hint_en = _HINT[_kind(group.family, group.code)]
        targets = ", ".join(group.targets) or "?"
        victims = ", ".join(group.victims) or "?"
        issues.append(
            Issue(
                id="icmp-unreachable-%d-%s-%d" % (group.family, group.reporter, group.code),
                type="icmp_unreachable",
                severity="warning",
                title="Destino inalcanzable: %s" % names[0],
                detail=(
                    "%s informó %d vez/veces «%s» a %s por el destino %s. %s"
                    % (group.reporter, group.count, names[0], victims, targets, hint_es)
                ),
                title_en="Destination unreachable: %s" % names[1],
                detail_en=(
                    "%s reported \"%s\" %d time(s) to %s for destination %s. %s"
                    % (group.reporter, names[1], group.count, victims, targets, hint_en)
                ),
                evidence={
                    "reporter": group.reporter,
                    "family": group.family,
                    "icmp_type": group.icmp_type,
                    "code": group.code,
                    "count": group.count,
                    "targets": list(group.targets),
                    "victims": list(group.victims),
                },
            )
        )
    return issues
