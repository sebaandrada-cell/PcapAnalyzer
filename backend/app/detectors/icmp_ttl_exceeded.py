"""ICMP / ICMPv6 time-exceeded: routing loops, or reassembly timeouts."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for group in state.icmp_errors.values():
        exceeded = (group.family == 4 and group.icmp_type == 11) or (
            group.family == 6 and group.icmp_type == 3)
        if not exceeded or group.count < config.ICMP_TTL_EXCEEDED_MIN:
            continue
        targets = ", ".join(group.targets) or "?"
        if group.code == 1:
            title, title_en = (
                "Tiempo de reensamblado de fragmentos excedido",
                "Fragment reassembly time exceeded",
            )
            hint, hint_en = (
                "El host no recibió todos los fragmentos a tiempo: pérdida de "
                "fragmentos en el camino o un MTU mal dimensionado.",
                "The host did not get all the fragments in time: fragments lost on "
                "the path or a badly sized MTU.",
            )
        else:
            title, title_en = ("TTL excedido repetidamente", "TTL exceeded repeatedly")
            hint, hint_en = (
                "Puede ser un bucle de enrutamiento (los paquetes circulan hasta "
                "agotar el TTL) o un traceroute en curso.",
                "It can be a routing loop (packets circulate until the TTL runs out) "
                "or a traceroute in progress.",
            )
        issues.append(
            Issue(
                id="icmp-ttl-exceeded-%d-%s-%d" % (group.family, group.reporter, group.code),
                type="icmp_ttl_exceeded",
                severity="warning",
                title=title,
                detail=(
                    "%s devolvió %d mensajes ICMP «tiempo excedido» (umbral: %d) "
                    "para el destino %s. %s"
                    % (group.reporter, group.count, config.ICMP_TTL_EXCEEDED_MIN, targets, hint)
                ),
                title_en=title_en,
                detail_en=(
                    "%s returned %d ICMP \"time exceeded\" messages (threshold: %d) "
                    "for destination %s. %s"
                    % (group.reporter, group.count, config.ICMP_TTL_EXCEEDED_MIN, targets, hint_en)
                ),
                evidence={
                    "reporter": group.reporter,
                    "family": group.family,
                    "icmp_type": group.icmp_type,
                    "code": group.code,
                    "count": group.count,
                    "targets": list(group.targets),
                },
            )
        )
    return issues
