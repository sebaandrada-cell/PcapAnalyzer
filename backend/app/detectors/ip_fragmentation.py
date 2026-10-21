"""IPv4 fragmentation: high fragmentation rate and datagrams that could not
be reassembled (missing last fragment)."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue


def detect(state) -> List[Issue]:
    issues: List[Issue] = []

    if state.packets and state.frag_packets:
        pct = 100.0 * state.frag_packets / state.packets
        if pct >= config.FRAG_HIGH_PCT:
            issues.append(
                Issue(
                    id="ip-fragmentation-high",
                    type="ip_fragmentation_high",
                    severity="warning",
                    title="Fragmentación IP elevada (%.1f%% de los paquetes)" % pct,
                    detail=(
                        "%d de %d paquetes son fragmentos IP (%.1f%%, umbral %.1f%%). "
                        "La fragmentación degrada el rendimiento y suele indicar un "
                        "MTU mal dimensionado (túneles, VPNs, jumbo frames)."
                        % (state.frag_packets, state.packets, pct,
                           config.FRAG_HIGH_PCT)
                    ),
                    title_en="High IP fragmentation (%.1f%% of packets)" % pct,
                    detail_en=(
                        "%d of %d packets are IP fragments (%.1f%%, threshold "
                        "%.1f%%). Fragmentation hurts performance and usually "
                        "points to a mis-sized MTU (tunnels, VPNs, jumbo frames)."
                        % (state.frag_packets, state.packets, pct,
                           config.FRAG_HIGH_PCT)
                    ),
                    evidence={
                        "fragment_packets": state.frag_packets,
                        "total_packets": state.packets,
                        "fragment_pct": round(pct, 2),
                        "datagrams": len(state.frag_groups),
                    },
                )
            )

    incomplete = {
        key: group for key, group in state.frag_groups.items()
        if group.has_first and not group.has_last
    }
    if incomplete:
        samples = [
            {"src": key[0], "dst": key[1], "ip_id": key[2],
             "fragments_seen": group.packets}
            for key, group in list(incomplete.items())[:5]
        ]
        issues.append(
            Issue(
                id="ip-fragments-incomplete",
                type="ip_fragments_incomplete",
                severity="warning",
                title="Fragmento final IP no observado (%d datagrama(s))" % len(incomplete),
                detail=(
                    "En %d datagrama(s) no se observó el fragmento final después "
                    "del fragmento inicial. Esto no demuestra pérdida: la captura "
                    "puede terminar antes o no incluir todos los puntos de observación."
                    % len(incomplete)
                ),
                title_en="Final IP fragment not observed (%d datagram(s))" % len(incomplete),
                detail_en=(
                    "The final fragment was not observed for %d datagram(s) after "
                    "their first fragment. This does not prove packet loss: the "
                    "capture may end early or omit observation points."
                    % len(incomplete)
                ),
                evidence={"incomplete_datagrams": len(incomplete),
                          "samples": samples,
                          "capture_boundary_possible": True},
            )
        )

    return issues
