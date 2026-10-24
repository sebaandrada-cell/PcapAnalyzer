"""Connections cut with RST after they were established (not the SYN->RST pattern)."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue
from ._util import conv_label

_WARN_CONVS = 10  # this many reset conversations is more than a stray close


def detect(state) -> List[Issue]:
    reset = [conv for conv in state.tcp_convs.values() if conv.resets_midstream]
    if len(reset) < config.TCP_RESET_MIN_CONVS:
        return []
    reset.sort(key=lambda conv: conv.stream_id)
    examples = [conv_label(conv) for conv in reset[:5]]
    return [
        Issue(
            id="tcp-resets-midstream",
            type="tcp_resets",
            severity="warning" if len(reset) >= _WARN_CONVS else "info",
            title="Conexiones cerradas con RST tras establecerse",
            detail=(
                "%d conversaciones TCP terminaron con RST después de completar el "
                "saludo (umbral: %d). Un cierre abrupto puntual es normal; muchos "
                "suelen indicar un servidor, balanceador o firewall que corta "
                "sesiones (timeouts, límite de conexiones, inspección). Ejemplos: %s."
                % (len(reset), config.TCP_RESET_MIN_CONVS, "; ".join(examples))
            ),
            title_en="Connections closed with RST after being established",
            detail_en=(
                "%d TCP conversations ended with a RST after completing the "
                "handshake (threshold: %d). An occasional abrupt close is normal; "
                "many usually mean a server, load balancer or firewall cutting "
                "sessions (timeouts, connection limits, inspection). Examples: %s."
                % (len(reset), config.TCP_RESET_MIN_CONVS, "; ".join(examples))
            ),
            evidence={
                "conversations": len(reset),
                "stream_ids": [conv.stream_id for conv in reset[:10]],
            },
        )
    ]
