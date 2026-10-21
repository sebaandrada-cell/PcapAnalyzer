"""Slow TCP handshakes (high SYN -> SYN-ACK RTT)."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue
from ._util import conv_label


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for conv in state.tcp_convs.values():
        if conv.syn_ts is None or conv.synack_ts is None:
            continue
        rtt = conv.synack_ts - conv.syn_ts
        if rtt <= config.TCP_HANDSHAKE_SLOW_S:
            continue
        issues.append(
            Issue(
                id="tcp-slow-handshake-%d" % conv.stream_id,
                type="tcp_slow_handshake",
                severity="warning",
                title="Handshake TCP lento (%.0f ms)" % (rtt * 1000),
                detail=(
                    "La conexión %s tardó %.0f ms entre SYN y SYN-ACK (umbral: "
                    "%.0f ms). Indica alta latencia de red o un servidor "
                    "sobrecargado." % (conv_label(conv), rtt * 1000,
                                       config.TCP_HANDSHAKE_SLOW_S * 1000)
                ),
                title_en="Slow TCP handshake (%.0f ms)" % (rtt * 1000),
                detail_en=(
                    "Connection %s took %.0f ms between SYN and SYN-ACK "
                    "(threshold: %.0f ms). Indicates high network latency or an "
                    "overloaded server." % (conv_label(conv), rtt * 1000,
                                            config.TCP_HANDSHAKE_SLOW_S * 1000)
                ),
                conversation=conv_label(conv),
                evidence={"stream_id": conv.stream_id,
                          "handshake_rtt_ms": round(rtt * 1000, 1)},
            )
        )
    return issues
