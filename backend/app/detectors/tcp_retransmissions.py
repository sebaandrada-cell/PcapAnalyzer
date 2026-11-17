"""TCP retransmission rate per conversation (packet loss / congestion)."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue
from ._util import conv_label


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for conv in state.tcp_convs.values():
        if conv.packets < config.RETRANS_MIN_PACKETS \
                or conv.retransmissions < config.RETRANS_MIN_COUNT:
            continue
        pct = 100.0 * conv.retransmissions / conv.packets
        if pct < config.RETRANS_WARN_PCT:
            continue
        severity = "critical" if pct >= config.RETRANS_CRIT_PCT else "warning"
        issues.append(
            Issue(
                id="tcp-retrans-%d" % conv.stream_id,
                type="tcp_retransmissions",
                severity=severity,
                title="Retransmisiones TCP elevadas (%.1f%%)" % pct,
                detail=(
                    "La conversación %s tiene %d retransmisiones sobre %d paquetes "
                    "(%.1f%%). Puede indicar pérdida de paquetes o congestión."
                    % (conv_label(conv), conv.retransmissions, conv.packets, pct)
                ),
                title_en="High TCP retransmissions (%.1f%%)" % pct,
                detail_en=(
                    "Conversation %s has %d retransmissions out of %d packets "
                    "(%.1f%%). May indicate packet loss or congestion."
                    % (conv_label(conv), conv.retransmissions, conv.packets, pct)
                ),
                conversation=conv_label(conv),
                evidence={
                    "stream_id": conv.stream_id,
                    "retransmissions": conv.retransmissions,
                    "packets": conv.packets,
                    "retransmission_pct": round(pct, 2),
                },
            )
        )
    return issues
