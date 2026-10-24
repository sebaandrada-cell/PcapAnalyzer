"""TCP segments arriving out of order: multipath/ECMP, LAG or a reordering link."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue
from ._util import conv_label

_WARN_PCT = 5.0  # share of the conversation's packets that makes it a warning


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for conv in state.tcp_convs.values():
        if conv.out_of_order < config.TCP_OUT_OF_ORDER_MIN:
            continue
        pct = 100.0 * conv.out_of_order / conv.packets if conv.packets else 0.0
        issues.append(
            Issue(
                id="tcp-out-of-order-%d" % conv.stream_id,
                type="tcp_out_of_order",
                severity="warning" if pct >= _WARN_PCT else "info",
                title="Segmentos TCP fuera de orden",
                detail=(
                    "La conversación %s tuvo %d segmentos fuera de orden (%.1f%% de "
                    "sus paquetes; umbral: %d). Suele indicar varios caminos "
                    "(balanceo ECMP o LAG) o un enlace que reordena; si coincide con "
                    "retransmisiones, el rendimiento se degrada."
                    % (conv_label(conv), conv.out_of_order, pct, config.TCP_OUT_OF_ORDER_MIN)
                ),
                title_en="Out-of-order TCP segments",
                detail_en=(
                    "Conversation %s had %d out-of-order segments (%.1f%% of its "
                    "packets; threshold: %d). It usually points to multiple paths "
                    "(ECMP or LAG balancing) or a link that reorders; combined with "
                    "retransmissions it degrades throughput."
                    % (conv_label(conv), conv.out_of_order, pct, config.TCP_OUT_OF_ORDER_MIN)
                ),
                conversation=conv_label(conv),
                evidence={
                    "stream_id": conv.stream_id,
                    "out_of_order": conv.out_of_order,
                    "out_of_order_pct": round(pct, 2),
                },
            )
        )
    return issues
