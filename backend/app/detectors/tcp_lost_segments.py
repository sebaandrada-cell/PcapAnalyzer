"""Sequence-number jumps: a segment was never seen ("previous segment not captured")."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue
from ._util import conv_label


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for conv in state.tcp_convs.values():
        if conv.lost_segments < config.TCP_LOST_SEGMENT_MIN:
            continue
        # Real loss leaves a trail (duplicate ACKs, retransmissions). A bare jump
        # is also what a capture that started mid-stream or dropped packets shows.
        confirmed = bool(conv.dup_acks or conv.retransmissions)
        issues.append(
            Issue(
                id="tcp-lost-segments-%d" % conv.stream_id,
                type="tcp_lost_segments",
                severity="warning" if confirmed else "info",
                title="Segmentos TCP no vistos en la captura",
                detail=(
                    "En la conversación %s se detectaron %d salto(s) de secuencia sin "
                    "ver el segmento intermedio. %s"
                    % (conv_label(conv), conv.lost_segments,
                       "Coincide con ACK duplicados o retransmisiones: es pérdida real "
                       "de paquetes." if confirmed else
                       "Sin ACK duplicados ni retransmisiones, puede ser una captura "
                       "que empezó a mitad de conversación o que no vio todo el "
                       "tráfico (SPAN saturado, drops del capturador).")
                ),
                title_en="TCP segments missing from the capture",
                detail_en=(
                    "Conversation %s had %d sequence-number jump(s) with the "
                    "in-between segment never seen. %s"
                    % (conv_label(conv), conv.lost_segments,
                       "It coincides with duplicate ACKs or retransmissions: this is "
                       "real packet loss." if confirmed else
                       "With no duplicate ACKs or retransmissions it may be a capture "
                       "that started mid-conversation or did not see all the traffic "
                       "(overloaded SPAN port, capture drops).")
                ),
                conversation=conv_label(conv),
                evidence={
                    "stream_id": conv.stream_id,
                    "lost_segments": conv.lost_segments,
                    "confirmed_loss": confirmed,
                },
            )
        )
    return issues
