"""Repeated duplicate ACKs: the receiver keeps asking for a segment that never arrives."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue
from ._util import conv_label


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for conv in state.tcp_convs.values():
        if conv.dup_acks < config.TCP_DUP_ACK_MIN:
            continue
        issues.append(
            Issue(
                id="tcp-dup-acks-%d" % conv.stream_id,
                type="tcp_dup_acks",
                severity="warning",
                title="ACK duplicados repetidos",
                detail=(
                    "La conversación %s recibió %d ACK duplicados (umbral: %d). El "
                    "receptor sigue pidiendo un segmento que no le llega: es el síntoma "
                    "típico de un paquete perdido en el camino (o muy reordenado) y "
                    "suele ir seguido de una retransmisión rápida."
                    % (conv_label(conv), conv.dup_acks, config.TCP_DUP_ACK_MIN)
                ),
                title_en="Repeated duplicate ACKs",
                detail_en=(
                    "Conversation %s saw %d duplicate ACKs (threshold: %d). The "
                    "receiver keeps asking for a segment that never arrives: the "
                    "classic symptom of a packet lost on the path (or heavily "
                    "reordered), usually followed by a fast retransmission."
                    % (conv_label(conv), conv.dup_acks, config.TCP_DUP_ACK_MIN)
                ),
                conversation=conv_label(conv),
                evidence={"stream_id": conv.stream_id, "dup_acks": conv.dup_acks},
            )
        )
    return issues
