"""Sender filled the receiver's window: throughput is limited by the receive side."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue
from ._util import conv_label


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for conv in state.tcp_convs.values():
        if conv.window_full < config.TCP_WINDOW_FULL_MIN:
            continue
        issues.append(
            Issue(
                id="tcp-window-full-%d" % conv.stream_id,
                type="tcp_window_full",
                severity="warning",
                title="Ventana de recepción TCP llena",
                detail=(
                    "El emisor de la conversación %s llenó la ventana de recepción en "
                    "%d ocasión(es) (umbral: %d) y tuvo que esperar un ACK. El "
                    "rendimiento queda limitado por el receptor: ventana pequeña, "
                    "falta de window scaling o una aplicación que lee despacio."
                    % (conv_label(conv), conv.window_full, config.TCP_WINDOW_FULL_MIN)
                ),
                title_en="TCP receive window full",
                detail_en=(
                    "The sender in conversation %s filled the receive window %d "
                    "time(s) (threshold: %d) and had to wait for an ACK. Throughput "
                    "is capped by the receiver: small window, missing window scaling "
                    "or an application that reads slowly."
                    % (conv_label(conv), conv.window_full, config.TCP_WINDOW_FULL_MIN)
                ),
                conversation=conv_label(conv),
                evidence={"stream_id": conv.stream_id, "window_full": conv.window_full},
            )
        )
    return issues
