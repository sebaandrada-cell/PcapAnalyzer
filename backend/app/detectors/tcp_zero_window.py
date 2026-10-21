"""TCP zero-window advertisements: the receiver cannot drain its buffer."""
from __future__ import annotations

from .. import config
from typing import List

from ..models import Issue
from ._util import conv_label


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for conv in state.tcp_convs.values():
        if conv.zero_window_events < config.TCP_ZERO_WINDOW_MIN_EVENTS:
            continue
        issues.append(
            Issue(
                id="tcp-zero-window-%d" % conv.stream_id,
                type="tcp_zero_window",
                severity="warning",
                title="Anuncios TCP window 0 repetidos",
                detail=(
                    "La conversación %s anunció ventana TCP 0 en %d ocasión(es) "
                    "(umbral: %d). Es evidencia de presión de recepción, pero por "
                    "sí sola no mide cuánto duró ni demuestra saturación sostenida."
                    % (conv_label(conv), conv.zero_window_events,
                       config.TCP_ZERO_WINDOW_MIN_EVENTS)
                ),
                title_en="Repeated TCP zero-window advertisements",
                detail_en=(
                    "Conversation %s advertised TCP window 0 %d time(s) "
                    "(threshold: %d). This indicates receive-side pressure, but "
                    "alone does not measure duration or prove sustained saturation."
                    % (conv_label(conv), conv.zero_window_events,
                       config.TCP_ZERO_WINDOW_MIN_EVENTS)
                ),
                conversation=conv_label(conv),
                evidence={
                    "stream_id": conv.stream_id,
                    "zero_window_events": conv.zero_window_events,
                },
            )
        )
    return issues
