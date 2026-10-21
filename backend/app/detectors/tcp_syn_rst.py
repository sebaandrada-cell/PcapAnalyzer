"""SYN answered by an immediate RST with no SYN-ACK: firewall / closed port."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue
from ._util import conv_label


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for conv in state.tcp_convs.values():
        if conv.syn_ts is None or conv.synack_seen or conv.rst_ts is None:
            continue
        delay = conv.rst_ts - conv.syn_ts
        if delay < 0 or delay > config.SYN_RST_MAX_DELAY_S:
            continue
        issues.append(
            Issue(
                id="tcp-syn-rst-%d" % conv.stream_id,
                type="tcp_syn_rst",
                severity="critical",
                title="SYN respondido con RST inmediato",
                detail=(
                    "La conexión %s recibió un RST %.1f ms después del SYN sin ver "
                    "SYN-ACK. Posible firewall rechazando la conexión o puerto cerrado."
                    % (conv_label(conv), delay * 1000)
                ),
                title_en="SYN answered by an immediate RST",
                detail_en=(
                    "Connection %s received a RST %.1f ms after the SYN with no "
                    "SYN-ACK seen. Possibly a firewall rejecting the connection or "
                    "a closed port." % (conv_label(conv), delay * 1000)
                ),
                conversation=conv_label(conv),
                evidence={
                    "stream_id": conv.stream_id,
                    "syn_to_rst_ms": round(delay * 1000, 3),
                    "dst_port": conv.dst_port,
                },
            )
        )
    return issues
