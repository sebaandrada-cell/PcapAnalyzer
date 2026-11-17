"""SYN answered by an immediate RST with no SYN-ACK: firewall / closed port.

Refusals to the same destination and port are one finding (a client retrying
a closed port produces one per attempt)."""
from __future__ import annotations

from typing import Dict, List, Tuple

from .. import config
from ..models import Issue
from ._util import conv_label


def detect(state) -> List[Issue]:
    groups: Dict[Tuple[str, int], list] = {}
    for conv in sorted(state.tcp_convs.values(), key=lambda c: c.stream_id):
        if conv.syn_ts is None or conv.synack_seen or conv.rst_ts is None:
            continue
        delay = conv.rst_ts - conv.syn_ts
        if delay < 0 or delay > config.SYN_RST_MAX_DELAY_S:
            continue
        groups.setdefault((conv.dst, conv.dst_port), []).append((conv, delay))

    issues: List[Issue] = []
    for (dst, port), refused in groups.items():
        conv, delay = refused[0]
        if len(refused) == 1:
            issues.append(Issue(
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
                    "dst_port": port,
                },
            ))
            continue
        clients = sorted({c.src for c, _ in refused})
        slowest = max(d for _, d in refused) * 1000
        issues.append(Issue(
            id="tcp-syn-rst-%d" % conv.stream_id,
            type="tcp_syn_rst",
            severity="critical",
            title="Conexiones a %s:%d rechazadas con RST (%d)" % (dst, port, len(refused)),
            detail=(
                "%d intentos de conexión a %s:%d desde %s recibieron un RST sin "
                "SYN-ACK (en %.1f ms como mucho). El puerto está cerrado en ese equipo "
                "o un firewall lo rechaza; el cliente sigue reintentando."
                % (len(refused), dst, port, ", ".join(clients[:3]), slowest)
            ),
            title_en="Connections to %s:%d refused with RST (%d)" % (dst, port, len(refused)),
            detail_en=(
                "%d connection attempts to %s:%d from %s got a RST with no SYN-ACK "
                "(within %.1f ms at most). The port is closed on that host or a "
                "firewall rejects it; the client keeps retrying."
                % (len(refused), dst, port, ", ".join(clients[:3]), slowest)
            ),
            conversation="%s:%d" % (dst, port),
            evidence={
                "attempts": len(refused),
                "dst": dst,
                "dst_port": port,
                "clients": clients[:10],
                "stream_ids": [c.stream_id for c, _ in refused][:10],
                "max_syn_to_rst_ms": round(slowest, 3),
            },
        ))
    return issues
