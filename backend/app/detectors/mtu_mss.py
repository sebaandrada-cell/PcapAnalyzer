"""MTU/MSS problems: low negotiated MSS, ICMP Fragmentation Needed and
suspected PMTUD black holes."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue
from ._util import conv_label


def _detect_mss_low(state, issues: List[Issue]) -> None:
    for conv in state.tcp_convs.values():
        negotiated = [m for m in (conv.mss_client, conv.mss_server) if m]
        if not negotiated:
            continue
        effective = min(negotiated)
        if effective >= config.MSS_LOW_THRESHOLD:
            continue
        issues.append(
            Issue(
                id="mss-low-%d" % conv.stream_id,
                type="mss_low",
                severity="info",
                title="MSS negociado bajo (%d bytes)" % effective,
                detail=(
                    "La conversación %s negoció un MSS efectivo de %d bytes "
                    "(umbral: %d). Suele indicar un túnel/VPN u overhead de "
                    "encapsulado en el camino." % (conv_label(conv), effective,
                                                   config.MSS_LOW_THRESHOLD)
                ),
                title_en="Low negotiated MSS (%d bytes)" % effective,
                detail_en=(
                    "Conversation %s negotiated an effective MSS of %d bytes "
                    "(threshold: %d). Usually indicates a tunnel/VPN or "
                    "encapsulation overhead on the path."
                    % (conv_label(conv), effective, config.MSS_LOW_THRESHOLD)
                ),
                conversation=conv_label(conv),
                evidence={
                    "stream_id": conv.stream_id,
                    "mss_client": conv.mss_client,
                    "mss_server": conv.mss_server,
                },
            )
        )


def _detect_icmp_frag_needed(state, issues: List[Issue]) -> None:
    grouped = {}
    for event in state.icmp_frag_events:
        grouped.setdefault((event.src, event.dst, event.mtu), []).append(event)
    for idx, ((router, host, mtu), events) in enumerate(grouped.items()):
        issues.append(
            Issue(
                id="icmp-frag-needed-%d" % idx,
                type="icmp_frag_needed",
                severity="warning",
                title="ICMP Fragmentation Needed (MTU %d en el camino)" % mtu,
                detail=(
                    "El router %s notificó a %s que sus paquetes exceden el MTU "
                    "del camino (%d bytes, %d aviso(s)). Si el emisor no reduce "
                    "el tamaño, ese tráfico se perderá." % (router, host, mtu,
                                                            len(events))
                ),
                title_en="ICMP Fragmentation Needed (path MTU %d)" % mtu,
                detail_en=(
                    "Router %s told %s that its packets exceed the path MTU "
                    "(%d bytes, %d notice(s)). If the sender does not reduce the "
                    "size, that traffic will be lost."
                    % (router, host, mtu, len(events))
                ),
                conversation="%s <-> %s" % (router, host),
                evidence={"router": router, "affected_host": host,
                          "path_mtu": mtu, "events": len(events)},
            )
        )


def _detect_pmtud_blackhole(state, issues: List[Issue]) -> None:
    for conv in state.tcp_convs.values():
        if conv.full_size_retrans < config.PMTUD_MIN_FULLSIZE_RETRANS:
            continue
        # If an ICMP frag-needed reached either peer this is not a black hole;
        # the icmp_frag_needed issue already covers it.
        if any(e.dst in (conv.src, conv.dst) for e in state.icmp_frag_events):
            continue
        issues.append(
            Issue(
                id="pmtud-blackhole-%d" % conv.stream_id,
                type="pmtud_blackhole",
                severity="warning",
                title="Posible agujero negro PMTUD",
                detail=(
                    "La conversación %s retransmitió %d veces segmentos de tamaño "
                    "máximo (MSS) sin que se observara ningún ICMP Fragmentation "
                    "Needed hacia sus extremos. Patrón típico de PMTUD roto: los "
                    "paquetes grandes se descartan silenciosamente en el camino."
                    % (conv_label(conv), conv.full_size_retrans)
                ),
                title_en="Possible PMTUD black hole",
                detail_en=(
                    "Conversation %s retransmitted maximum-size segments (MSS) "
                    "%d times with no ICMP Fragmentation Needed seen towards its "
                    "endpoints. Typical of broken PMTUD: large packets are "
                    "silently dropped on the path."
                    % (conv_label(conv), conv.full_size_retrans)
                ),
                conversation=conv_label(conv),
                evidence={
                    "stream_id": conv.stream_id,
                    "full_size_retransmissions": conv.full_size_retrans,
                    "mss_client": conv.mss_client,
                    "mss_server": conv.mss_server,
                },
            )
        )


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    _detect_mss_low(state, issues)
    _detect_icmp_frag_needed(state, issues)
    _detect_pmtud_blackhole(state, issues)
    return issues
