"""ARP storm: a sustained rate of ARP requests on the segment.

A burst is normal (a host coming up, a cache flush). Several seconds at a high
rate point at a scan or sweep that makes the gateway resolve many addresses, a
misconfigured host, or a loop. The evidence names the busiest senders and how
many distinct addresses were asked for, which separates a sweep (many targets)
from a host repeating the same question (few targets).
"""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue

_TOP_SENDERS = 5


def detect(state) -> List[Issue]:
    rates = state.arp_requests_per_second
    threshold = config.ARP_STORM_RATE_PER_S
    storm_seconds = [count for count in rates.values() if count >= threshold]
    if len(storm_seconds) < config.ARP_STORM_MIN_SECONDS:
        return []

    total = sum(rates.values())
    peak = max(storm_seconds)
    targets = len(state.arp_request_targets)
    senders = sorted(state.arp_request_senders.items(), key=lambda kv: (-kv[1][0], kv[0]))
    top = [{"mac": mac, "ips": list(ips), "requests": count}
           for mac, (count, ips) in senders[:_TOP_SENDERS]]

    lead_es = lead_en = ""
    if top:
        share = round(100.0 * top[0]["requests"] / total) if total else 0
        who = top[0]["mac"] + (" (%s)" % ", ".join(top[0]["ips"]) if top[0]["ips"] else "")
        lead_es = " El %d %% de las peticiones sale de %s." % (share, who)
        lead_en = " %d%% of the requests come from %s." % (share, who)

    return [
        Issue(
            id="arp-storm-0",
            type="arp_storm",
            severity="warning",
            title="Tormenta ARP: hasta %d peticiones por segundo" % peak,
            detail=(
                "Durante %d segundos hubo %d o más peticiones ARP por segundo "
                "(pico de %d, %d peticiones en total, %d direcciones distintas "
                "preguntadas).%s Muchas direcciones distintas desde un mismo equipo "
                "suelen ser un barrido o escaneo que obliga al router a resolverlas; "
                "pocas direcciones repetidas apuntan a un equipo mal configurado o a "
                "un bucle de capa 2."
                % (len(storm_seconds), threshold, peak, total, targets, lead_es)
            ),
            title_en="ARP storm: up to %d requests per second" % peak,
            detail_en=(
                "For %d seconds there were %d or more ARP requests per second "
                "(peak %d, %d requests in total, %d distinct addresses asked for).%s "
                "Many distinct addresses from one device usually mean a sweep or scan "
                "that makes the router resolve them; a few repeated addresses point to "
                "a misconfigured host or a layer-2 loop."
                % (len(storm_seconds), threshold, peak, total, targets, lead_en)
            ),
            evidence={
                "requests": total,
                "peak_requests_per_s": peak,
                "seconds_over_threshold": len(storm_seconds),
                "threshold_per_s": threshold,
                "distinct_targets": targets,
                "top_senders": top,
            },
        )
    ]
