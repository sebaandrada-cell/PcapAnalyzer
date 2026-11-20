"""ARP spoofing: one MAC claiming several IPs, at least one of which another
MAC also claims (a man-in-the-middle poisons the gateway and its victims)."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set

from .. import config
from ..models import Issue


def detect(state) -> List[Issue]:
    ips_by_mac: Dict[str, Set[str]] = defaultdict(set)
    for ip_addr, macs in state.arp_map.items():
        for mac in macs:
            ips_by_mac[mac].add(ip_addr)

    issues: List[Issue] = []
    for mac, ips in sorted(ips_by_mac.items()):
        if len(ips) < config.ARP_SPOOF_MIN_IPS:
            continue
        contested = sorted(ip for ip in ips if len(state.arp_map.get(ip, {})) > 1)
        if not contested:
            continue
        issues.append(Issue(
            id="arp-spoofing-%s" % mac,
            type="arp_spoofing",
            severity="critical",
            title="Posible ARP spoofing desde %s" % mac,
            detail=(
                "La MAC %s se anuncia como %d IPs (%s) y otras MACs también reclaman "
                "%s. Es el patrón de un ataque de intermediario (envenenamiento ARP). "
                "Un clúster o una IP virtual (VRRP/HSRP) también puede producirlo: "
                "comprueba a qué equipo pertenece esa MAC."
                % (mac, len(ips), ", ".join(sorted(ips)), ", ".join(contested))
            ),
            title_en="Possible ARP spoofing from %s" % mac,
            detail_en=(
                "MAC %s announces itself as %d IPs (%s) and other MACs also claim %s. "
                "This is the pattern of a man-in-the-middle attack (ARP poisoning). A "
                "cluster or a virtual IP (VRRP/HSRP) can also cause it: check which "
                "device owns that MAC."
                % (mac, len(ips), ", ".join(sorted(ips)), ", ".join(contested))
            ),
            evidence={"mac": mac, "ips": sorted(ips), "contested_ips": contested},
        ))
    return issues
