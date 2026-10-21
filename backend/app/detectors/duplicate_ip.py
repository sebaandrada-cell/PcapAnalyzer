"""Duplicate IP addresses: the same IP announced by several MACs via ARP."""
from __future__ import annotations

from typing import List

from ..models import Issue


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for idx, (ip_addr, macs) in enumerate(state.arp_map.items()):
        if len(macs) < 2:
            continue
        mac_list = sorted(macs)
        issues.append(
            Issue(
                id="ip-duplicate-%d" % idx,
                type="ip_duplicate",
                severity="warning",
                title="IP anunciada por varias MACs: %s" % ip_addr,
                detail=(
                    "La dirección %s apareció como origen ARP desde %d MACs (%s). "
                    "Puede indicar conflicto de IP, pero también proxy ARP, "
                    "redundancia o segmentos distintos; verifica la VLAN y el tipo "
                    "de anuncio antes de concluir que hay duplicidad."
                    % (ip_addr, len(macs), ", ".join(mac_list))
                ),
                title_en="IP announced by multiple MACs: %s" % ip_addr,
                detail_en=(
                    "Address %s appeared as an ARP source from %d MACs (%s). "
                    "This may indicate an IP conflict, but can also be proxy ARP, "
                    "redundancy, or separate segments; verify VLAN and announcement "
                    "type before concluding there is a duplicate."
                    % (ip_addr, len(macs), ", ".join(mac_list))
                ),
                conversation=ip_addr,
                evidence={"ip": ip_addr, "macs": mac_list,
                          "announcements": sum(macs.values()),
                          "proxy_arp_or_segment_boundary_possible": True},
            )
        )
    return issues
