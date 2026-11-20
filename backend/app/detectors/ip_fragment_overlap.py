"""Overlapping IP fragments with different data (teardrop-style attack or a
broken stack): tshark flags them while reassembling."""
from __future__ import annotations

from typing import List

from ..models import Issue


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for (src, dst), datagrams in sorted(state.security.overlaps.items()):
        issues.append(Issue(
            id="frag-overlap-%s-%s" % (src, dst),
            type="ip_fragment_overlap",
            severity="critical",
            title="Fragmentos IP solapados de %s a %s" % (src, dst),
            detail=(
                "%d datagrama(s) de %s a %s tienen fragmentos que se solapan con datos "
                "distintos. Es la firma de ataques como teardrop o de evasión de IDS; "
                "una pila TCP/IP defectuosa también puede producirlo. Bloquéalos en el "
                "cortafuegos e identifica el origen." % (datagrams, src, dst)
            ),
            title_en="Overlapping IP fragments from %s to %s" % (src, dst),
            detail_en=(
                "%d datagram(s) from %s to %s have fragments that overlap with different "
                "data. This is the signature of attacks such as teardrop or IDS evasion; "
                "a broken TCP/IP stack can also cause it. Block them at the firewall and "
                "identify the source." % (datagrams, src, dst)
            ),
            conversation="%s <-> %s" % (src, dst),
            evidence={"source": src, "destination": dst, "datagrams": datagrams},
        ))
    return issues
