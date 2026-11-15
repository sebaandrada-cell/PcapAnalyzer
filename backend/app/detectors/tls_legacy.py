"""Servers that negotiated an obsolete TLS version (SSL 3.0, TLS 1.0, TLS 1.1)."""
from __future__ import annotations

from typing import Dict, List

from ..models import Issue

# Version chosen in the ServerHello. TLS 1.2 and 1.3 both show 0x0303 there.
_LEGACY = {"0x0300": "SSL 3.0", "0x0301": "TLS 1.0", "0x0302": "TLS 1.1"}


def detect(state) -> List[Issue]:
    by_server: Dict[str, list] = {}
    for session in state.tls_sessions.values():
        if session.negotiated in _LEGACY:
            by_server.setdefault(session.server, []).append(session)

    issues: List[Issue] = []
    for idx, (server, sessions) in enumerate(by_server.items()):
        versions = sorted({_LEGACY[s.negotiated] for s in sessions})
        names = sorted({s.sni for s in sessions if s.sni})[:5]
        issues.append(Issue(
            id="tls-legacy-%d" % idx,
            type="tls_legacy_version",
            severity="warning",
            title="TLS obsoleto negociado con %s (%s)" % (server, ", ".join(versions)),
            detail=(
                "El servidor %s aceptó %d sesión(es) con %s. Son versiones retiradas "
                "(RFC 8996): sin cifrados modernos y rechazadas por navegadores y "
                "librerías actuales, lo que acaba en fallos de conexión intermitentes "
                "según el cliente."
                % (server, len(sessions), ", ".join(versions))
            ),
            title_en="Obsolete TLS negotiated with %s (%s)" % (server, ", ".join(versions)),
            detail_en=(
                "Server %s accepted %d session(s) with %s. These versions are "
                "deprecated (RFC 8996): no modern ciphers and refused by current "
                "browsers and libraries, which ends in connection failures that "
                "depend on the client."
                % (server, len(sessions), ", ".join(versions))
            ),
            conversation=server,
            evidence={"server": server, "sessions": len(sessions),
                      "stream_ids": sorted(s.stream_id for s in sessions)[:10],
                      "versions": versions, "server_names": names},
        ))
    return issues
