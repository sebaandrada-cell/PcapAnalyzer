"""Insecure protocols in use: Telnet, SMBv1, SNMP v1/v2c."""
from __future__ import annotations

from typing import List

from ..models import Issue

_WHY = {
    "Telnet": ("todo, contraseñas incluidas, viaja sin cifrar; usa SSH",
               "everything, passwords included, travels unencrypted; use SSH"),
    "SMBv1": ("versión obsoleta y explotada por gusanos como WannaCry; desactívala "
              "y usa SMB 2/3", "obsolete version exploited by worms such as "
              "WannaCry; disable it and use SMB 2/3"),
    "SNMP v1": ("la comunidad viaja en claro y no hay autenticación real; usa SNMPv3",
                "the community string travels in clear and there is no real "
                "authentication; use SNMPv3"),
    "SNMP v2c": ("la comunidad viaja en claro y no hay autenticación real; usa SNMPv3",
                 "the community string travels in clear and there is no real "
                 "authentication; use SNMPv3"),
}


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for protocol, use in sorted(state.security.insecure.items()):
        servers, clients = sorted(use.servers), sorted(use.clients)
        why_es, why_en = _WHY[protocol]
        issues.append(Issue(
            id="insecure-%s" % protocol.replace(" ", "-").lower(),
            type="insecure_protocol",
            severity="warning",
            title="Protocolo inseguro en uso: %s" % protocol,
            detail=("%d paquetes %s con %d servidor(es) (%s): %s."
                    % (use.packets, protocol, len(servers), ", ".join(servers), why_es)),
            title_en="Insecure protocol in use: %s" % protocol,
            detail_en=("%d %s packets with %d server(s) (%s): %s."
                       % (use.packets, protocol, len(servers), ", ".join(servers), why_en)),
            conversation=servers[0] if len(servers) == 1 else None,
            evidence={"protocol": protocol, "packets": use.packets, "servers": servers,
                      "clients": clients},
        ))
    return issues
