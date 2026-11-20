"""Logins sent in clear text (FTP, POP3, IMAP, SMTP AUTH, HTTP Basic).

Only the protocol, the server and how many logins are reported: user names
and passwords are never read into the result."""
from __future__ import annotations

from typing import List

from ..models import Issue


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for (protocol, server), use in sorted(state.security.logins.items()):
        clients = sorted(use.clients)
        issues.append(Issue(
            id="cleartext-%s-%s" % (protocol.replace(" ", "-").lower(), server),
            type="cleartext_credentials",
            severity="warning",
            title="Credenciales sin cifrar: %s hacia %s" % (protocol, server),
            detail=(
                "Se ven %d inicios de sesión %s hacia %s sin cifrar, desde %d equipo(s). "
                "Cualquiera en el camino puede leer el usuario y la contraseña. Pasa el "
                "servicio a su versión cifrada (FTPS/SFTP, POP3S/IMAPS, SMTP con "
                "STARTTLS, HTTPS) y cambia esas contraseñas. PcapAnalyzer no muestra "
                "las credenciales." % (use.count, protocol, server, len(clients))
            ),
            title_en="Cleartext credentials: %s to %s" % (protocol, server),
            detail_en=(
                "%d %s logins to %s are sent unencrypted, from %d host(s). Anyone on "
                "the path can read the user name and password. Move the service to its "
                "encrypted version (FTPS/SFTP, POP3S/IMAPS, SMTP with STARTTLS, HTTPS) "
                "and change those passwords. PcapAnalyzer does not show the "
                "credentials." % (use.count, protocol, server, len(clients))
            ),
            conversation=server,
            evidence={"protocol": protocol, "server": server, "logins": use.count,
                      "clients": clients},
        ))
    return issues
