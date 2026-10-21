"""TLS alert records: handshake_failure and other fatal alerts."""
from __future__ import annotations

from typing import List

from ..models import Issue

_TLS_ALERT_NAMES = {
    0: "close_notify",
    40: "handshake_failure",
    42: "bad_certificate",
    46: "certificate_unknown",
    48: "unknown_ca",
    49: "access_denied",
    70: "protocol_version",
    80: "internal_error",
    112: "unrecognized_name",
    116: "certificate_required",
}


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for idx, alert in enumerate(state.tls_alerts):
        if alert.desc == 0:  # close_notify is benign
            continue
        name = _TLS_ALERT_NAMES.get(alert.desc, "alert_%d" % alert.desc)
        fatal = alert.level == 2
        issues.append(
            Issue(
                id="tls-alert-%d" % idx,
                type="tls_handshake_failure" if alert.desc == 40 else "tls_alert",
                severity="warning" if fatal else "info",
                title="Alerta TLS %s (%s)" % (name, "fatal" if fatal else "warning"),
                detail=(
                    "El host %s envió una alerta TLS '%s' a %s. "
                    % (alert.src, name, alert.dst)
                    + (
                        "El handshake TLS falló: revisar cipher suites, versiones de "
                        "protocolo o certificados incompatibles."
                        if alert.desc == 40
                        else "Puede indicar un problema en la sesión TLS."
                    )
                ),
                title_en="TLS alert %s (%s)" % (name, "fatal" if fatal else "warning"),
                detail_en=(
                    "Host %s sent a TLS alert '%s' to %s. "
                    % (alert.src, name, alert.dst)
                    + (
                        "The TLS handshake failed: check cipher suites, protocol "
                        "versions or incompatible certificates."
                        if alert.desc == 40
                        else "May indicate a problem in the TLS session."
                    )
                ),
                conversation="%s <-> %s" % (alert.src, alert.dst),
                evidence={
                    "alert_description": name,
                    "alert_code": alert.desc,
                    "alert_level": alert.level,
                    "tcp_stream": alert.stream_id,
                },
            )
        )
    return issues
