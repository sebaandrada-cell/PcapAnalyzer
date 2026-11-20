"""VPN/tunnel health: unanswered IKE, IKE without ESP, one-way tunnels,
unanswered WireGuard/OpenVPN handshakes and too-frequent renegotiation."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue

_DATA_TUNNEL_TYPES = ("esp", "wireguard", "openvpn", "gre", "l2tp", "teredo")
_HANDSHAKE_NAMES = {"wireguard": "WireGuard", "openvpn": "OpenVPN", "ike": "IKE"}


def detect(state) -> List[Issue]:
    issues: List[Issue] = []

    data_pairs = {
        pair for (tunnel_type, pair) in state.tunnels
        if tunnel_type in _DATA_TUNNEL_TYPES
    }

    for (tunnel_type, pair), tunnel in state.tunnels.items():
        sent, received = tunnel.packets_a2b, tunnel.packets_b2a
        initiator, responder = tunnel.peer_a, tunnel.peer_b
        if received > sent:  # normalize: 'sent' is the dominant direction
            sent, received = received, sent
            initiator, responder = responder, initiator
        label = "%s <-> %s" % (tunnel.peer_a, tunnel.peer_b)
        issues.extend(_renegotiation(tunnel, pair, label))
        unanswered = _unanswered_handshake(tunnel, pair, label)
        if unanswered is not None:
            issues.append(unanswered)
            continue

        if tunnel_type == "ike":
            if sent >= config.IKE_NO_RESPONSE_MIN and received == 0:
                issues.append(
                    Issue(
                        id="ike-no-response-%s-%s" % pair,
                        type="ike_no_response",
                        severity="warning",
                        title="IKE sin respuesta observada",
                        detail=(
                            "Se observaron %d mensajes IKE de %s a %s sin respuesta "
                            "en esta captura. Puede deberse a filtrado, falta de "
                            "alcance o un gateway sin respuesta; una captura parcial "
                            "o un punto de observación asimétrico también puede "
                            "ocultar la respuesta."
                            % (sent, initiator, responder)
                        ),
                        title_en="No IKE response observed",
                        detail_en=(
                            "%d IKE messages from %s to %s were observed without "
                            "a response in this capture. Filtering, reachability, "
                            "or an unresponsive gateway are possible causes; a "
                            "partial capture or asymmetric observation point may "
                            "also hide the response." % (sent, initiator, responder)
                        ),
                        conversation=label,
                        evidence={"initiator": initiator, "responder": responder,
                                  "requests": sent},
                    )
                )
            elif sent > 0 and received > 0 and pair not in data_pairs:
                issues.append(
                    Issue(
                        id="ike-incomplete-%s-%s" % pair,
                        type="ike_handshake_incomplete",
                        severity="warning",
                        title="Negociación IKE sin tráfico ESP posterior",
                        detail=(
                            "Los peers %s y %s intercambiaron mensajes IKE pero en "
                            "la captura nunca aparece tráfico ESP entre ellos: la "
                            "negociación pudo fallar (autenticación, propuestas "
                            "incompatibles) o el túnel no llegó a usarse."
                            % (tunnel.peer_a, tunnel.peer_b)
                        ),
                        title_en="IKE negotiation with no subsequent ESP traffic",
                        detail_en=(
                            "Peers %s and %s exchanged IKE messages but no ESP "
                            "traffic between them ever appears in the capture: "
                            "negotiation may have failed (authentication, "
                            "incompatible proposals) or the tunnel was never used."
                            % (tunnel.peer_a, tunnel.peer_b)
                        ),
                        conversation=label,
                        evidence={"peer_a": tunnel.peer_a, "peer_b": tunnel.peer_b,
                                  "ike_packets": sent + received},
                    )
                )

        elif tunnel_type in _DATA_TUNNEL_TYPES:
            if sent >= config.ESP_ONE_WAY_MIN and received == 0:
                issues.append(
                    Issue(
                        id="tunnel-one-way-%s-%s-%s" % ((tunnel_type,) + pair),
                        type="esp_one_way" if tunnel_type == "esp" else "tunnel_one_way",
                        severity="warning",
                        title="Túnel %s unidireccional" % tunnel_type.upper(),
                        detail=(
                            "Se observan %d paquetes %s de %s hacia %s pero ninguno "
                            "de vuelta: túnel asimétrico o roto (SA o claves caducadas, "
                            "routing asimétrico o peer caído)."
                            % (sent, tunnel_type.upper(), initiator, responder)
                        ),
                        title_en="%s tunnel is one-way" % tunnel_type.upper(),
                        detail_en=(
                            "%d %s packets seen from %s to %s but none coming "
                            "back: asymmetric or broken tunnel (expired SA or keys, "
                            "asymmetric routing or dead peer)."
                            % (sent, tunnel_type.upper(), initiator, responder)
                        ),
                        conversation=label,
                        evidence={"tunnel_type": tunnel_type, "sender": initiator,
                                  "silent_peer": responder, "packets": sent},
                    )
                )

    return issues


def _unanswered_handshake(tunnel, pair, label):
    """WireGuard/OpenVPN handshakes sent again and again with no answer."""
    if tunnel.type not in ("wireguard", "openvpn"):
        return None
    if tunnel.handshake_replies or tunnel.handshake_requests < config.TUNNEL_HANDSHAKE_NO_RESPONSE_MIN:
        return None
    name = _HANDSHAKE_NAMES[tunnel.type]
    sender, peer = ((tunnel.peer_a, tunnel.peer_b) if tunnel.packets_a2b >= tunnel.packets_b2a
                    else (tunnel.peer_b, tunnel.peer_a))
    count = tunnel.handshake_requests
    return Issue(
        id="tunnel-handshake-%s-%s-%s" % ((tunnel.type,) + pair),
        type="tunnel_handshake_no_response",
        severity="warning",
        title="Handshake %s sin respuesta" % name,
        detail=(
            "%s envió %d inicios de handshake %s a %s y no se ve ninguna respuesta. "
            "El túnel no llega a levantarse: puerto UDP filtrado en el camino, peer "
            "caído o claves que el peer no reconoce (WireGuard no responde a una "
            "clave pública que no tiene configurada)." % (sender, count, name, peer)
        ),
        title_en="%s handshake with no response" % name,
        detail_en=(
            "%s sent %d %s handshake initiations to %s and no response is seen. "
            "The tunnel never comes up: UDP port filtered on the path, peer down, "
            "or keys the peer does not recognise (WireGuard stays silent to a "
            "public key it does not have configured)." % (sender, count, name, peer)
        ),
        conversation=label,
        evidence={"tunnel_type": tunnel.type, "initiator": sender, "responder": peer,
                  "initiations": count},
    )


def _renegotiation(tunnel, pair, label) -> List[Issue]:
    """Answered handshakes repeated far more often than a normal rekey."""
    replies = tunnel.handshake_replies
    if replies < config.TUNNEL_RENEGOTIATION_MIN or tunnel.first_reply_ts is None:
        return []
    interval = (tunnel.last_reply_ts - tunnel.first_reply_ts) / (replies - 1)
    if interval >= config.TUNNEL_RENEGOTIATION_MAX_INTERVAL_S:
        return []
    name = _HANDSHAKE_NAMES.get(tunnel.type, tunnel.type.upper())
    interval = round(interval, 1)
    return [Issue(
        id="tunnel-renegotiation-%s-%s-%s" % ((tunnel.type,) + pair),
        type="tunnel_renegotiation",
        severity="warning",
        title="Túnel %s renegociado %d veces (cada %g s)" % (name, replies, interval),
        detail=(
            "Entre %s y %s se completaron %d handshakes %s, uno cada %g s de media. "
            "Un túnel sano solo renegocia al renovar claves (minutos u horas): el "
            "túnel se cae y vuelve a levantarse. Suele ser pérdida intermitente en el "
            "camino, un NAT que olvida la sesión, tiempos de vida de SA o DPD/keepalive "
            "mal ajustados, o dos peers que se pisan la configuración."
            % (tunnel.peer_a, tunnel.peer_b, replies, name, interval)
        ),
        title_en="%s tunnel renegotiated %d times (every %g s)" % (name, replies, interval),
        detail_en=(
            "Between %s and %s, %d %s handshakes completed, one every %g s on average. "
            "A healthy tunnel only renegotiates when it rekeys (minutes or hours): this "
            "tunnel keeps dropping and coming back. Usual causes are intermittent loss on "
            "the path, a NAT forgetting the session, badly tuned SA lifetimes or "
            "DPD/keepalives, or two peers fighting over the configuration."
            % (tunnel.peer_a, tunnel.peer_b, replies, name, interval)
        ),
        conversation=label,
        evidence={"tunnel_type": tunnel.type, "peer_a": tunnel.peer_a,
                  "peer_b": tunnel.peer_b, "handshakes": replies,
                  "avg_interval_s": interval},
    )]
