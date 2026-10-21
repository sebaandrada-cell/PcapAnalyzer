"""VPN/tunnel health: unanswered IKE, IKE without ESP, one-way ESP."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue

_DATA_TUNNEL_TYPES = ("esp", "wireguard", "openvpn")


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
                        id="tunnel-one-way-%s-%s" % pair,
                        type="esp_one_way",
                        severity="warning",
                        title="Túnel %s unidireccional" % tunnel_type.upper(),
                        detail=(
                            "Se observan %d paquetes %s de %s hacia %s pero ninguno "
                            "de vuelta: túnel asimétrico o roto (SA caducada, "
                            "routing asimétrico o peer caído)."
                            % (sent, tunnel_type.upper(), initiator, responder)
                        ),
                        title_en="%s tunnel is one-way" % tunnel_type.upper(),
                        detail_en=(
                            "%d %s packets seen from %s to %s but none coming "
                            "back: asymmetric or broken tunnel (expired SA, "
                            "asymmetric routing or dead peer)."
                            % (sent, tunnel_type.upper(), initiator, responder)
                        ),
                        conversation=label,
                        evidence={"tunnel_type": tunnel_type, "sender": initiator,
                                  "silent_peer": responder, "packets": sent},
                    )
                )

    return issues
