"""DHCP leases that failed: NAK, DECLINE and requests nobody answered."""
from __future__ import annotations

from typing import List

from .. import config
from ..models import Issue

_DISCOVER, _OFFER, _REQUEST, _DECLINE, _ACK, _NAK = 1, 2, 3, 4, 5, 6
MIN_DHCP_ATTEMPTS = config.DHCP_NO_RESPONSE_MIN_ATTEMPTS


def _evidence(txns) -> dict:
    return {
        "count": len({txn.client_mac for txn in txns}),  # clients, not transactions
        "clients": sorted({txn.client_mac for txn in txns})[:10],
        "servers": sorted({txn.server for txn in txns if txn.server})[:5],
    }


def detect(state) -> List[Issue]:
    txns = list(state.dhcp_txns.values())
    nak = [t for t in txns if _NAK in t.types]
    declined = [t for t in txns if _DECLINE in t.types]
    # A capture taken on another host sees a neighbour's broadcast DISCOVER but
    # not the unicast answer: only report a client that had to try again.
    open_txns = [t for t in txns
                 if t.types & {_DISCOVER, _REQUEST} and not t.types & {_OFFER, _ACK, _NAK}]
    attempts: dict = {}
    for txn in open_txns:
        attempts[txn.client_mac] = attempts.get(txn.client_mac, 0) + max(1, txn.requests)
    unanswered = [t for t in open_txns if attempts[t.client_mac] >= MIN_DHCP_ATTEMPTS]

    issues: List[Issue] = []
    if nak:
        ev = _evidence(nak)
        issues.append(Issue(
            id="dhcp-nak",
            type="dhcp_nak",
            severity="warning",
            title="El servidor DHCP rechazó peticiones (NAK: %d)" % _evidence(nak)["count"],
            detail=(
                "%d cliente(s) recibieron DHCP NAK (%s). El servidor no acepta la "
                "dirección pedida: el cliente viene de otra red, la concesión caducó o "
                "hay dos servidores DHCP con ámbitos distintos en el mismo segmento."
                % (ev["count"], ", ".join(ev["clients"][:3]))
            ),
            title_en="The DHCP server refused requests (NAK: %d)" % _evidence(nak)["count"],
            detail_en=(
                "%d client(s) received a DHCP NAK (%s). The server does not accept the "
                "requested address: the client comes from another network, the lease "
                "expired, or two DHCP servers with different scopes share the segment."
                % (ev["count"], ", ".join(ev["clients"][:3]))
            ),
            conversation=None,
            evidence=ev,
        ))
    if declined:
        ev = _evidence(declined)
        issues.append(Issue(
            id="dhcp-declined",
            type="dhcp_declined",
            severity="warning",
            title="Clientes rechazaron la IP ofrecida (DECLINE: %d)" % _evidence(declined)["count"],
            detail=(
                "%d cliente(s) enviaron DHCP DECLINE (%s). El cliente comprobó la "
                "dirección ofrecida y ya estaba en uso: hay un equipo con IP fija dentro "
                "del rango del servidor DHCP."
                % (ev["count"], ", ".join(ev["clients"][:3]))
            ),
            title_en="Clients declined the offered IP (DECLINE: %d)" % _evidence(declined)["count"],
            detail_en=(
                "%d client(s) sent a DHCP DECLINE (%s). The client probed the offered "
                "address and it was already in use: a host with a static IP sits "
                "inside the DHCP server's range."
                % (ev["count"], ", ".join(ev["clients"][:3]))
            ),
            conversation=None,
            evidence=ev,
        ))
    if unanswered:
        ev = _evidence(unanswered)
        issues.append(Issue(
            id="dhcp-no-response",
            type="dhcp_no_response",
            severity="warning",
            title="Peticiones DHCP sin respuesta (%d)" % _evidence(unanswered)["count"],
            detail=(
                "%d cliente(s) pidieron dirección varias veces y ningún servidor contestó (%s). "
                "Servidor DHCP caído o sin direcciones libres, falta el relay (ip helper) "
                "en la VLAN, o un filtro bloquea UDP 67/68."
                % (ev["count"], ", ".join(ev["clients"][:3]))
            ),
            title_en="DHCP requests with no answer (%d)" % _evidence(unanswered)["count"],
            detail_en=(
                "%d client(s) asked for an address repeatedly and no server answered (%s). DHCP "
                "server down or out of free addresses, missing relay (ip helper) on the "
                "VLAN, or a filter blocking UDP 67/68."
                % (ev["count"], ", ".join(ev["clients"][:3]))
            ),
            conversation=None,
            evidence=ev,
        ))
    return issues
