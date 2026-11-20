"""Demo mode (LLM_DEMO=1): deterministic fake AI responses built from the
analysis itself — no API calls, no credentials, no cost. Lets users exercise
the diagnosis panel and the NL query bar before configuring a real key.
"""
from __future__ import annotations

import unicodedata
from typing import Any, Dict, List, Tuple

from ..models import AnalysisResult, Issue

_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}

_NEXT_STEP_BY_TYPE = {
    "tcp_syn_rst": "Revisa las reglas del firewall entre los hosts implicados y "
                   "confirma que el puerto de destino está en escucha.",
    "tcp_retransmissions": "Comprueba pérdida de paquetes en el camino (errores de "
                           "interfaz, duplex, saturación de enlaces) entre los extremos.",
    "ip_duplicate": "Localiza las dos MACs que anuncian la misma IP y corrige la "
                    "dirección duplicada (o investiga un posible ARP spoofing).",
    "arp_storm": "Identifica el equipo que más pregunta: si barre muchas direcciones, "
                 "busca el escaneo que lo provoca; si repite pocas, revisa su "
                 "configuración y descarta un bucle de capa 2 (STP).",
    "ike_no_response": "Verifica que el gateway VPN está activo y que UDP 500/4500 "
                       "no está bloqueado en el camino.",
    "esp_one_way": "Revisa el estado de las SAs IPsec en ambos extremos y el routing "
                   "de retorno del túnel.",
    "ip_fragments_incomplete": "Busca filtros que descarten fragmentos IP y revisa el "
                               "MTU de los enlaces intermedios.",
    "pmtud_blackhole": "Permite ICMP tipo 3/código 4 en los firewalls del camino o "
                       "ajusta el MSS clamping en el router.",
    "dns_unanswered": "Comprueba la disponibilidad del servidor DNS y que UDP 53 no "
                      "esté filtrado.",
    "dns_slow": "Mide la latencia hacia el servidor DNS y valora usar un resolver "
                "más cercano.",
    "dns_servfail": "Revisa los logs del servidor DNS: zona rota, upstream caído o "
                    "validación DNSSEC fallida.",
    "tls_handshake_failure": "Compara versiones de TLS y cipher suites soportadas "
                             "por cliente y servidor.",
    "tcp_zero_window": "Revisa la carga de la aplicación receptora: no vacía su "
                       "buffer a tiempo.",
    "tcp_slow_handshake": "Mide el RTT hacia el servidor y su carga: el SYN-ACK "
                          "tarda demasiado.",
    "http_server_errors": "Revisa los logs de la aplicación y de sus dependencias "
                          "(backend, base de datos, proxy inverso) en el momento de "
                          "los errores 5xx.",
    "http_client_errors": "Identifica qué cliente y qué rutas generan los 4xx: URL "
                          "obsoletas, credenciales o un límite de peticiones.",
    "http_slow": "Compara el tiempo de respuesta HTTP con el RTT del saludo TCP: si la "
                 "red es rápida, perfila la aplicación o su base de datos.",
    "dhcp_nak": "Comprueba que solo hay un servidor DHCP por segmento y que el ámbito "
                "coincide con la subred del cliente.",
    "dhcp_declined": "Busca el equipo con IP fija dentro del rango DHCP y exclúyela "
                     "del ámbito o cambia su dirección.",
    "dhcp_no_response": "Verifica que el servidor DHCP está activo y con direcciones "
                        "libres, y que la VLAN tiene configurado el relay (ip helper).",
    "tls_legacy_version": "Habilita TLS 1.2 o 1.3 en el servidor y desactiva SSL 3.0, "
                          "TLS 1.0 y TLS 1.1.",
}

# English counterpart of _NEXT_STEP_BY_TYPE. Keep both dicts in sync: a missing
# key silently drops that issue's step from the English text (tests enforce it).
_NEXT_STEP_BY_TYPE_EN = {
    "tcp_syn_rst": "Check the firewall rules between the hosts involved and "
                   "confirm the destination port is listening.",
    "tcp_retransmissions": "Check for packet loss along the path (interface errors, "
                           "duplex, saturated links) between the endpoints.",
    "ip_duplicate": "Find the two MACs announcing the same IP and fix the duplicate "
                    "address (or investigate possible ARP spoofing).",
    "arp_storm": "Identify the device asking the most: if it sweeps many addresses, "
                 "find the scan behind it; if it repeats a few, check its "
                 "configuration and rule out a layer-2 loop (STP).",
    "ike_no_response": "Verify that the VPN gateway is up and that UDP 500/4500 is "
                       "not blocked along the path.",
    "esp_one_way": "Check the state of the IPsec SAs at both ends and the return "
                   "routing of the tunnel.",
    "ip_fragments_incomplete": "Look for filters that drop IP fragments and review "
                               "the MTU of the intermediate links.",
    "pmtud_blackhole": "Allow ICMP type 3/code 4 on the firewalls along the path or "
                       "adjust MSS clamping on the router.",
    "dns_unanswered": "Check the availability of the DNS server and that UDP 53 is "
                      "not filtered.",
    "dns_slow": "Measure the latency to the DNS server and consider using a closer "
                "resolver.",
    "dns_servfail": "Review the DNS server logs: broken zone, upstream down or failed "
                    "DNSSEC validation.",
    "tls_handshake_failure": "Compare the TLS versions and cipher suites supported by "
                             "client and server.",
    "tcp_zero_window": "Check the load on the receiving application: it is not "
                       "draining its buffer in time.",
    "tcp_slow_handshake": "Measure the RTT to the server and its load: the SYN-ACK "
                          "takes too long.",
    "http_server_errors": "Check the application logs and its dependencies (backend, "
                          "database, reverse proxy) at the time of the 5xx errors.",
    "http_client_errors": "Identify which client and paths produce the 4xx: stale "
                          "URLs, credentials or a rate limit.",
    "http_slow": "Compare the HTTP response time with the TCP handshake RTT: if the "
                 "network is fast, profile the application or its database.",
    "dhcp_nak": "Make sure there is a single DHCP server per segment and its scope "
                "matches the client's subnet.",
    "dhcp_declined": "Find the host with a static IP inside the DHCP range and exclude "
                     "it from the scope or change its address.",
    "dhcp_no_response": "Verify the DHCP server is up with free addresses and that the "
                        "VLAN has the relay (ip helper) configured.",
    "tls_legacy_version": "Enable TLS 1.2 or 1.3 on the server and disable SSL 3.0, "
                          "TLS 1.0 and TLS 1.1.",
}

DEMO_MARK = "_(modo demo: texto generado sin IA — configura ANTHROPIC_API_KEY para el diagnóstico real)_"

# Language-specific scaffolding. The interpolated evidence (issue titles and
# details) comes from the detectors, which provide Spanish text plus English
# title_en/detail_en; demo mode is a fallback for trying the UI without an API
# key.
_DEMO = {
    "es": {
        "h": ("Qué está pasando", "Causa probable", "Siguiente paso recomendado"),
        "mark": DEMO_MARK,
        "fallback_step": "Revisa en detalle los problemas listados en el dashboard.",
        "intro": "La captura (%d paquetes, %d conversaciones) presenta %d problema(s); "
                 "los más relevantes: %s",
        "clean_story": "La captura (%d paquetes, %d conversaciones) no presenta "
                       "problemas detectables por el motor.",
        "clean_cause": "Tráfico dentro de parámetros normales.",
        "clean_step": "Si el problema persiste, captura en otro punto de la red o "
                      "durante más tiempo.",
        "suffix": "(modo demo)",
    },
    "en": {
        "h": ("What is happening", "Likely cause", "Recommended next step"),
        "mark": "_(demo mode: text generated without AI — set ANTHROPIC_API_KEY for "
                "the real diagnosis)_",
        "fallback_step": "Review the problems listed in the dashboard in detail.",
        "intro": "The capture (%d packets, %d conversations) has %d problem(s); "
                 "the most relevant: %s",
        "clean_story": "The capture (%d packets, %d conversations) has no problems "
                       "detectable by the engine.",
        "clean_cause": "Traffic within normal parameters.",
        "clean_step": "If the problem persists, capture at another point in the "
                      "network or for longer.",
        "suffix": "(demo mode)",
    },
}


def _demo(lang: str):
    return _DEMO.get(lang, _DEMO["es"])


def _top_issues(analysis: AnalysisResult, count: int = 3) -> List[Issue]:
    return sorted(
        analysis.issues, key=lambda i: _SEVERITY_ORDER.get(i.severity, 9)
    )[:count]


def demo_diagnosis(analysis: AnalysisResult, lang: str = "es") -> Dict[str, Any]:
    cfg = _demo(lang)
    h1, h2, h3 = cfg["h"]
    issues = _top_issues(analysis)
    summary = analysis.summary

    if issues:
        english = lang == "en"
        story = " ".join(
            (issue.detail_en if english and issue.detail_en else issue.detail)
            for issue in issues[:2]
        )
        causes = "; ".join(
            (issue.title_en if english and issue.title_en else issue.title).lower()
            for issue in issues
        )
        next_steps = _NEXT_STEP_BY_TYPE_EN if english else _NEXT_STEP_BY_TYPE
        steps = []
        for issue in issues:
            step = next_steps.get(issue.type)
            if step and step not in steps:
                steps.append(step)
        if not steps:
            steps.append(cfg["fallback_step"])
        steps_text = " ".join(
            "%d) %s" % (index + 1, step) for index, step in enumerate(steps[:3])
        )
        text = (
            "**%s**: %s\n\n**%s**: %s.\n\n**%s**: %s\n\n%s"
            % (h1,
               cfg["intro"] % (summary.packets, summary.conversations,
                               len(analysis.issues), story),
               h2, causes, h3, steps_text, cfg["mark"])
        )
    else:
        text = (
            "**%s**: %s\n\n**%s**: %s\n\n**%s**: %s\n\n%s"
            % (h1, cfg["clean_story"] % (summary.packets, summary.conversations),
               h2, cfg["clean_cause"], h3, cfg["clean_step"], cfg["mark"])
        )

    return {
        "diagnosis": text,
        "model": "demo",
        "usage": {"input_tokens": 0, "output_tokens": 0},
    }


# keyword sets -> (display filter, explanation, matching issue types)
_QUERY_RULES: List[Tuple[Tuple[str, ...], str, str, Tuple[str, ...]]] = [
    (("retransmis", "perdida", "congestion"),
     "tcp.analysis.retransmission",
     "Paquetes TCP retransmitidos",
     ("tcp_retransmissions", "pmtud_blackhole")),
    (("dns",),
     "dns",
     "Todo el tráfico DNS",
     ("dns_unanswered", "dns_slow", "dns_servfail", "dns_nxdomain")),
    (("rst", "firewall", "rechaz", "bloque", "fallid"),
     "tcp.flags.reset == 1",
     "Paquetes TCP con el flag RST",
     ("tcp_syn_rst",)),
    (("vpn", "esp", "ike", "tunel", "ipsec"),
     "esp || isakmp",
     "Tráfico de túneles IPsec (ESP e IKE)",
     ("ike_no_response", "ike_handshake_incomplete", "esp_one_way")),
    (("tls", "ssl", "certific", "handshake"),
     "tls",
     "Tráfico TLS",
     ("tls_handshake_failure", "tls_alert", "tcp_slow_handshake")),
    (("fragment", "mtu", "mss"),
     "ip.flags.mf == 1 || ip.frag_offset > 0 || icmp.type == 3",
     "Fragmentos IP y avisos de MTU",
     ("ip_fragmentation_high", "ip_fragments_incomplete", "icmp_frag_needed", "mss_low")),
    (("arp", "duplicad", "spoof"),
     "arp",
     "Tráfico ARP",
     ("ip_duplicate", "arp_storm")),
    (("lent", "latencia", "tarda"),
     "tcp.analysis.ack_rtt > 0.2 || dns.time > 0.5",
     "Respuestas lentas (TCP y DNS)",
     ("tcp_slow_handshake", "dns_slow")),
]


def _normalize(text: str) -> str:
    decomposed = unicodedata.normalize("NFD", text.lower())
    return "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")


def demo_query(question: str, analysis: AnalysisResult, lang: str = "es") -> Dict[str, Any]:
    normalized = _normalize(question)
    display_filter, explanation, issue_types = "ip", "Todo el tráfico IP", ()
    for keywords, rule_filter, rule_explanation, rule_types in _QUERY_RULES:
        if any(keyword in normalized for keyword in keywords):
            display_filter, explanation, issue_types = (
                rule_filter, rule_explanation, rule_types,
            )
            break

    matched_issues = [i.id for i in analysis.issues if i.type in issue_types]
    matched_streams = sorted({
        int(i.evidence["stream_id"]) for i in analysis.issues
        if i.id in set(matched_issues) and isinstance(i.evidence.get("stream_id"), int)
    })
    return {
        "filter": display_filter,
        "explanation": "%s %s" % (explanation, _demo(lang)["suffix"]),
        "matched_tcp_streams": matched_streams,
        "matched_issue_ids": matched_issues,
        "model": "demo",
    }
