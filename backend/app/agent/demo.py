"""Deterministic stand-ins for the agent when no model is configured."""
from __future__ import annotations

from typing import Dict, Optional

from ..llm.demo import demo_diagnosis
from ..models import AnalysisResult, Issue
from .prompts import REPORT_HEADERS

DEMO_CHAT_REPLY: Dict[str, str] = {
    "es": (
        "_(modo demo)_ La investigación interactiva necesita una clave de Anthropic: define "
        "`ANTHROPIC_API_KEY` en el entorno del backend, pon `LLM_DEMO=0` y reinicia. Mientras "
        "tanto puedes usar los filtros de la lista de paquetes y la información experta."
    ),
    "en": (
        "_(demo mode)_ Interactive investigation needs an Anthropic key: set "
        "`ANTHROPIC_API_KEY` in the backend environment, set `LLM_DEMO=0` and restart. Meanwhile "
        "you can use the packet-list filters and the expert information."
    ),
}


def _is_v6(address: str) -> bool:
    return ":" in address


def evidence_filter(issue: Issue) -> Optional[str]:
    """Best display filter for an issue's packets, mirroring frontend/src/issueFilter.ts."""
    ev = issue.evidence
    stream = ev.get("stream_id", ev.get("tcp_stream"))
    if isinstance(stream, int):
        return "tcp.stream eq %d" % stream
    ids = ev.get("stream_ids")
    if isinstance(ids, list) and ids and all(isinstance(i, int) for i in ids):
        return "tcp.stream in {%s}" % " ".join(str(i) for i in ids)
    reporter = ev.get("reporter")
    if isinstance(reporter, str) and reporter and issue.type.startswith("icmp_"):
        family, proto = ("ipv6", "icmpv6") if _is_v6(reporter) else ("ip", "icmp")
        return "%s.src == %s && %s" % (family, reporter, proto)
    if issue.type.startswith("dns_"):
        name = ev.get("query_name")
        if isinstance(name, str) and name:
            return 'dns && _ws.col.info contains "%s"' % name.replace('"', '\\"')
        server = ev.get("server")
        if isinstance(server, str) and server:
            return "dns && %s.addr == %s" % ("ipv6" if _is_v6(server) else "ip", server)
    return None


def demo_investigation(analysis: AnalysisResult, lang: str) -> str:
    english = lang == "en"
    report = demo_diagnosis(analysis, lang)["diagnosis"]
    headers = REPORT_HEADERS["en" if english else "es"]
    lines = ["", "## %s" % headers[1], ""]
    if not analysis.issues:
        lines.append("- " + ("No issues were detected." if english else "No se detectaron problemas."))
    for issue in analysis.issues:
        title = (issue.title_en if english and issue.title_en else issue.title)
        mark = evidence_filter(issue)
        lines.append("- **%s** (%s)%s" % (title, issue.severity, " [[filter: %s]]" % mark if mark else ""))
    note = (
        "_(demo mode: this text is generated without AI from the detectors' findings)_"
        if english else
        "_(modo demo: este texto se genera sin IA a partir de lo que encontraron los detectores)_"
    )
    return report + "\n".join(lines) + "\n\n" + note
