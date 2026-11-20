"""PDF report generation (Fase 4).

Builds a client-deliverable report (Spanish or English) from an AnalysisResult (plus the
optional AI diagnosis) using reportlab — no system dependencies.
"""
from __future__ import annotations

import html
import re
from datetime import datetime
from io import BytesIO
from typing import List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from . import __version__
from .models import AnalysisResult

_SEVERITY_LABEL = {
    "es": {"critical": "CRÍTICO", "warning": "AVISO", "info": "INFO"},
    "en": {"critical": "CRITICAL", "warning": "WARNING", "info": "INFO"},
}
_SEVERITY_COLOR = {
    "critical": colors.HexColor("#d03b3b"),
    "warning": colors.HexColor("#8a5b00"),
    "info": colors.HexColor("#1c5cab"),
}
_INK = colors.HexColor("#0b0b0b")
_MUTED = colors.HexColor("#52514e")
_GRID = colors.HexColor("#e1e0d9")
_HEADER_BG = colors.HexColor("#f0efec")

MAX_REPORT_EXPERT = 15
MAX_REPORT_CONVERSATIONS = 15


def _fmt_bytes(value: int) -> str:
    if value >= 1024 ** 3:
        return "%.1f GB" % (value / 1024 ** 3)
    if value >= 1024 ** 2:
        return "%.1f MB" % (value / 1024 ** 2)
    if value >= 1024:
        return "%.1f KB" % (value / 1024)
    return "%d B" % value


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return "%.1f s" % seconds
    minutes = int(seconds // 60)
    return "%dm %02ds" % (minutes, round(seconds % 60))


def _esc(value: object) -> str:
    """Capture-derived strings are untrusted; escape before Paragraph markup."""
    return html.escape(str(value))


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=base["Title"], fontSize=18,
                                textColor=_INK, spaceAfter=2 * mm, alignment=0),
        "meta": ParagraphStyle("meta", parent=base["Normal"], fontSize=9,
                               textColor=_MUTED, spaceAfter=6 * mm),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=13,
                             textColor=_INK, spaceBefore=6 * mm, spaceAfter=2 * mm),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontSize=11,
                             textColor=_INK, spaceBefore=4 * mm, spaceAfter=1.5 * mm),
        "body": ParagraphStyle("body", parent=base["Normal"], fontSize=9.5,
                               textColor=_INK, leading=13),
        "detail": ParagraphStyle("detail", parent=base["Normal"], fontSize=9,
                                 textColor=_MUTED, leading=12, spaceAfter=2.5 * mm),
        "cell": ParagraphStyle("cell", parent=base["Normal"], fontSize=8.5,
                               textColor=_INK, leading=11),
        "footer": ParagraphStyle("footer", parent=base["Normal"], fontSize=8,
                                 textColor=_MUTED, alignment=1, spaceBefore=8 * mm),
    }


def _table(data: List[List[object]], col_widths=None) -> Table:
    table = Table(data, colWidths=col_widths, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), _MUTED),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, _GRID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return table


_PKT_RE = re.compile(r"\[\[pkt:\s*(\d+)(?:\s*[-–]\s*(\d+))?\s*\]\]")
_FILTER_RE = re.compile(r"\[\[filter:\s*([^\]]+?)\s*\]\]")


def _inline_markup(raw: str, lang: str = "es") -> str:
    """Escape the model's text, then turn its light markup into Paragraph tags."""
    # Evidence marks are replaced on the ESCAPED text so a filter cannot inject tags.
    text = _esc(raw)
    text = _PKT_RE.sub(
        lambda m: ((_PKT_WORDS[lang][1] + " %s–%s") % (m.group(1), m.group(2))) if m.group(2)
        else (_PKT_WORDS[lang][0] + " %s") % m.group(1),
        text,
    )
    # Filters and `code` are kept verbatim: stash them so the bold pass cannot
    # interleave <b> with <font> (reportlab rejects crossed tags).
    spans: List[str] = []

    def stash(value: str) -> str:
        spans.append('<font face="Courier">%s</font>' % value)
        return "\x00%d\x00" % (len(spans) - 1)

    text = _FILTER_RE.sub(lambda m: stash(m.group(1)), text)
    text = re.sub(r"`([^`]+)`", lambda m: stash(m.group(1)), text)
    parts = text.split("**")
    text = "".join("<b>%s</b>" % part if i % 2 == 1 else part for i, part in enumerate(parts))
    return re.sub(r"\x00(\d+)\x00", lambda m: spans[int(m.group(1))], text)


_PKT_WORDS = {"es": ("paquete", "paquetes"), "en": ("packet", "packets")}


def _investigation_flowables(text: str, styles, lang: str = "es") -> List[object]:
    """The agent's report: headings, bullets, paragraphs, notes and evidence marks."""
    flow: List[object] = []
    paragraph: List[str] = []

    def flush() -> None:
        if paragraph:
            joined = " ".join(paragraph)
            note = re.match(r"^_\((.*)\)_$", joined) or re.match(r"^_(.*)_$", joined)
            body = "<i>%s</i>" % _inline_markup(note.group(1), lang) if note else _inline_markup(joined, lang)
            flow.append(Paragraph(body, styles["body"]))
            flow.append(Spacer(1, 2 * mm))
            paragraph.clear()

    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        bullet = re.match(r"^[-*•]\s+(.*)$", line)
        if heading:
            flush()
            style = styles["h3"] if len(heading.group(1)) > 2 else styles["h2"]
            flow.append(Paragraph(_inline_markup(heading.group(2), lang), style))
        elif bullet:
            flush()
            flow.append(Paragraph("• " + _inline_markup(bullet.group(1), lang), styles["body"]))
        elif line == "":
            flush()
        elif line.startswith("```"):
            continue
        else:
            paragraph.append(line)
    flush()
    return flow


def _diagnosis_paragraphs(diagnosis: str, styles) -> List[Paragraph]:
    """Render the AI diagnosis; supports the **bold** markers it uses."""
    flow = []
    for raw in diagnosis.split("\n\n"):
        text = _esc(raw.strip())
        if not text:
            continue
        parts = text.split("**")
        rendered = "".join(
            "<b>%s</b>" % part if index % 2 == 1 else part
            for index, part in enumerate(parts)
        )
        flow.append(Paragraph(rendered, styles["body"]))
        flow.append(Spacer(1, 2 * mm))
    return flow


def build_report(analysis: AnalysisResult, diagnosis: Optional[str] = None,
                 lang: str = "es") -> bytes:
    lang = "en" if lang == "en" else "es"
    en = lang == "en"

    def T(es_text: str, en_text: str) -> str:
        return en_text if en else es_text

    labels = _SEVERITY_LABEL[lang]
    styles = _styles()
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=T("Informe de análisis — %s", "Analysis report — %s") % analysis.file.name,
    )
    flow: list = []
    summary = analysis.summary

    flow.append(Paragraph(T("Informe de análisis de captura", "Capture analysis report"), styles["title"]))
    flow.append(Paragraph(
        T("%s · %s · generado el %s · PcapAnalyzer %s", "%s · %s · generated on %s · PcapAnalyzer %s")
        % (_esc(analysis.file.name), _fmt_bytes(analysis.file.size_bytes),
           datetime.now().strftime(T("%d/%m/%Y %H:%M", "%Y-%m-%d %H:%M")), __version__),
        styles["meta"],
    ))

    flow.append(Paragraph(T("Resumen", "Summary"), styles["h2"]))
    flow.append(_table([
        [T("Paquetes", "Packets"), T("Duración", "Duration"), "Bytes",
         T("Conversaciones", "Conversations"), T("Problemas", "Problems")],
        ["{:,}".format(summary.packets).replace(",", "," if en else "."),
         _fmt_duration(summary.duration_seconds),
         _fmt_bytes(summary.bytes),
         str(summary.conversations),
         str(len(analysis.issues))],
    ], col_widths=[34 * mm, 34 * mm, 34 * mm, 34 * mm, 34 * mm]))

    if analysis.capture_quality.notes:
        flow.append(Paragraph(T("Calidad de la captura", "Capture quality"), styles["h2"]))
        for note in analysis.capture_quality.notes:
            flow.append(Paragraph(
                "<b>[%s]</b> %s" % (labels.get(note.severity, "INFO"),
                                    _esc(note.title_en if en else note.title)),
                ParagraphStyle("quality", parent=styles["body"],
                               textColor=_SEVERITY_COLOR.get(note.severity, _INK)),
            ))
            flow.append(Paragraph(_esc(note.detail_en if en else note.detail), styles["detail"]))

    if analysis.issues:
        flow.append(Paragraph(T("Problemas detectados", "Detected problems"), styles["h2"]))
        for issue in analysis.issues:
            severity = ParagraphStyle(
                "sev", parent=styles["body"],
                textColor=_SEVERITY_COLOR.get(issue.severity, _INK),
            )
            flow.append(Paragraph(
                "<b>[%s]</b> %s" % (labels.get(issue.severity, "?"),
                                    _esc((issue.title_en or issue.title) if en else issue.title)),
                severity,
            ))
            flow.append(Paragraph(
                _esc((issue.detail_en or issue.detail) if en else issue.detail), styles["detail"]))

    if diagnosis and re.search(r"(?m)^#{1,6}\s", diagnosis):
        flow.append(Paragraph(T("Investigación asistida por IA", "AI-assisted investigation"), styles["h2"]))
        flow.extend(_investigation_flowables(diagnosis, styles, lang))
    elif diagnosis:
        flow.append(Paragraph(T("Diagnóstico asistido (IA)", "AI-assisted diagnosis"), styles["h2"]))
        flow.extend(_diagnosis_paragraphs(diagnosis, styles))

    flow.append(Paragraph(T("Distribución de protocolos", "Protocol distribution"), styles["h2"]))
    flow.append(_table(
        [[T("Protocolo", "Protocol"), T("Paquetes", "Packets"), T("% paquetes", "% packets"), "Bytes"]]
        + [
            [proto.protocol.upper(), str(proto.packets),
             "%.1f%%" % proto.packet_pct, _fmt_bytes(proto.bytes)]
            for proto in analysis.protocols
        ],
        col_widths=[50 * mm, 30 * mm, 30 * mm, 30 * mm],
    ))

    flow.append(Paragraph("Top talkers", styles["h2"]))
    flow.append(_table(
        [["Host", T("Paquetes", "Packets"), T("Enviado", "Sent"), T("Recibido", "Received"), "Total"]]
        + [
            [_esc(talker.address), str(talker.packets),
             _fmt_bytes(talker.bytes_sent), _fmt_bytes(talker.bytes_received),
             _fmt_bytes(talker.bytes_total)]
            for talker in analysis.conversations.top_talkers
        ],
        col_widths=[50 * mm, 25 * mm, 30 * mm, 30 * mm, 30 * mm],
    ))

    if analysis.conversations.tcp:
        flow.append(Paragraph(T("Conversaciones TCP principales", "Top TCP conversations"), styles["h2"]))
        rows = [[T("Origen", "Source"), T("Destino", "Destination"), T("Paquetes", "Packets"), "Bytes",
                 "Retrans.", T("ACK dup.", "Dup ACK"), T("RTT med.", "Avg RTT")]]
        for conv in analysis.conversations.tcp[:MAX_REPORT_CONVERSATIONS]:
            rows.append([
                Paragraph(_esc("%s:%d" % (conv.src, conv.src_port)), styles["cell"]),
                Paragraph(_esc("%s:%d" % (conv.dst, conv.dst_port)), styles["cell"]),
                str(conv.packets), _fmt_bytes(conv.bytes),
                "%d (%.1f%%)" % (conv.retransmissions, conv.retransmission_pct),
                str(conv.dup_acks),
                "%.1f ms" % conv.rtt_avg_ms if conv.rtt_avg_ms is not None else "—",
            ])
        flow.append(_table(
            rows, col_widths=[36 * mm, 36 * mm, 18 * mm, 22 * mm, 26 * mm, 16 * mm, 20 * mm]))

    expert = [e for e in analysis.expert_info if e.severity in ("error", "warning")]
    if expert:
        flow.append(Paragraph(T("Información experta de Wireshark (errores y avisos)",
                                "Wireshark expert info (errors and warnings)"), styles["h2"]))
        flow.append(_table(
            [[T("Severidad", "Severity"), T("Grupo", "Group"), T("Mensaje", "Message"), T("Veces", "Count")]]
            + [
                [e.severity.upper(), _esc(e.group),
                 Paragraph(_esc(e.summary), styles["cell"]), str(e.count)]
                for e in expert[:MAX_REPORT_EXPERT]
            ],
            col_widths=[24 * mm, 26 * mm, 100 * mm, 16 * mm],
        ))

    if analysis.tunnels:
        flow.append(Paragraph(T("Túneles VPN detectados", "Detected VPN tunnels"), styles["h2"]))
        flow.append(_table(
            [[T("Tipo", "Type"), "Peer A", "Peer B", T("Paquetes", "Packets"), "Bytes",
              T("Duración", "Duration"), T("Sin tráfico máx.", "Max idle"), "Handshakes"]]
            + [
                [tunnel.type.upper(), Paragraph(_esc(tunnel.peer_a), styles["cell"]),
                 Paragraph(_esc(tunnel.peer_b), styles["cell"]),
                 str(tunnel.packets), _fmt_bytes(tunnel.bytes),
                 _fmt_duration(tunnel.duration_s), _fmt_duration(tunnel.max_idle_s),
                 str(tunnel.handshakes)]
                for tunnel in analysis.tunnels
            ],
            col_widths=[20 * mm, 34 * mm, 34 * mm, 17 * mm, 19 * mm, 17 * mm, 19 * mm, 18 * mm],
        ))

    if analysis.service_response_times:
        flow.append(Paragraph(T("Tiempos de respuesta (SRT)", "Service response times (SRT)"), styles["h2"]))
        flow.append(_table(
            [[T("Protocolo", "Protocol"), T("Muestras", "Samples"), T("Mín", "Min"), T("Media", "Avg"), T("Máx", "Max")]]
            + [
                [srt.protocol, str(srt.samples), "%.1f ms" % srt.min_ms,
                 "%.1f ms" % srt.avg_ms, "%.1f ms" % srt.max_ms]
                for srt in analysis.service_response_times
            ],
            col_widths=[44 * mm, 26 * mm, 24 * mm, 24 * mm, 24 * mm],
        ))

    if analysis.tls_sessions:
        flow.append(Paragraph(T("Sesiones TLS", "TLS sessions"), styles["h2"]))
        flow.append(_table(
            [[T("Cliente", "Client"), T("Servidor", "Server"), T("Versión", "Version"), "Cipher", T("Alerta", "Alert")]]
            + [
                [_esc(tls.client), _esc(tls.server), tls.version or "—",
                 _esc(tls.cipher or "—"), _esc(tls.alert or "—")]
                for tls in analysis.tls_sessions
            ],
            col_widths=[30 * mm, 30 * mm, 22 * mm, 48 * mm, 32 * mm],
        ))

    flow.append(Paragraph(
        T("Informe generado por PcapAnalyzer · la captura se analiza en tu máquina y se "
          "conserva cifrada solo mientras dura la sesión de investigación; después se borra.",
          "Report generated by PcapAnalyzer · the capture is analysed on your machine and "
          "kept encrypted only while the investigation session lasts; then it is deleted."),
        styles["footer"],
    ))

    document.build(flow)
    return buffer.getvalue()
