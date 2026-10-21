"""PDF report generation (Fase 4).

Builds a client-deliverable Spanish report from an AnalysisResult (plus the
optional AI diagnosis) using reportlab — no system dependencies.
"""
from __future__ import annotations

import html
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

_SEVERITY_LABEL = {"critical": "CRÍTICO", "warning": "AVISO", "info": "INFO"}
_SEVERITY_COLOR = {
    "critical": colors.HexColor("#d03b3b"),
    "warning": colors.HexColor("#8a5b00"),
    "info": colors.HexColor("#1c5cab"),
}
_INK = colors.HexColor("#0b0b0b")
_MUTED = colors.HexColor("#52514e")
_GRID = colors.HexColor("#e1e0d9")
_HEADER_BG = colors.HexColor("#f0efec")

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


def build_report(analysis: AnalysisResult, diagnosis: Optional[str] = None) -> bytes:
    styles = _styles()
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title="Informe de análisis — %s" % analysis.file.name,
    )
    flow: list = []
    summary = analysis.summary

    flow.append(Paragraph("Informe de análisis de captura", styles["title"]))
    flow.append(Paragraph(
        "%s · %s · generado el %s · PcapAnalyzer %s"
        % (_esc(analysis.file.name), _fmt_bytes(analysis.file.size_bytes),
           datetime.now().strftime("%d/%m/%Y %H:%M"), __version__),
        styles["meta"],
    ))

    flow.append(Paragraph("Resumen", styles["h2"]))
    flow.append(_table([
        ["Paquetes", "Duración", "Bytes", "Conversaciones", "Problemas"],
        ["{:,}".format(summary.packets).replace(",", "."),
         _fmt_duration(summary.duration_seconds),
         _fmt_bytes(summary.bytes),
         str(summary.conversations),
         str(len(analysis.issues))],
    ], col_widths=[34 * mm, 34 * mm, 34 * mm, 34 * mm, 34 * mm]))

    if analysis.issues:
        flow.append(Paragraph("Problemas detectados", styles["h2"]))
        for issue in analysis.issues:
            severity = ParagraphStyle(
                "sev", parent=styles["body"],
                textColor=_SEVERITY_COLOR.get(issue.severity, _INK),
            )
            flow.append(Paragraph(
                "<b>[%s]</b> %s" % (_SEVERITY_LABEL.get(issue.severity, "?"),
                                    _esc(issue.title)),
                severity,
            ))
            flow.append(Paragraph(_esc(issue.detail), styles["detail"]))

    if diagnosis:
        flow.append(Paragraph("Diagnóstico asistido (IA)", styles["h2"]))
        flow.extend(_diagnosis_paragraphs(diagnosis, styles))

    flow.append(Paragraph("Distribución de protocolos", styles["h2"]))
    flow.append(_table(
        [["Protocolo", "Paquetes", "% paquetes", "Bytes"]]
        + [
            [proto.protocol.upper(), str(proto.packets),
             "%.1f%%" % proto.packet_pct, _fmt_bytes(proto.bytes)]
            for proto in analysis.protocols
        ],
        col_widths=[50 * mm, 30 * mm, 30 * mm, 30 * mm],
    ))

    flow.append(Paragraph("Top talkers", styles["h2"]))
    flow.append(_table(
        [["Host", "Paquetes", "Enviado", "Recibido", "Total"]]
        + [
            [_esc(talker.address), str(talker.packets),
             _fmt_bytes(talker.bytes_sent), _fmt_bytes(talker.bytes_received),
             _fmt_bytes(talker.bytes_total)]
            for talker in analysis.conversations.top_talkers
        ],
        col_widths=[50 * mm, 25 * mm, 30 * mm, 30 * mm, 30 * mm],
    ))

    if analysis.conversations.tcp:
        flow.append(Paragraph("Conversaciones TCP principales", styles["h2"]))
        rows = [["Origen", "Destino", "Paquetes", "Bytes", "Retrans."]]
        for conv in analysis.conversations.tcp[:MAX_REPORT_CONVERSATIONS]:
            rows.append([
                Paragraph(_esc("%s:%d" % (conv.src, conv.src_port)), styles["cell"]),
                Paragraph(_esc("%s:%d" % (conv.dst, conv.dst_port)), styles["cell"]),
                str(conv.packets), _fmt_bytes(conv.bytes),
                "%d (%.1f%%)" % (conv.retransmissions, conv.retransmission_pct),
            ])
        flow.append(_table(rows, col_widths=[42 * mm, 42 * mm, 22 * mm, 28 * mm, 30 * mm]))

    if analysis.tunnels:
        flow.append(Paragraph("Túneles VPN detectados", styles["h2"]))
        flow.append(_table(
            [["Tipo", "Peer A", "Peer B", "Paquetes", "Bytes"]]
            + [
                [tunnel.type.upper(), _esc(tunnel.peer_a), _esc(tunnel.peer_b),
                 str(tunnel.packets), _fmt_bytes(tunnel.bytes)]
                for tunnel in analysis.tunnels
            ],
            col_widths=[26 * mm, 42 * mm, 42 * mm, 25 * mm, 28 * mm],
        ))

    if analysis.service_response_times:
        flow.append(Paragraph("Tiempos de respuesta (SRT)", styles["h2"]))
        flow.append(_table(
            [["Protocolo", "Muestras", "Mín", "Media", "Máx"]]
            + [
                [srt.protocol, str(srt.samples), "%.1f ms" % srt.min_ms,
                 "%.1f ms" % srt.avg_ms, "%.1f ms" % srt.max_ms]
                for srt in analysis.service_response_times
            ],
            col_widths=[44 * mm, 26 * mm, 24 * mm, 24 * mm, 24 * mm],
        ))

    if analysis.tls_sessions:
        flow.append(Paragraph("Sesiones TLS", styles["h2"]))
        flow.append(_table(
            [["Cliente", "Servidor", "Versión", "Cipher", "Alerta"]]
            + [
                [_esc(tls.client), _esc(tls.server), tls.version or "—",
                 _esc(tls.cipher or "—"), _esc(tls.alert or "—")]
                for tls in analysis.tls_sessions
            ],
            col_widths=[30 * mm, 30 * mm, 22 * mm, 48 * mm, 32 * mm],
        ))

    flow.append(Paragraph(
        "Informe generado por PcapAnalyzer · la captura se analizó y se descartó, "
        "no se almacena.",
        styles["footer"],
    ))

    document.build(flow)
    return buffer.getvalue()
