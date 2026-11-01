"""The six capture tools the agent can call.

Every tool receives a ``ToolContext`` with a decrypted copy of the session's
capture (valid for that call only) and returns a ``ToolResult`` whose
``content`` is JSON-serializable and bounded in size. Errors are returned, not
raised, so the model can react to them.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from .. import config
from ..sessions import Session
from .fields import check_fields
from .tshark_run import ToolError, run_tshark, validate_filter


@dataclass
class ToolContext:
    session: Session
    pcap_path: str  # decrypted temp path, valid for the duration of one tool call
    tshark_path: str


@dataclass
class ToolResult:
    content: Any  # JSON-serializable
    is_error: bool = False
    truncated: bool = False


def _error(code: str, **extra: Any) -> ToolResult:
    content: Dict[str, Any] = {"error": code}
    content.update(extra)
    return ToolResult(content=content, is_error=True)


def _cap(rows: List[Any], key: str, truncated: List[str]) -> List[Any]:
    if len(rows) > config.TOOL_MAX_ROWS:
        truncated.append(key)
        return rows[: config.TOOL_MAX_ROWS]
    return rows


# ---- capture_overview --------------------------------------------------------
def capture_overview(ctx: ToolContext) -> ToolResult:
    """Everything the analysis engine already computed, without the LLM-context cuts."""
    a = ctx.session.analysis
    truncated: List[str] = []
    tcp = sorted(a.conversations.tcp, key=lambda c: c.bytes, reverse=True)
    udp = sorted(a.conversations.udp, key=lambda c: c.bytes, reverse=True)
    content = {
        "file": a.file.model_dump(),
        "summary": a.summary.model_dump(),
        "protocols": [p.model_dump() for p in a.protocols],
        "tcp_conversations": [c.model_dump() for c in _cap(tcp, "tcp_conversations", truncated)],
        "udp_conversations": [c.model_dump() for c in _cap(udp, "udp_conversations", truncated)],
        "top_talkers": [t.model_dump() for t in a.conversations.top_talkers],
        "tunnels": [t.model_dump() for t in a.tunnels],
        "issues": [
            i.model_dump(include={"id", "type", "severity", "title", "detail", "conversation", "evidence"})
            for i in _cap(list(a.issues), "issues", truncated)
        ],
        "expert_info": [e.model_dump() for e in _cap(list(a.expert_info), "expert_info", truncated)],
        "dns_queries": [d.model_dump() for d in _cap(list(a.dns_queries), "dns_queries", truncated)],
        "tls_sessions": [t.model_dump() for t in _cap(list(a.tls_sessions), "tls_sessions", truncated)],
        "http_requests": [h.model_dump() for h in _cap(list(a.http_requests), "http_requests", truncated)],
        "dhcp_leases": [d.model_dump() for d in _cap(list(a.dhcp_leases), "dhcp_leases", truncated)],
        "service_response_times": [s.model_dump() for s in a.service_response_times],
        "resolved_names": [r.model_dump() for r in _cap(list(a.resolved_names), "resolved_names", truncated)],
        "truncated_sections": truncated,
    }
    return ToolResult(content=content, truncated=bool(truncated))


# ---- filter_packets ----------------------------------------------------------
def filter_packets(
    ctx: ToolContext,
    display_filter: str,
    fields: List[str],
    limit: int = 50,
    offset: int = 0,
) -> ToolResult:
    """Apply a real Wireshark display filter and return the requested fields."""
    limit = max(1, min(int(limit), config.TOOL_MAX_ROWS))
    offset = max(0, int(offset))
    rejected = check_fields(fields, ctx.session.content_allowed)
    if rejected:
        return _error(
            "fields_not_allowed",
            fields=rejected,
            hint="Solo cabeceras y metadatos; el contenido requiere que el usuario active «permitir contenido».",
        )
    try:
        validate_filter(ctx.pcap_path, display_filter)
    except ToolError as exc:
        return _error("invalid_filter", message=str(exc))

    wanted = [f for f in fields if f != "frame.number"]
    args = [
        "-r", ctx.pcap_path, "-Y", display_filter, "-T", "fields",
        "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=|",
        "-e", "frame.number",
    ]
    for name in wanted:
        args += ["-e", name]
    # tshark's -c counts packets read, not matched, so paging happens here on a
    # size-bounded output: the last line may be cut and is dropped.
    out = run_tshark(args)
    lines = out.split("\n")
    cut = len(out.encode("utf-8")) >= config.TOOL_MAX_OUTPUT_BYTES * 4
    if cut and lines:
        lines = lines[:-1]
    lines = [ln for ln in lines if ln != ""]
    page = lines[offset: offset + limit]
    rows = []
    for line in page:
        parts = line.split("\t")
        row: Dict[str, Any] = {"frame": int(parts[0]) if parts[0].isdigit() else parts[0]}
        for name, value in zip(wanted, parts[1:]):
            row[name] = value.split("|") if "|" in value else value
        rows.append(row)
    return ToolResult(
        content={
            "filter": display_filter,
            "fields": ["frame.number"] + wanted,
            "rows": rows,
            "offset": offset,
            "returned": len(rows),
            "has_more": len(lines) > offset + limit or cut,
        },
        truncated=cut,
    )
