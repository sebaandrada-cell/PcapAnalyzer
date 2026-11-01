"""The six capture tools the agent can call.

Every tool receives a ``ToolContext`` with a decrypted copy of the session's
capture (valid for that call only) and returns a ``ToolResult`` whose
``content`` is JSON-serializable and bounded in size. Errors are returned, not
raised, so the model can react to them.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .. import config
from ..sessions import Session
from . import stats_parse
from .fields import check_fields
from .stream_metrics import StreamPacket, compute_stream_metrics, select_rows
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


# ---- statistics --------------------------------------------------------------
STAT_KINDS = (
    "conversations_tcp", "conversations_udp", "conversations_ip", "endpoints_ip",
    "io_per_interval", "protocol_hierarchy", "expert", "dns", "service_response_time",
)
SRT_PROTOCOLS = ("icmp", "icmpv6", "smb", "smb2", "ldap", "rpc", "dcerpc", "snmp", "kerberos")
_STAT_ARGS = {
    "conversations_tcp": ("conv,tcp", stats_parse.parse_conversations),
    "conversations_udp": ("conv,udp", stats_parse.parse_conversations),
    "conversations_ip": ("conv,ip", stats_parse.parse_conversations),
    "endpoints_ip": ("endpoints,ip", stats_parse.parse_endpoints),
    "protocol_hierarchy": ("io,phs", stats_parse.parse_protocol_hierarchy),
    "expert": ("expert", stats_parse.parse_expert),
    "dns": ("dns,tree", stats_parse.parse_dns_tree),
}


def statistics(
    ctx: ToolContext,
    kind: str,
    display_filter: Optional[str] = None,
    interval_s: int = 1,
    protocol: Optional[str] = None,
) -> ToolResult:
    """Aggregates from ``tshark -z``: where is the traffic and where are the symptoms."""
    if kind not in STAT_KINDS:
        return _error("unknown_kind", kinds=list(STAT_KINDS))
    if display_filter:
        try:
            validate_filter(ctx.pcap_path, display_filter)
        except ToolError as exc:
            return _error("invalid_filter", message=str(exc))
    if kind == "io_per_interval":
        interval = max(1, min(int(interval_s), 3600))
        spec = "io,stat,%d" % interval + (",%s" % display_filter if display_filter else "")
        parser = stats_parse.parse_io_stat
    elif kind == "service_response_time":
        if protocol not in SRT_PROTOCOLS:
            return _error("unsupported_protocol", protocols=list(SRT_PROTOCOLS),
                          hint="DNS and HTTP response times are in capture_overview.service_response_times.")
        spec = "%s,srt" % protocol + (",%s" % display_filter if display_filter else "")
        parser = stats_parse.parse_srt
    else:
        base, parser = _STAT_ARGS[kind]
        spec = base + (",%s" % display_filter if display_filter else "")
    try:
        text = run_tshark(["-r", ctx.pcap_path, "-q", "-z", spec])
    except ToolError as exc:
        return _error("tool_failed", message=str(exc))
    rows = parser(text)
    truncated = isinstance(rows, list) and len(rows) > config.TOOL_MAX_ROWS
    if truncated:
        rows = rows[: config.TOOL_MAX_ROWS]
    return ToolResult(
        content={"kind": kind, "filter": display_filter, "rows": rows,
                 "returned": len(rows), "truncated": truncated},
        truncated=truncated,
    )


# ---- stream_detail -----------------------------------------------------------
_ANALYSIS_FIELDS = (
    ("tcp.analysis.retransmission", "retransmission"),
    ("tcp.analysis.fast_retransmission", "fast_retransmission"),
    ("tcp.analysis.spurious_retransmission", "spurious_retransmission"),
    ("tcp.analysis.duplicate_ack", "dup_ack"),
    ("tcp.analysis.out_of_order", "out_of_order"),
    ("tcp.analysis.lost_segment", "lost_segment"),
    ("tcp.analysis.zero_window", "zero_window"),
    ("tcp.analysis.window_full", "window_full"),
    ("tcp.analysis.zero_window_probe", "zero_window_probe"),
    ("tcp.analysis.window_update", "window_update"),
    ("tcp.analysis.keep_alive", "keep_alive"),
)
_STREAM_FIELDS = (
    "frame.number", "frame.time_relative", "frame.time_delta_displayed", "ip.src", "ipv6.src",
    "tcp.srcport", "udp.srcport", "ip.dst", "ipv6.dst", "tcp.dstport", "udp.dstport",
    "tcp.flags.str", "tcp.seq", "tcp.ack", "tcp.len", "udp.length", "tcp.window_size",
    "tcp.analysis.ack_rtt",
)
# tshark's tcp.flags.str letters (position is fixed, "·" means clear).
_FLAG_LETTERS = {"A": "ACK", "P": "PSH", "R": "RST", "S": "SYN", "F": "FIN", "U": "URG", "E": "ECE", "C": "CWR"}


def _opt_int(value: str) -> Optional[int]:
    return int(value) if value.isdigit() else None


def _opt_float(value: str) -> Optional[float]:
    try:
        return float(value) if value else None
    except ValueError:
        return None


def stream_detail(ctx: ToolContext, stream_id: int, protocol: str = "tcp") -> ToolResult:
    """Packet-by-packet view of one conversation plus computed metrics."""
    if protocol not in ("tcp", "udp"):
        return _error("unsupported_protocol", protocols=["tcp", "udp"])
    args = ["-r", ctx.pcap_path, "-Y", "%s.stream eq %d" % (protocol, int(stream_id)),
            "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    names = list(_STREAM_FIELDS) + [f for f, _ in _ANALYSIS_FIELDS]
    for name in names:
        args += ["-e", name]
    try:
        out = run_tshark(args)
    except ToolError as exc:
        return _error("tool_failed", message=str(exc))
    packets: List[StreamPacket] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        v = dict(zip(names, line.split("\t")))
        flag_str = v.get("tcp.flags.str", "")
        packets.append(StreamPacket(
            frame=int(v["frame.number"]),
            time=float(v["frame.time_relative"] or 0),
            src=v.get("ip.src") or v.get("ipv6.src") or "",
            sport=_opt_int(v.get("tcp.srcport") or v.get("udp.srcport") or "") or 0,
            dst=v.get("ip.dst") or v.get("ipv6.dst") or "",
            dport=_opt_int(v.get("tcp.dstport") or v.get("udp.dstport") or "") or 0,
            flags=[_FLAG_LETTERS[c] for c in flag_str if c in _FLAG_LETTERS],
            seq=_opt_int(v.get("tcp.seq", "")),
            ack=_opt_int(v.get("tcp.ack", "")),
            length=_opt_int(v.get("tcp.len") or v.get("udp.length") or "") or 0,
            window=_opt_int(v.get("tcp.window_size", "")),
            analysis=[name for field, name in _ANALYSIS_FIELDS if v.get(field)],
            ack_rtt=_opt_float(v.get("tcp.analysis.ack_rtt", "")),
            delta=_opt_float(v.get("frame.time_delta_displayed", "")) or 0.0,
        ))
    if not packets:
        return _error("stream_not_found", stream_id=int(stream_id), protocol=protocol)
    metrics = compute_stream_metrics(packets)
    a = metrics["endpoints"]["a"]
    rows, truncated = select_rows(packets, config.TOOL_MAX_ROWS)
    return ToolResult(
        content={
            "stream_id": int(stream_id),
            "protocol": protocol,
            "metrics": metrics,
            "rows": [
                {**p.__dict__, "direction": "a_to_b" if "%s:%s" % (p.src, p.sport) == a else "b_to_a"}
                for p in rows
            ],
            "rows_truncated": truncated,
        },
        truncated=truncated,
    )
