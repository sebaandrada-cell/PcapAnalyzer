"""The six capture tools the agent can call.

Every tool receives a ``ToolContext`` with a decrypted copy of the session's
capture (valid for that call only) and returns a ``ToolResult`` whose
``content`` is JSON-serializable and bounded in size. Errors are returned, not
raised, so the model can react to them.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from .. import config
from ..sessions import Session
from . import stats_parse
from .fields import check_fields
from .masking import mask_sensitive
from .stream_metrics import StreamPacket, compute_stream_metrics, select_rows
from .tshark_run import ToolError, ToolTimeout, run_tshark, validate_filter

logger = logging.getLogger("pcapanalyzer.agent")


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
    except ToolTimeout:
        raise  # execute_tool reports timeouts distinctly
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
    except ToolTimeout:
        raise  # execute_tool reports timeouts distinctly
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


# ---- follow_stream -----------------------------------------------------------
_DIRECTIONS = ("both", "a_to_b", "b_to_a")


def follow_stream(
    ctx: ToolContext,
    stream_id: int,
    protocol: str = "tcp",
    direction: str = "both",
    max_bytes: int = 16384,
) -> ToolResult:
    """Reassembled text of one stream. Only when the user allowed content."""
    if not ctx.session.content_allowed:
        return _error(
            "content_disabled",
            hint="El usuario no ha activado «permitir contenido de los paquetes». Pídeselo si lo necesitas y explica que puede contener credenciales.",
        )
    if protocol not in ("tcp", "udp"):
        return _error("unsupported_protocol", protocols=["tcp", "udp"])
    if direction not in _DIRECTIONS:
        return _error("invalid_input", message="direction must be one of %s" % ", ".join(_DIRECTIONS))
    max_bytes = max(256, min(int(max_bytes), 65536))
    try:
        text = run_tshark(["-r", ctx.pcap_path, "-q", "-z", "follow,%s,ascii,%d" % (protocol, int(stream_id))])
    except ToolTimeout:
        raise  # execute_tool reports timeouts distinctly
    except ToolError as exc:
        return _error("tool_failed", message=str(exc))
    parsed = stats_parse.parse_follow(text)
    if "a" not in parsed["nodes"]:
        return _error("stream_not_found", stream_id=int(stream_id), protocol=protocol)
    pieces = []
    for chunk in parsed["chunks"]:
        if direction != "both" and chunk["direction"] != direction:
            continue
        pieces.append("--- %s ---\n%s" % (chunk["direction"], chunk["text"]))
    full = mask_sensitive("\n".join(pieces))
    data = full.encode("utf-8")
    truncated = len(data) > max_bytes
    if truncated:
        full = data[:max_bytes].decode("utf-8", "ignore")
    return ToolResult(
        content={
            "stream_id": int(stream_id), "protocol": protocol, "nodes": parsed["nodes"],
            "text": full, "bytes_returned": len(full.encode("utf-8")), "truncated": truncated,
        },
        truncated=truncated,
    )


# ---- protocol_reference ------------------------------------------------------
REFERENCE_TOPICS = ("tcp_analysis", "icmp", "tls", "dns", "dhcp", "vpn", "pmtud", "rtt_window")
_REFERENCE_DIR = os.path.join(os.path.dirname(__file__), "reference")


def protocol_reference(topic: str) -> ToolResult:
    """Curated notes so the model does not improvise protocol semantics."""
    if topic not in REFERENCE_TOPICS:
        return _error("unknown_topic", topics=list(REFERENCE_TOPICS))
    with open(os.path.join(_REFERENCE_DIR, topic + ".md"), "r", encoding="utf-8") as handle:
        return ToolResult(content={"topic": topic, "text": handle.read()})


# ---- definitions for the model and the dispatcher ----------------------------------
def _schema(properties: Dict[str, Any], required: List[str]) -> Dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


_TRUNCATION_NOTE = " Output is bounded; a truncated result says so and you can narrow the filter or page."

TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "capture_overview",
        "description": (
            "Everything the analysis engine already computed for this capture: summary, protocols, "
            "TCP/UDP conversations with per-stream counters (retransmissions, dup ACKs, RTT...), top "
            "talkers, tunnels, detected issues with evidence, Wireshark expert info, DNS/TLS/HTTP/DHCP "
            "tables, service response times and resolved names. Call it first, once." + _TRUNCATION_NOTE
        ),
        "strict": True,
        "input_schema": _schema({}, []),
    },
    {
        "name": "filter_packets",
        "description": (
            "Apply a real Wireshark display filter to the capture and return the requested fields per "
            "matching packet (frame.number is always included). Use it to verify a hypothesis or list "
            "specific packets; prefer statistics/stream_detail for aggregates. Payload fields "
            "(tcp.payload, data.data, http.file_data...) need the user's content switch." + _TRUNCATION_NOTE
        ),
        "strict": True,
        "input_schema": _schema({
            "display_filter": {"type": "string", "description": "Wireshark display filter, e.g. tcp.stream eq 7 && tcp.analysis.retransmission"},
            "fields": {"type": "array", "items": {"type": "string"}, "description": "tshark field names, e.g. frame.time_relative, ip.src, tcp.flags.str, _ws.col.info"},
            "limit": {"type": "integer", "description": "rows per page (1-200)"},
            "offset": {"type": "integer", "description": "rows to skip (paging)"},
        }, ["display_filter", "fields", "limit", "offset"]),
    },
    {
        "name": "stream_detail",
        "description": (
            "Packet-by-packet table of one TCP or UDP conversation (time, direction, flags, seq/ack, "
            "window, length, Wireshark analysis flags) plus computed metrics: handshake RTT, ACK RTT "
            "stats per direction, throughput, largest idle gap and who was expected to talk, "
            "retransmission/dup-ACK/zero-window events with frame numbers, and how it closed. Use it "
            "to explain why a conversation is slow or failed." + _TRUNCATION_NOTE
        ),
        "strict": True,
        "input_schema": _schema({
            "stream_id": {"type": "integer", "description": "tcp.stream or udp.stream id"},
            "protocol": {"type": "string", "enum": ["tcp", "udp"]},
        }, ["stream_id", "protocol"]),
    },
    {
        "name": "statistics",
        "description": (
            "Aggregates from tshark -z: conversations_tcp/udp/ip, endpoints_ip, io_per_interval "
            "(frames and bytes per interval_s seconds), protocol_hierarchy, expert (all expert info "
            "grouped by severity), dns (query/response/rcode counters) and service_response_time "
            "(protocol: icmp, icmpv6, smb, smb2, ldap, rpc, dcerpc, snmp, kerberos). An optional "
            "display_filter restricts the computation. Use it to find where traffic and symptoms "
            "concentrate before looking at packets." + _TRUNCATION_NOTE
        ),
        "strict": True,
        "input_schema": _schema({
            "kind": {"type": "string", "enum": list(STAT_KINDS)},
            "display_filter": {"type": ["string", "null"], "description": "optional Wireshark display filter"},
            "interval_s": {"type": "integer", "description": "bucket size for io_per_interval (1-3600)"},
            "protocol": {"type": ["string", "null"], "description": "for service_response_time only"},
        }, ["kind", "display_filter", "interval_s", "protocol"]),
    },
    {
        "name": "follow_stream",
        "description": (
            "Reassembled text of one TCP/UDP stream (like Wireshark's Follow Stream), credentials "
            "masked. Only works when the user enabled 'allow packet content' for this session; "
            "otherwise it returns content_disabled and you should ask the user to enable it, "
            "explaining that payload may contain secrets. Use it for application-layer problems "
            "(HTTP errors, SMB/SIP dialogs) once transport looks clean." + _TRUNCATION_NOTE
        ),
        "strict": True,
        "input_schema": _schema({
            "stream_id": {"type": "integer"},
            "protocol": {"type": "string", "enum": ["tcp", "udp"]},
            "direction": {"type": "string", "enum": ["both", "a_to_b", "b_to_a"]},
            "max_bytes": {"type": "integer", "description": "256-65536"},
        }, ["stream_id", "protocol", "direction", "max_bytes"]),
    },
    {
        "name": "protocol_reference",
        "description": (
            "Curated reference notes on protocol semantics: tcp_analysis (Wireshark flags), icmp, tls "
            "(handshake and alert codes), dns (rcodes and retry behaviour), dhcp, vpn (IKE/ESP/"
            "WireGuard/OpenVPN), pmtud (MTU black holes), rtt_window (reading RTT, window, "
            "throughput and gaps). Consult it instead of guessing what a code or flag means."
        ),
        "strict": True,
        "input_schema": _schema({"topic": {"type": "string", "enum": list(REFERENCE_TOPICS)}}, ["topic"]),
    },
]

_TOOL_SCHEMAS = {t["name"]: t["input_schema"] for t in TOOL_DEFINITIONS}
# Strict schemas list every key as required (the API demands it); the dispatcher
# still tolerates a missing optional key by applying these defaults.
_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "filter_packets": {"limit": 50, "offset": 0},
    "stream_detail": {"protocol": "tcp"},
    "statistics": {"display_filter": None, "interval_s": 1, "protocol": None},
    "follow_stream": {"protocol": "tcp", "direction": "both", "max_bytes": 16384},
}


def _validate_input(
    schema: Dict[str, Any], tool_input: Dict[str, Any], defaults: Dict[str, Any]
) -> Optional[str]:
    """Minimal JSON-schema check (types, enums, required) without extra dependencies."""
    if not isinstance(tool_input, dict):
        return "input must be an object"
    for name in schema.get("required", []):
        if name not in tool_input and name not in defaults:
            return "missing required field: %s" % name
    for name, value in tool_input.items():
        prop = schema["properties"].get(name)
        if prop is None:
            return "unknown field: %s" % name
        types = prop.get("type")
        types = types if isinstance(types, list) else [types]
        ok = False
        for kind in types:
            if kind == "null" and value is None:
                ok = True
            elif kind == "integer" and isinstance(value, int) and not isinstance(value, bool):
                ok = True
            elif kind == "string" and isinstance(value, str):
                ok = True
            elif kind == "array" and isinstance(value, list) and all(isinstance(v, str) for v in value):
                ok = True
        if not ok:
            return "field %s must be of type %s" % (name, "/".join(types))
        if "enum" in prop and value is not None and value not in prop["enum"]:
            return "field %s must be one of %s" % (name, ", ".join(prop["enum"]))
    return None


def _run_tool(ctx: ToolContext, name: str, i: Dict[str, Any]) -> ToolResult:
    if name == "capture_overview":
        return capture_overview(ctx)
    if name == "filter_packets":
        return filter_packets(ctx, i["display_filter"], i["fields"], i["limit"], i["offset"])
    if name == "stream_detail":
        return stream_detail(ctx, i["stream_id"], i["protocol"])
    if name == "statistics":
        return statistics(ctx, i["kind"], i.get("display_filter"), i["interval_s"], i.get("protocol"))
    if name == "follow_stream":
        return follow_stream(ctx, i["stream_id"], i["protocol"], i["direction"], i["max_bytes"])
    return protocol_reference(i["topic"])


def execute_tool(ctx: ToolContext, name: str, tool_input: Dict[str, Any]) -> ToolResult:
    """Validate, dispatch and never raise: errors come back as ToolResult(is_error=True)."""
    schema = _TOOL_SCHEMAS.get(name)
    if schema is None:
        return _error("unknown_tool", tools=list(_TOOL_SCHEMAS))
    defaults = _DEFAULTS.get(name, {})
    problem = _validate_input(schema, tool_input, defaults)
    if problem:
        return _error("invalid_input", message=problem)
    merged = dict(defaults)
    merged.update(tool_input)
    try:
        return _run_tool(ctx, name, merged)
    except ToolTimeout:
        return _error("timeout", message="La consulta a la captura superó el tiempo máximo (%ds)." % config.TOOL_TIMEOUT_S)
    except ToolError as exc:
        return _error("tool_failed", message=str(exc))
    except Exception:
        logger.exception("Tool %s failed", name)  # no payload is logged, only the traceback
        return _error("internal", message="La herramienta falló de forma inesperada.")


def serialize_result(result: ToolResult, max_bytes: Optional[int] = None) -> Tuple[str, bool]:
    """JSON text for the model, cut down (rows/text) until it fits in max_bytes."""
    max_bytes = max_bytes or config.TOOL_MAX_OUTPUT_BYTES
    content = result.content
    text = json.dumps(content, ensure_ascii=False, default=str)
    if len(text.encode("utf-8")) <= max_bytes:
        return text, result.truncated
    if not isinstance(content, dict):
        text = text[: max_bytes - 1]
        return json.dumps(text, ensure_ascii=False), True
    shrunk = dict(content)
    shrunk["truncated"] = True
    shrunk["note"] = "Output cut to fit the size limit; narrow the filter, request fewer fields or page."
    for _ in range(12):
        text = json.dumps(shrunk, ensure_ascii=False, default=str)
        if len(text.encode("utf-8")) <= max_bytes:
            return text, True
        rows = shrunk.get("rows")
        if isinstance(rows, list) and len(rows) > 1:
            shrunk["rows"] = rows[: max(1, len(rows) // 2)]
            shrunk["returned"] = len(shrunk["rows"])
            shrunk["has_more"] = True
        elif isinstance(shrunk.get("text"), str) and len(shrunk["text"]) > 64:
            shrunk["text"] = shrunk["text"][: len(shrunk["text"]) // 2]
        else:
            # Last resort: keep only the small scalar keys.
            shrunk = {k: v for k, v in shrunk.items() if not isinstance(v, (list, dict, str)) or k in ("error", "note")}
            shrunk["truncated"] = True
    return json.dumps(shrunk, ensure_ascii=False, default=str)[:max_bytes], True


def tool_result_block(tool_use_id: str, result: ToolResult) -> Dict[str, Any]:
    text, _ = serialize_result(result)
    return {"type": "tool_result", "tool_use_id": tool_use_id, "content": text, "is_error": result.is_error}
