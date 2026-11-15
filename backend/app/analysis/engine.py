"""Single-pass analysis engine.

Consumes the packet stream produced by ``tshark -T ek`` exactly once,
accumulating summary counters, per-protocol stats, per-conversation state and
the raw material for issue detection. Detection rules themselves live in
``detectors.py``.
"""
from __future__ import annotations

import logging
import re
import time
from array import array
from bisect import bisect_left
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .. import __version__, config
from ..detectors import build_issues
from ..detectors.tls_alerts import _TLS_ALERT_NAMES
from .quality import apply_quality_caveats, build_capture_quality, duplicate_key, is_duplicate
from ..models import (
    AnalysisResult,
    Conversations,
    DhcpLeaseRow,
    DnsQueryRow,
    ExpertEntry,
    FileInfo,
    HttpRequestRow,
    Meta,
    PacketList,
    PacketRow,
    ProtocolStat,
    ResolvedName,
    ServiceResponseTime,
    Summary,
    TcpConversation,
    TimeSeriesPoint,
    TlsSession,
    TopTalker,
    Tunnel,
    UdpConversation,
)
from ..tshark import (
    ROW_FIELDS,
    field as fget,
    field_bool,
    field_present,
    iter_packets,
    tshark_version,
)


_log = logging.getLogger("uvicorn.error")


@dataclass
class ConvState:
    stream_id: int
    src: str
    src_port: int
    dst: str
    dst_port: int
    packets: int = 0
    bytes: int = 0
    bytes_fwd: int = 0
    bytes_rev: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    # TCP-only signals
    retransmissions: int = 0
    zero_window_events: int = 0
    syn_ts: Optional[float] = None
    synack_ts: Optional[float] = None
    synack_seen: bool = False
    ack_seen: bool = False  # some segment acknowledged the peer (see analysis/quality.py)
    # Per direction: first ACK number seen, SYN sent, and whether that side
    # acknowledged peer data that never appears in the capture.
    fwd_first_ack: Optional[int] = None
    rev_first_ack: Optional[int] = None
    fwd_syn_sent: bool = False
    rev_syn_sent: bool = False
    fwd_acks_unseen: bool = False
    rev_acks_unseen: bool = False
    rst_ts: Optional[float] = None
    mss_client: Optional[int] = None
    mss_server: Optional[int] = None
    full_size_retrans: int = 0  # retransmissions of MSS-sized segments (PMTUD)
    # Wireshark "SEQ/ACK analysis" counters
    dup_acks: int = 0
    out_of_order: int = 0
    lost_segments: int = 0
    window_full: int = 0
    resets_midstream: int = 0  # RST after the handshake had completed
    rtt_sum: float = 0.0  # tcp.analysis.ack_rtt samples (seconds)
    rtt_samples: int = 0
    rtt_max: float = 0.0


@dataclass
class DnsQuery:
    ts: float
    name: str
    server: str
    client: str


@dataclass
class DnsExchange:
    name: str
    server: str
    client: str
    latency_s: float
    status: str = "ok"


@dataclass
class TlsAlert:
    ts: float
    src: str
    dst: str
    level: int
    desc: int
    stream_id: Optional[int]


@dataclass
class DnsError:
    rcode: int  # 2 = SERVFAIL, 3 = NXDOMAIN
    name: str
    server: str
    client: str


@dataclass
class IcmpFragEvent:
    """ICMP 'Fragmentation Needed' / ICMPv6 'Packet Too Big'."""

    ts: float
    src: str  # router reporting the bottleneck
    dst: str  # sender of the too-big packet
    mtu: int


@dataclass
class IcmpErrorGroup:
    """ICMP/ICMPv6 error messages from one reporter, grouped by type and code."""

    family: int  # 4 or 6
    reporter: str
    icmp_type: int
    code: int
    count: int = 0
    first_ts: float = 0.0
    targets: List[str] = field(default_factory=list)  # destinations that failed
    victims: List[str] = field(default_factory=list)  # hosts that got the error


@dataclass
class ExpertAgg:
    """Wireshark "Expert Information" line: same severity/group/text, counted."""

    severity: str
    group: str
    summary: str
    count: int = 0
    first_packet: int = 0


@dataclass
class FragGroup:
    """Fragments of one IPv4 datagram, keyed by (src, dst, ip.id, proto)."""

    packets: int = 0
    bytes: int = 0
    has_first: bool = False
    has_last: bool = False  # saw the MF=0, offset>0 fragment


@dataclass
class TunnelState:
    type: str  # esp | ike | wireguard | openvpn | gre | l2tp
    peer_a: str
    peer_b: str
    packets_a2b: int = 0
    packets_b2a: int = 0
    bytes: int = 0

_TUNNEL_TOKENS = [
    ("esp", "esp"),
    ("isakmp", "ike"),
    ("wireguard", "wireguard"),
    ("openvpn", "openvpn"),
    ("gre", "gre"),
    ("l2tp", "l2tp"),
]

_TLS_VERSIONS = {
    "0x0300": "SSL 3.0",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
}

# Common cipher suites; unknown values fall back to their hex id.
_TLS_CIPHERS = {
    "0x002f": "RSA_AES_128_CBC_SHA",
    "0x0035": "RSA_AES_256_CBC_SHA",
    "0x009c": "RSA_AES_128_GCM_SHA256",
    "0x1301": "TLS_AES_128_GCM_SHA256",
    "0x1302": "TLS_AES_256_GCM_SHA384",
    "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
    "0xc02b": "ECDHE_ECDSA_AES_128_GCM_SHA256",
    "0xc02f": "ECDHE_RSA_AES_128_GCM_SHA256",
    "0xc030": "ECDHE_RSA_AES_256_GCM_SHA384",
}


@dataclass
class TlsSessionState:
    stream_id: int
    client: str
    server: str
    version: Optional[str] = None
    cipher: Optional[str] = None
    sni: Optional[str] = None
    alert: Optional[str] = None
    negotiated: Optional[str] = None  # raw version of the ServerHello (detectors/tls_legacy.py)


@dataclass
class DhcpTxnState:
    """One DHCP transaction (all messages sharing a BOOTP xid)."""

    client_mac: str
    hostname: Optional[str] = None
    ip: Optional[str] = None
    server: Optional[str] = None
    first_ts: float = 0.0
    ack_ts: Optional[float] = None
    # message types seen (1 discover, 2 offer, 3 request, 4 decline, 5 ack,
    # 6 nak, 7 release, 8 inform)
    types: set = field(default_factory=set)
    requests: int = 0  # DISCOVER + REQUEST messages (retries included)


@dataclass
class CaptureState:
    """Everything accumulated during the single pass over the capture."""

    packets: int = 0
    bytes: int = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    proto_packets: Dict[str, int] = field(default_factory=dict)
    proto_bytes: Dict[str, int] = field(default_factory=dict)
    # per-second buckets: second offset -> [packets, bytes, retransmissions]
    buckets: Dict[int, List[int]] = field(default_factory=dict)
    tcp_convs: Dict[int, ConvState] = field(default_factory=dict)
    udp_convs: Dict[int, ConvState] = field(default_factory=dict)
    talkers: Dict[str, Dict[str, int]] = field(default_factory=dict)
    # DNS IDs can legitimately be reused before an earlier transaction has
    # completed, so each key needs a FIFO rather than a single query.
    dns_pending: Dict[Tuple[str, str, str], List[DnsQuery]] = field(default_factory=dict)
    dns_answered: List[DnsExchange] = field(default_factory=list)
    dns_errors: List[DnsError] = field(default_factory=list)
    tls_alerts: List[TlsAlert] = field(default_factory=list)
    icmp_frag_events: List[IcmpFragEvent] = field(default_factory=list)
    frag_packets: int = 0
    frag_groups: Dict[Tuple[str, str, str, str], FragGroup] = field(default_factory=dict)
    tunnels: Dict[Tuple[str, Tuple[str, str]], TunnelState] = field(default_factory=dict)
    # ARP: IP address -> {MAC -> announcement count} (duplicate IP detection)
    arp_map: Dict[str, Dict[str, int]] = field(default_factory=dict)
    # Wireshark-style packet list (first PACKET_LIST_MAX packets)
    packet_rows: List[PacketRow] = field(default_factory=list)
    # HTTP requests + per-stream queue of requests awaiting their response
    http_requests: List[HttpRequestRow] = field(default_factory=list)
    http_pending: Dict[int, List[HttpRequestRow]] = field(default_factory=dict)
    # Service response times (Wireshark SRT): per-protocol latency samples (seconds)
    http_response_times: List[float] = field(default_factory=list)
    # TLS sessions keyed by tcp.stream
    tls_sessions: Dict[int, TlsSessionState] = field(default_factory=dict)
    # DHCP transactions keyed by BOOTP xid (+ client MAC)
    dhcp_txns: Dict[Tuple[str, str], DhcpTxnState] = field(default_factory=dict)
    # ICMP errors (unreachable, TTL exceeded) grouped by reporter/type/code
    icmp_errors: Dict[Tuple[int, str, int, int], IcmpErrorGroup] = field(default_factory=dict)
    # Wireshark expert info, aggregated; entries kept per severity band
    expert: Dict[Tuple[str, str, str], ExpertAgg] = field(default_factory=dict)
    expert_band_sizes: Dict[str, int] = field(default_factory=dict)
    # IP -> name learned from DNS answers (Wireshark "Resolved Addresses")
    resolved: Dict[str, str] = field(default_factory=dict)
    truncated_sections: set = field(default_factory=set)
    # Packets whose fields could not be parsed (malformed capture); never fatal.
    skipped_packets: int = 0
    # Capture quality (analysis/quality.py)
    duplicate_frames: int = 0
    truncated_frames: int = 0
    recent_frames: "OrderedDict[tuple, float]" = field(default_factory=OrderedDict)
    # Frame numbers of the duplicates, ascending (see query_packets).
    duplicate_numbers: array = field(default_factory=lambda: array("I"))
    # TCP streams where a non-ACK frame was duplicated: the capture copies there.
    mirrored_streams: set = field(default_factory=set)
    dns_queries_seen: int = 0


def _sanitize(value: str, max_len: int = 255) -> str:
    """Strings coming from the capture are untrusted; strip control chars."""
    return "".join(ch if ch.isprintable() else "?" for ch in value)[:max_len]


def _protocol_label(layers_chain: List[str]) -> str:
    """Reduce a frame.protocols chain to its most specific useful layer."""
    # ICMP errors and tunnels quote/carry inner packets; label them by the
    # carrier, not by the (possibly partial) innermost layer.
    for carrier in ("icmp", "icmpv6"):
        if carrier in layers_chain:
            return carrier
    layers = list(layers_chain)
    while layers and layers[-1] in ("data", "data-text-lines", "ethertype"):
        layers.pop()
    return layers[-1] if layers else "unknown"


def _track_acks(conv: "ConvState", forward: bool, syn: bool, ack: bool,
                ack_number: Optional[int]) -> None:
    """Note when a side acknowledges peer data (one-way capture detection)."""
    side = "fwd" if forward else "rev"
    if syn and not ack:
        setattr(conv, side + "_syn_sent", True)
        return
    if not ack or ack_number is None:
        return
    first = getattr(conv, side + "_first_ack")
    if first is None:
        setattr(conv, side + "_first_ack", ack_number)
        # An ACK after our own SYN means the peer's SYN-ACK existed.
        if getattr(conv, side + "_syn_sent") and not syn:
            setattr(conv, side + "_acks_unseen", True)
    elif ack_number > first:
        setattr(conv, side + "_acks_unseen", True)


def _update_conversation(
    convs: Dict[int, ConvState],
    stream_id: int,
    src: str,
    src_port: int,
    dst: str,
    dst_port: int,
    ts: float,
    length: int,
) -> ConvState:
    conv = convs.get(stream_id)
    if conv is None:
        conv = ConvState(stream_id, src, src_port, dst, dst_port,
                         first_ts=ts, last_ts=ts)
        convs[stream_id] = conv
    conv.packets += 1
    conv.bytes += length
    conv.last_ts = ts
    if src == conv.src and src_port == conv.src_port:
        conv.bytes_fwd += length
    else:
        conv.bytes_rev += length
    return conv


# Wireshark TCP-analysis flags surfaced per packet: (tshark field, short name).
_ANALYSIS_FLAGS = [
    ("tcp.analysis.retransmission", "retransmission"),
    ("tcp.analysis.fast_retransmission", "fast_retransmission"),
    ("tcp.analysis.spurious_retransmission", "spurious_retransmission"),
    ("tcp.analysis.duplicate_ack", "dup_ack"),
    ("tcp.analysis.out_of_order", "out_of_order"),
    ("tcp.analysis.lost_segment", "lost_segment"),
    ("tcp.analysis.window_full", "window_full"),
    ("tcp.analysis.zero_window", "zero_window"),
    ("tcp.analysis.zero_window_probe", "zero_window_probe"),
    ("tcp.analysis.window_update", "window_update"),
    ("tcp.analysis.keep_alive", "keep_alive"),
]
_TCP_FLAG_NAMES = [
    ("tcp.flags.syn", "SYN"),
    ("tcp.flags.fin", "FIN"),
    ("tcp.flags.reset", "RST"),
    ("tcp.flags.push", "PSH"),
    ("tcp.flags.ack", "ACK"),
]
# _ws.expert.severity / _ws.expert.group values (tshark -G values)
_EXPERT_SEVERITY = {1048576: "chat", 2097152: "chat", 4194304: "note",
                    6291456: "warning", 8388608: "error"}
_EXPERT_RANK = {"chat": 0, "note": 1, "warning": 2, "error": 3}
_EXPERT_GROUPS = {
    16777216: "Checksum", 33554432: "Sequence", 50331648: "Response",
    67108864: "Request", 83886080: "Undecoded", 100663296: "Reassemble",
    117440512: "Malformed", 134217728: "Debug", 150994944: "Protocol",
    167772160: "Security", 184549376: "Comment", 201326592: "Decryption",
    218103808: "Assumption", 234881024: "Deprecated", 251658240: "Receive",
    268435456: "Interface", 285212672: "Dissector bug",
}


_EXPERT_COUNTER = re.compile(r"\(#\d+\)")


_EPOCH_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)")


def _epoch(value: Optional[str], fallback: float) -> float:
    """Parse frame.time_epoch tolerantly.

    A record whose sub-second field is out of range makes tshark print
    ``"12.(1000000000 nanoseconds)"``; keep the leading number instead of
    aborting the whole analysis.
    """
    match = _EPOCH_RE.match(value or "")
    return float(match.group(1)) if match else fallback


def _opt_int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _expert_messages(layers: dict) -> List[Tuple[str, str, str]]:
    """(severity, group, text) for every expert-info entry on this packet."""
    messages = _as_list(layers.get("_ws_expert_message"))
    if not messages:
        return []
    severities = _as_list(layers.get("_ws_expert_severity"))
    groups = _as_list(layers.get("_ws_expert_group"))
    out = []
    for index, text in enumerate(messages):
        sev = _EXPERT_SEVERITY.get(_opt_int(severities[index]) if index < len(severities) else None, "chat")
        grp = _EXPERT_GROUPS.get(_opt_int(groups[index]) if index < len(groups) else None, "Other")
        # "Duplicate ACK (#1)", "(#2)"... would split one finding into many lines.
        out.append((sev, grp, _EXPERT_COUNTER.sub("(#n)", _sanitize(str(text), 200))))
    return out


def _record_expert(state: "CaptureState", number: int, messages) -> None:
    for severity, group, text in messages:
        key = (severity, group, text)
        entry = state.expert.get(key)
        if entry is None:
            # Errors/warnings and chat/notes have separate budgets so a flood of
            # per-port "connection established" lines cannot hide a real error.
            band = "high" if severity in ("error", "warning") else "low"
            if state.expert_band_sizes.get(band, 0) >= config.MAX_EXPERT_ENTRIES:
                state.truncated_sections.add("expert_info")
                continue
            state.expert_band_sizes[band] = state.expert_band_sizes.get(band, 0) + 1
            entry = state.expert[key] = ExpertAgg(severity, group, text, 0, number)
        entry.count += 1


def _packet_extras(layers: dict, chain: List[str], expert_messages,
                   duplicate: bool = False) -> dict:
    """Optional PacketRow fields (ports, TCP flags/seq/ack/window, flags...)."""
    extras: dict = {}
    quoted = "icmp" in chain or "icmpv6" in chain  # inner packet belongs to the error
    ttl = _opt_int(fget(layers, "ip.ttl"))
    if ttl is not None:
        extras["ttl"] = ttl
    if not quoted:
        if fget(layers, "tcp.srcport") is not None:
            extras["sport"] = _opt_int(fget(layers, "tcp.srcport"))
            extras["dport"] = _opt_int(fget(layers, "tcp.dstport"))
            extras["tcp_flags"] = [name for fld, name in _TCP_FLAG_NAMES if field_bool(layers, fld)]
            extras["seq"] = _opt_int(fget(layers, "tcp.seq"))
            extras["ack"] = _opt_int(fget(layers, "tcp.ack"))
            extras["win"] = _opt_int(fget(layers, "tcp.window_size"))
            extras["payload"] = _opt_int(fget(layers, "tcp.len"))
            extras["analysis"] = [name for fld, name in _ANALYSIS_FLAGS if field_present(layers, fld)]
            rtt = fget(layers, "tcp.analysis.ack_rtt")
            if rtt is not None:
                try:
                    extras["rtt_ms"] = round(float(rtt) * 1000, 3)
                except ValueError:
                    pass
        elif fget(layers, "udp.srcport") is not None:
            extras["sport"] = _opt_int(fget(layers, "udp.srcport"))
            extras["dport"] = _opt_int(fget(layers, "udp.dstport"))
    if duplicate:
        # Wireshark's flags on a copied frame describe the copy, not the network.
        extras["analysis"] = ["duplicate_frame"]
        extras.pop("rtt_ms", None)
    if expert_messages:
        severity, _group, text = max(expert_messages, key=lambda m: _EXPERT_RANK[m[0]])
        extras["expert"] = severity
        extras["expert_message"] = text[:120]
    return extras


def build_packet_row(layers: dict, chain: List[str], ts: float, first_ts: float,
                     length: int, src: Optional[str], dst: Optional[str],
                     expert_messages, duplicate: bool) -> PacketRow:
    """One row of the packet list (shared by the analysis and packet queries)."""
    # tcp.stream tags the row so the flow graph can filter one conversation
    # precisely (ICMP errors quote an inner packet — don't tag those).
    raw_stream = fget(layers, "tcp.stream")
    pkt_stream = (
        int(raw_stream)
        if raw_stream is not None and "icmp" not in chain and "icmpv6" not in chain
        else None
    )
    return PacketRow(
        number=int(fget(layers, "frame.number", "0") or 0),
        time=round(max(0.0, ts - first_ts), 6),
        src=_sanitize(src or "—", 64),
        dst=_sanitize(dst or "—", 64),
        protocol=_sanitize(fget(layers, "_ws.col.protocol", "?") or "?", 24),
        length=length,
        info=_sanitize(fget(layers, "_ws.col.info", "") or "", 200),
        stream=pkt_stream,
        **_packet_extras(layers, chain, expert_messages, duplicate),
    )


def query_packets(
    tshark_path: str,
    pcap_path: str,
    analysis: AnalysisResult,
    display_filter: str,
    limit: int,
    offset: int = 0,
) -> Tuple[List[PacketRow], bool, int]:
    """Rows matching a real Wireshark display filter, over the whole capture.

    Returns ``(rows, has_more, matched)``; ``matched`` is the total number of
    matching packets when ``has_more`` is false. tshark is stopped as soon as the page is
    full, so a filter matching millions of packets costs one page.
    """
    first_ts = analysis.summary.start_time_epoch or 0.0
    duplicates = analysis._duplicate_frames
    rows: List[PacketRow] = []
    has_more = False
    seen = 0
    packets = iter_packets(
        tshark_path, pcap_path, timeout_s=config.PACKET_QUERY_TIMEOUT_S,
        display_filter=display_filter.strip() or None, fields=ROW_FIELDS,
    )
    try:
        for layers in packets:
            seen += 1
            if seen <= offset:
                continue
            if len(rows) >= limit:
                has_more = True
                break
            try:
                number = int(fget(layers, "frame.number", "0") or 0)
                ts = _epoch(fget(layers, "frame.time_epoch"), first_ts)
                chain = [t for t in (fget(layers, "frame.protocols", "") or "").split(":") if t]
                duplicate = False
                if duplicates is not None and len(duplicates):
                    index = bisect_left(duplicates, number)
                    duplicate = index < len(duplicates) and duplicates[index] == number
                rows.append(build_packet_row(
                    layers, chain, ts, first_ts, int(fget(layers, "frame.len", "0") or 0),
                    fget(layers, "ip.src") or fget(layers, "ipv6.src"),
                    fget(layers, "ip.dst") or fget(layers, "ipv6.dst"),
                    [] if duplicate else _expert_messages(layers), duplicate,
                ))
            except (ValueError, TypeError):
                continue  # same tolerance as the analysis: skip a malformed packet
    finally:
        packets.close()
    return rows, has_more, seen


def _consume_packet(state: CaptureState, layers: dict) -> None:
    ts = _epoch(fget(layers, "frame.time_epoch"), state.last_ts or 0.0)
    length = int(fget(layers, "frame.len", "0") or 0)

    state.packets += 1
    state.bytes += length
    if state.first_ts is None:
        state.first_ts = ts
    state.last_ts = ts

    chain = [token for token in (fget(layers, "frame.protocols", "") or "").split(":") if token]
    label = _protocol_label(chain)
    state.proto_packets[label] = state.proto_packets.get(label, 0) + 1
    state.proto_bytes[label] = state.proto_bytes.get(label, 0) + length

    src = fget(layers, "ip.src") or fget(layers, "ipv6.src")
    dst = fget(layers, "ip.dst") or fget(layers, "ipv6.dst")

    cap_len = _opt_int(fget(layers, "frame.cap_len"))
    if cap_len is not None and cap_len < length:
        state.truncated_frames += 1

    # A copy of a frame seen a moment ago (port mirror, several interfaces) is
    # kept in the totals and the packet list but left out of every analysis:
    # Wireshark flags it as a retransmission / duplicate ACK, which it is not.
    dup_key, weak = duplicate_key(layers, chain, src, dst)
    stream_tag = fget(layers, "tcp.stream")
    if weak and stream_tag not in state.mirrored_streams:
        duplicate = False  # could be a genuine duplicate ACK
    else:
        duplicate = is_duplicate(state.recent_frames, dup_key, ts)
        if duplicate and not weak and stream_tag is not None \
                and len(state.mirrored_streams) < config.MAX_CONVERSATIONS:
            state.mirrored_streams.add(stream_tag)
    if duplicate:
        state.duplicate_frames += 1
        if len(state.duplicate_numbers) < config.MAX_DUPLICATE_FRAMES_TRACKED:
            state.duplicate_numbers.append(int(fget(layers, "frame.number", "0") or 0))

    expert_messages = [] if duplicate else _expert_messages(layers)
    if expert_messages:
        _record_expert(state, int(fget(layers, "frame.number", "0") or 0), expert_messages)

    if len(state.packet_rows) < config.PACKET_LIST_MAX:
        state.packet_rows.append(build_packet_row(
            layers, chain, ts, state.first_ts, length, src, dst, expert_messages, duplicate))

    if src and dst:
        for addr, sent in ((src, True), (dst, False)):
            if addr not in state.talkers and len(state.talkers) >= config.MAX_TRACKED_TALKERS:
                state.truncated_sections.add("talkers")
                continue
            talker = state.talkers.setdefault(
                addr, {"packets": 0, "bytes_sent": 0, "bytes_received": 0}
            )
            talker["packets"] += 1
            talker["bytes_sent" if sent else "bytes_received"] += length

    bucket_key = int(ts - state.first_ts) if ts >= state.first_ts else 0
    bucket = state.buckets.get(bucket_key)
    if bucket is None:
        if len(state.buckets) < config.MAX_TIME_SERIES_BUCKETS:
            bucket = state.buckets[bucket_key] = [0, 0, 0]
        else:
            state.truncated_sections.add("time_series")
    if bucket is not None:
        bucket[0] += 1
        bucket[1] += length

    if duplicate:
        return

    tcp_stream = fget(layers, "tcp.stream")
    udp_stream = fget(layers, "udp.stream")

    # ICMP errors quote the offending packet; its embedded TCP/UDP/DNS fields
    # must not be accounted as real conversations or queries.
    is_icmp_error = "icmp" in chain or "icmpv6" in chain
    if is_icmp_error:
        tcp_stream = udp_stream = None

    if tcp_stream is not None and src and dst:
        stream_key = int(tcp_stream)
        if (
            stream_key not in state.tcp_convs
            and len(state.tcp_convs) + len(state.udp_convs) >= config.MAX_CONVERSATIONS
        ):
            state.truncated_sections.add("conversations")
            tcp_stream = None
    if tcp_stream is not None and src and dst:
        conv = _update_conversation(
            state.tcp_convs, int(tcp_stream), src,
            int(fget(layers, "tcp.srcport", "0") or 0), dst,
            int(fget(layers, "tcp.dstport", "0") or 0), ts, length,
        )
        syn = field_bool(layers, "tcp.flags.syn")
        ack = field_bool(layers, "tcp.flags.ack")
        if ack:
            conv.ack_seen = True
        forward = src == conv.src and int(fget(layers, "tcp.srcport", "0") or 0) == conv.src_port
        _track_acks(conv, forward, syn, ack, _opt_int(fget(layers, "tcp.ack")))
        mss = fget(layers, "tcp.options.mss_val")
        if syn and not ack:
            if conv.syn_ts is None:
                conv.syn_ts = ts
            if mss is not None:
                conv.mss_client = int(mss)
        if syn and ack:
            conv.synack_seen = True
            if conv.synack_ts is None:
                conv.synack_ts = ts
            if mss is not None:
                conv.mss_server = int(mss)
        if field_bool(layers, "tcp.flags.reset") and conv.rst_ts is None:
            conv.rst_ts = ts
        if (
            field_present(layers, "tcp.analysis.retransmission")
            or field_present(layers, "tcp.analysis.fast_retransmission")
            or field_present(layers, "tcp.analysis.spurious_retransmission")
        ):
            conv.retransmissions += 1
            if bucket is not None:
                bucket[2] += 1
            sender_mss = conv.mss_client if src == conv.src else conv.mss_server
            seg_len = int(fget(layers, "tcp.len", "0") or 0)
            if sender_mss and seg_len >= sender_mss:
                conv.full_size_retrans += 1
        if field_present(layers, "tcp.analysis.zero_window"):
            conv.zero_window_events += 1
        if field_present(layers, "tcp.analysis.duplicate_ack"):
            conv.dup_acks += 1
        if field_present(layers, "tcp.analysis.out_of_order"):
            conv.out_of_order += 1
        if field_present(layers, "tcp.analysis.lost_segment"):
            conv.lost_segments += 1
        if field_present(layers, "tcp.analysis.window_full"):
            conv.window_full += 1
        # RST after the handshake completed (SYN->RST without SYN-ACK is the
        # separate firewall/closed-port pattern, so it is not counted here).
        if field_bool(layers, "tcp.flags.reset") and conv.synack_seen:
            conv.resets_midstream = 1
        ack_rtt = fget(layers, "tcp.analysis.ack_rtt")
        if ack_rtt is not None:
            try:
                rtt_value = float(ack_rtt)
            except ValueError:
                rtt_value = None
            if rtt_value is not None and rtt_value >= 0:
                conv.rtt_sum += rtt_value
                conv.rtt_samples += 1
                conv.rtt_max = max(conv.rtt_max, rtt_value)

    if udp_stream is not None and src and dst:
        stream_key = int(udp_stream)
        if (
            stream_key not in state.udp_convs
            and len(state.tcp_convs) + len(state.udp_convs) >= config.MAX_CONVERSATIONS
        ):
            state.truncated_sections.add("conversations")
            udp_stream = None
    if udp_stream is not None and src and dst:
        _update_conversation(
            state.udp_convs, int(udp_stream), src,
            int(fget(layers, "udp.srcport", "0") or 0), dst,
            int(fget(layers, "udp.dstport", "0") or 0), ts, length,
        )

    # HTTP requests/responses (Wireshark "HTTP requests" view)
    if tcp_stream is not None and src and dst and not is_icmp_error:
        stream_id = int(tcp_stream)
        method = fget(layers, "http.request.method")
        if method is not None and len(state.http_requests) < config.MAX_HTTP_REQUESTS:
            request = HttpRequestRow(
                time=round(max(0.0, ts - state.first_ts), 6),
                client=src, server=dst,
                method=_sanitize(method, 16),
                host=_sanitize(fget(layers, "http.host", "") or "", 128),
                uri=_sanitize(fget(layers, "http.request.uri", "") or "", 200),
            )
            state.http_requests.append(request)
            state.http_pending.setdefault(stream_id, []).append(request)
        elif method is not None:
            state.truncated_sections.add("http_requests")
        # Response time = request to the first byte of the answer. http.time runs
        # to the last segment, which measures the download, not the server.
        waiting = state.http_pending.get(stream_id)
        if waiting and method is None and src == waiting[0].server \
                and waiting[0].response_ms is None \
                and (_opt_int(fget(layers, "tcp.len")) or 0) > 0:
            waiting[0].response_ms = round(
                max(0.0, ts - state.first_ts - waiting[0].time) * 1000, 1)
        response_code = fget(layers, "http.response.code")
        if response_code is not None:
            pending = state.http_pending.get(stream_id)
            answered = pending.pop(0) if pending else None
            if answered is not None:
                answered.status = int(response_code)
            http_time = fget(layers, "http.time")
            if http_time is not None:
                try:
                    seconds = float(http_time)
                except ValueError:
                    seconds = None
                if seconds is not None and seconds >= 0:
                    if len(state.http_response_times) < config.MAX_HTTP_REQUESTS:
                        state.http_response_times.append(seconds)

    # TLS sessions (Wireshark TLS view): one row per stream
    if tcp_stream is not None and src and dst and "tls" in chain:
        stream_id = int(tcp_stream)
        session = state.tls_sessions.get(stream_id)
        if session is None:
            if len(state.tls_sessions) < config.MAX_TLS_SESSIONS:
                session = TlsSessionState(stream_id=stream_id, client=src, server=dst)
                state.tls_sessions[stream_id] = session
            else:
                state.truncated_sections.add("tls_sessions")
        if session is not None:
            handshake_type = fget(layers, "tls.handshake.type")
            version = fget(layers, "tls.handshake.version") or fget(layers, "tls.record.version")
            if version is not None:
                session.version = _TLS_VERSIONS.get(version, version)
            cipher = fget(layers, "tls.handshake.ciphersuite")
            sni = fget(layers, "tls.handshake.extensions_server_name")
            if handshake_type == "1":
                session.client, session.server = src, dst
                if sni:
                    session.sni = _sanitize(sni, 128)
            if handshake_type == "2":
                hello_version = fget(layers, "tls.handshake.version")
                if hello_version is not None:
                    session.negotiated = hello_version
            if handshake_type == "2" and cipher:
                session.cipher = _TLS_CIPHERS.get(cipher, cipher)
            elif cipher and session.cipher is None:
                session.cipher = _TLS_CIPHERS.get(cipher, cipher)

    dns_id = fget(layers, "dns.id")
    if dns_id is not None and src and dst and not is_icmp_error:
        name = _sanitize(fget(layers, "dns.qry.name", "") or "")
        key = (udp_stream or ("tcp-%s" % tcp_stream), dns_id, name)
        if field_bool(layers, "dns.flags.response"):
            pending = state.dns_pending.get(key)
            query = pending.pop(0) if pending else None
            if pending == []:
                del state.dns_pending[key]
            rcode = int(fget(layers, "dns.flags.rcode", "0") or 0)
            if rcode == 0 and name:
                for addr in _as_list(layers.get("dns_a")) + _as_list(layers.get("dns_aaaa")):
                    address = _sanitize(str(addr), 45)
                    if address in state.resolved:
                        continue
                    if len(state.resolved) >= config.MAX_RESOLVED_NAMES:
                        state.truncated_sections.add("resolved_names")
                        break
                    state.resolved[address] = name
            if query is not None:
                if len(state.dns_answered) < config.MAX_DNS_TRANSACTIONS:
                    state.dns_answered.append(
                        DnsExchange(name=name, server=src, client=dst,
                                    latency_s=ts - query.ts,
                                    status={2: "servfail", 3: "nxdomain"}.get(rcode, "ok"))
                    )
                else:
                    state.truncated_sections.add("dns")
            if rcode in (2, 3):  # SERVFAIL / NXDOMAIN
                if len(state.dns_errors) < config.MAX_DNS_TRANSACTIONS:
                    state.dns_errors.append(
                        DnsError(rcode=rcode, name=name, server=src, client=dst)
                    )
                else:
                    state.truncated_sections.add("dns")
        else:
            if state.dns_queries_seen < config.MAX_DNS_TRANSACTIONS:
                state.dns_queries_seen += 1
                state.dns_pending.setdefault(key, []).append(
                    DnsQuery(ts=ts, name=name, server=dst, client=src)
                )
            else:
                state.truncated_sections.add("dns")

    dhcp_type = fget(layers, "dhcp.option.dhcp")
    if dhcp_type is not None and fget(layers, "dhcp.id") is not None:
        mac = _sanitize(fget(layers, "dhcp.hw.mac_addr", "") or "?", 32)
        key = (str(fget(layers, "dhcp.id")), mac)
        txn = state.dhcp_txns.get(key)
        if txn is None:
            if len(state.dhcp_txns) >= config.MAX_DHCP_TRANSACTIONS:
                state.truncated_sections.add("dhcp")
                txn = None
            else:
                txn = state.dhcp_txns[key] = DhcpTxnState(client_mac=mac, first_ts=ts)
        if txn is not None:
            try:
                kind = int(dhcp_type)
            except ValueError:
                kind = 0
            txn.types.add(kind)
            if kind in (1, 3):
                txn.requests += 1
            hostname = fget(layers, "dhcp.option.hostname")
            if hostname and txn.hostname is None:
                txn.hostname = _sanitize(hostname, 64)
            your_ip = fget(layers, "dhcp.ip.your")
            if your_ip and your_ip != "0.0.0.0" and kind in (2, 5):
                txn.ip = _sanitize(your_ip, 45)
            server_id = fget(layers, "dhcp.option.dhcp_server_id")
            if server_id and kind in (2, 5, 6):
                txn.server = _sanitize(server_id, 45)
            if kind == 5 and txn.ack_ts is None:
                txn.ack_ts = ts

    if field_present(layers, "tls.alert_message.desc"):
        desc = int(fget(layers, "tls.alert_message.desc", "-1") or -1)
        if len(state.tls_alerts) < config.MAX_TLS_ALERTS:
            state.tls_alerts.append(
                TlsAlert(
                    ts=ts,
                    src=src or "?",
                    dst=dst or "?",
                    level=int(fget(layers, "tls.alert_message.level", "0") or 0),
                    desc=desc,
                    stream_id=int(tcp_stream) if tcp_stream is not None else None,
                )
            )
        else:
            state.truncated_sections.add("tls_alerts")
        if tcp_stream is not None:
            session = state.tls_sessions.get(int(tcp_stream))
            if session is not None:
                session.alert = _TLS_ALERT_NAMES.get(desc, "alert_%d" % desc)

    # ICMP "Fragmentation Needed" / ICMPv6 "Packet Too Big" (path MTU)
    if src and dst:
        if fget(layers, "icmp.type") == "3" and fget(layers, "icmp.code") == "4":
            state.icmp_frag_events.append(IcmpFragEvent(
                ts=ts, src=src, dst=dst,
                mtu=int(fget(layers, "icmp.mtu", "0") or 0),
            )) if len(state.icmp_frag_events) < config.MAX_ICMP_EVENTS else state.truncated_sections.add("icmp")
        elif fget(layers, "icmpv6.type") == "2":
            state.icmp_frag_events.append(IcmpFragEvent(
                ts=ts, src=src, dst=dst,
                mtu=int(fget(layers, "icmpv6.mtu", "0") or 0),
            )) if len(state.icmp_frag_events) < config.MAX_ICMP_EVENTS else state.truncated_sections.add("icmp")

    # ICMP / ICMPv6 errors that point at a routing, firewall or host problem.
    # "Fragmentation needed" is handled above (path MTU), not here.
    if src and dst:
        error_key = None
        inner_dsts: list = []
        icmp4_type, icmp6_type = fget(layers, "icmp.type"), fget(layers, "icmpv6.type")
        if icmp4_type is not None:
            kind, code = _opt_int(icmp4_type), _opt_int(fget(layers, "icmp.code", "0")) or 0
            if kind is not None and ((kind == 3 and code != 4) or kind == 11):
                error_key = (4, src, kind, code)
                inner_dsts = _as_list(layers.get("ip_dst"))
        elif icmp6_type is not None:
            kind, code = _opt_int(icmp6_type), _opt_int(fget(layers, "icmpv6.code", "0")) or 0
            if kind in (1, 3):  # destination unreachable, time exceeded
                error_key = (6, src, kind, code)
                inner_dsts = _as_list(layers.get("ipv6_dst"))
        if error_key is not None:
            group = state.icmp_errors.get(error_key)
            if group is None:
                if len(state.icmp_errors) < config.MAX_ICMP_ERROR_GROUPS:
                    group = state.icmp_errors[error_key] = IcmpErrorGroup(
                        family=error_key[0], reporter=src,
                        icmp_type=error_key[2], code=error_key[3], first_ts=ts,
                    )
                else:
                    state.truncated_sections.add("icmp")
            if group is not None:
                group.count += 1
                # the quoted (inner) header's destination is what was unreachable
                target = _sanitize(str(inner_dsts[1]), 45) if len(inner_dsts) > 1 else None
                if target and target not in group.targets and len(group.targets) < 5:
                    group.targets.append(target)
                if dst not in group.victims and len(group.victims) < 3:
                    group.victims.append(dst)

    # IPv4 fragments (MF set, or a trailing fragment with offset > 0)
    frag_offset = int(fget(layers, "ip.frag_offset", "0") or 0)
    if src and dst and (field_bool(layers, "ip.flags.mf") or frag_offset > 0):
        state.frag_packets += 1
        group_key = (src, dst, fget(layers, "ip.id", "?") or "?",
                     fget(layers, "ip.proto", "?") or "?")
        group = state.frag_groups.get(group_key)
        if group is None and len(state.frag_groups) < config.MAX_FRAGMENT_GROUPS:
            group = state.frag_groups[group_key] = FragGroup()
        elif group is None:
            state.truncated_sections.add("fragments")
        if group is not None:
            group.packets += 1
            group.bytes += length
            if frag_offset == 0 and field_bool(layers, "ip.flags.mf"):
                group.has_first = True
            if frag_offset > 0 and not field_bool(layers, "ip.flags.mf"):
                group.has_last = True

    # VPN / tunnel traffic
    if src and dst:
        for token, tunnel_type in _TUNNEL_TOKENS:
            if token not in chain:
                continue
            pair = tuple(sorted((src, dst)))
            tunnel = state.tunnels.get((tunnel_type, pair))
            if tunnel is None:
                if len(state.tunnels) < config.MAX_TRACKED_TALKERS:
                    tunnel = TunnelState(type=tunnel_type, peer_a=src, peer_b=dst)
                    state.tunnels[(tunnel_type, pair)] = tunnel
                else:
                    state.truncated_sections.add("tunnels")
                    break
            if src == tunnel.peer_a:
                tunnel.packets_a2b += 1
            else:
                tunnel.packets_b2a += 1
            tunnel.bytes += length
            break

    # ARP announcements (duplicate IP detection)
    arp_ip = fget(layers, "arp.src.proto_ipv4")
    arp_mac = fget(layers, "arp.src.hw_mac")
    if arp_ip and arp_mac and arp_ip != "0.0.0.0":
        if arp_ip not in state.arp_map and len(state.arp_map) >= config.MAX_ARP_CLAIMS:
            state.truncated_sections.add("arp")
            return
        macs = state.arp_map.setdefault(arp_ip, {})
        if arp_mac not in macs and len(macs) >= config.MAX_ARP_MACS_PER_IP:
            state.truncated_sections.add("arp")
            return
        macs[arp_mac] = macs.get(arp_mac, 0) + 1


def _build_summary(state: CaptureState) -> Summary:
    duration = 0.0
    if state.first_ts is not None and state.last_ts is not None:
        duration = max(0.0, state.last_ts - state.first_ts)
    return Summary(
        packets=state.packets,
        bytes=state.bytes,
        duration_seconds=round(duration, 6),
        conversations=len(state.tcp_convs) + len(state.udp_convs),
        start_time_epoch=state.first_ts,
        end_time_epoch=state.last_ts,
        avg_packets_per_second=round(state.packets / duration, 2) if duration else 0.0,
        avg_bytes_per_second=round(state.bytes / duration, 2) if duration else 0.0,
    )


def _build_protocols(state: CaptureState) -> List[ProtocolStat]:
    total_packets = state.packets or 1
    total_bytes = state.bytes or 1
    stats = [
        ProtocolStat(
            protocol=proto,
            packets=count,
            bytes=state.proto_bytes.get(proto, 0),
            packet_pct=round(100.0 * count / total_packets, 2),
            bytes_pct=round(100.0 * state.proto_bytes.get(proto, 0) / total_bytes, 2),
        )
        for proto, count in state.proto_packets.items()
    ]
    stats.sort(key=lambda item: item.packets, reverse=True)
    return stats


def _build_time_series(state: CaptureState) -> List[TimeSeriesPoint]:
    return [
        TimeSeriesPoint(t=second, packets=vals[0], bytes=vals[1], retransmissions=vals[2])
        for second, vals in sorted(state.buckets.items())
    ]


def _build_conversations(state: CaptureState) -> Conversations:
    tcp = []
    for conv in state.tcp_convs.values():
        pct = 100.0 * conv.retransmissions / conv.packets if conv.packets else 0.0
        rtt_ms = None
        if conv.syn_ts is not None and conv.synack_ts is not None:
            rtt_ms = round((conv.synack_ts - conv.syn_ts) * 1000, 1)
        tcp.append(
            TcpConversation(
                mss_client=conv.mss_client,
                mss_server=conv.mss_server,
                handshake_rtt_ms=rtt_ms,
                stream_id=conv.stream_id,
                src=conv.src, src_port=conv.src_port,
                dst=conv.dst, dst_port=conv.dst_port,
                packets=conv.packets, bytes=conv.bytes,
                bytes_src_to_dst=conv.bytes_fwd, bytes_dst_to_src=conv.bytes_rev,
                start_time_epoch=conv.first_ts, end_time_epoch=conv.last_ts,
                duration_seconds=round(conv.last_ts - conv.first_ts, 6),
                retransmissions=conv.retransmissions,
                retransmission_pct=round(pct, 2),
                zero_window_events=conv.zero_window_events,
                dup_acks=conv.dup_acks,
                out_of_order=conv.out_of_order,
                lost_segments=conv.lost_segments,
                window_full=conv.window_full,
                resets_midstream=conv.resets_midstream,
                rtt_avg_ms=(round(conv.rtt_sum / conv.rtt_samples * 1000, 2)
                            if conv.rtt_samples else None),
                rtt_max_ms=round(conv.rtt_max * 1000, 2) if conv.rtt_samples else None,
            )
        )
    tcp.sort(key=lambda item: item.bytes, reverse=True)

    udp = [
        UdpConversation(
            stream_id=conv.stream_id,
            src=conv.src, src_port=conv.src_port,
            dst=conv.dst, dst_port=conv.dst_port,
            packets=conv.packets, bytes=conv.bytes,
            bytes_src_to_dst=conv.bytes_fwd, bytes_dst_to_src=conv.bytes_rev,
            start_time_epoch=conv.first_ts, end_time_epoch=conv.last_ts,
            duration_seconds=round(conv.last_ts - conv.first_ts, 6),
        )
        for conv in state.udp_convs.values()
    ]
    udp.sort(key=lambda item: item.bytes, reverse=True)

    talkers = [
        TopTalker(
            address=addr,
            packets=data["packets"],
            bytes_sent=data["bytes_sent"],
            bytes_received=data["bytes_received"],
            bytes_total=data["bytes_sent"] + data["bytes_received"],
        )
        for addr, data in state.talkers.items()
    ]
    talkers.sort(key=lambda item: item.bytes_total, reverse=True)

    return Conversations(tcp=tcp, udp=udp, top_talkers=talkers[: config.TOP_TALKERS_LIMIT])


def _build_dns_queries(state: CaptureState) -> List[DnsQueryRow]:
    """Wireshark-style DNS view: every query with its resolution outcome."""
    rows = []
    for exchange in state.dns_answered:
        status = exchange.status
        if status == "ok" and exchange.latency_s > config.DNS_SLOW_THRESHOLD_S:
            status = "slow"
        rows.append(DnsQueryRow(
            name=exchange.name, client=exchange.client, server=exchange.server,
            status=status, latency_ms=round(exchange.latency_s * 1000, 1),
        ))
    for pending in state.dns_pending.values():
        for query in pending:
            rows.append(DnsQueryRow(
                name=query.name, client=query.client, server=query.server,
                status="unanswered", latency_ms=None,
            ))
    return rows


def _build_dhcp_leases(state: CaptureState) -> List[DhcpLeaseRow]:
    """Wireshark-style DHCP view: one row per transaction with its outcome."""
    rows = []
    for txn in state.dhcp_txns.values():
        types = txn.types
        if 5 in types:
            status = "bound"
        elif 6 in types:
            status = "nak"
        elif 4 in types:
            status = "declined"
        elif 7 in types:
            status = "released"
        elif 2 in types:
            status = "offered"
        elif types & {1, 3}:
            status = "no_offer"
        else:  # INFORM-only exchanges carry no lease outcome worth reporting
            continue
        latency = (
            round((txn.ack_ts - txn.first_ts) * 1000, 1)
            if txn.ack_ts is not None else None
        )
        rows.append(DhcpLeaseRow(
            client_mac=txn.client_mac, hostname=txn.hostname, ip=txn.ip,
            server=txn.server, status=status, latency_ms=latency,
        ))
    return rows


def _build_service_response_times(state: CaptureState) -> List[ServiceResponseTime]:
    """Aggregate request→response latency per protocol (Wireshark SRT)."""
    dns_samples = [e.latency_s for e in state.dns_answered]
    tcp_samples = [
        (c.synack_ts - c.syn_ts)
        for c in state.tcp_convs.values()
        if c.syn_ts is not None and c.synack_ts is not None
    ]
    sources = [
        ("DNS", dns_samples),
        ("TCP handshake", tcp_samples),
        ("HTTP", state.http_response_times),
    ]
    rows = []
    for protocol, samples in sources:
        if not samples:
            continue
        rows.append(ServiceResponseTime(
            protocol=protocol,
            samples=len(samples),
            min_ms=round(min(samples) * 1000, 2),
            avg_ms=round(sum(samples) / len(samples) * 1000, 2),
            max_ms=round(max(samples) * 1000, 2),
        ))
    return rows


def _build_tls_sessions(state: CaptureState) -> List[TlsSession]:
    sessions = [
        TlsSession(
            stream_id=s.stream_id, client=s.client, server=s.server,
            version=s.version, cipher=s.cipher, sni=s.sni, alert=s.alert,
        )
        for s in state.tls_sessions.values()
    ]
    sessions.sort(key=lambda item: item.stream_id)
    return sessions


def _build_expert_info(state: CaptureState) -> List[ExpertEntry]:
    """Wireshark "Expert Information": errors first, then by how often it fired."""
    entries = [
        ExpertEntry(severity=e.severity, group=e.group, summary=e.summary,
                    count=e.count, first_packet=e.first_packet)
        for e in state.expert.values()
    ]
    entries.sort(key=lambda e: (-_EXPERT_RANK[e.severity], -e.count, e.summary))
    return entries


def _build_resolved_names(state: CaptureState) -> List[ResolvedName]:
    return [
        ResolvedName(address=address, name=name)
        for address, name in sorted(state.resolved.items())
    ]


def _build_tunnels(state: CaptureState) -> List[Tunnel]:
    tunnels = [
        Tunnel(
            type=tunnel.type,
            peer_a=tunnel.peer_a,
            peer_b=tunnel.peer_b,
            packets=tunnel.packets_a2b + tunnel.packets_b2a,
            packets_a_to_b=tunnel.packets_a2b,
            packets_b_to_a=tunnel.packets_b2a,
            bytes=tunnel.bytes,
        )
        for tunnel in state.tunnels.values()
    ]
    tunnels.sort(key=lambda item: item.bytes, reverse=True)
    return tunnels


def analyze_pcap(
    tshark_path: str,
    pcap_path: str,
    original_filename: str,
    size_bytes: int,
) -> AnalysisResult:
    """Run the full single-pass analysis over a capture file."""
    started = time.monotonic()
    state = CaptureState()
    for layers in iter_packets(tshark_path, pcap_path):
        try:
            _consume_packet(state, layers)
        except (ValueError, TypeError):
            # One malformed packet must not cost the user the whole analysis.
            # Only the count is kept: field values are capture data, never logged.
            state.skipped_packets += 1
            if state.skipped_packets == 1:
                _log.warning("Paquete con campos no interpretables; se omite y se sigue.")

    quality = build_capture_quality(state)
    issues = apply_quality_caveats(build_issues(state), quality)
    if len(issues) > config.MAX_ISSUES:
        state.truncated_sections.add("issues")
        issues = issues[:config.MAX_ISSUES]
    result = AnalysisResult(
        file=FileInfo(name=original_filename, size_bytes=size_bytes),
        summary=_build_summary(state),
        protocols=_build_protocols(state),
        time_series=_build_time_series(state),
        conversations=_build_conversations(state),
        tunnels=_build_tunnels(state),
        issues=issues,
        packet_list=PacketList(
            rows=state.packet_rows,
            total=state.packets,
            truncated=state.packets > len(state.packet_rows),
        ),
        dns_queries=_build_dns_queries(state),
        dhcp_leases=_build_dhcp_leases(state),
        http_requests=state.http_requests,
        service_response_times=_build_service_response_times(state),
        tls_sessions=_build_tls_sessions(state),
        expert_info=_build_expert_info(state),
        resolved_names=_build_resolved_names(state),
        capture_quality=quality,
        meta=Meta(
            engine_version=__version__,
            tshark_version=tshark_version(tshark_path),
            analysis_duration_ms=int((time.monotonic() - started) * 1000),
            truncated_sections=sorted(state.truncated_sections),
            skipped_packets=state.skipped_packets,
        ),
    )
    result._duplicate_frames = state.duplicate_numbers
    return result
