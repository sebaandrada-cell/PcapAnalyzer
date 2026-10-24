"""Pydantic models describing the analysis result.

These models are the contract shared by the HTTP API, the future React
frontend and the future LLM analysis layer — keep them free of FastAPI /
transport concerns.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field

try:  # Literal lives in typing from 3.8 on
    from typing import Literal
except ImportError:  # pragma: no cover
    from typing_extensions import Literal

Severity = Literal["critical", "warning", "info"]


class FileInfo(BaseModel):
    name: str
    size_bytes: int


class Summary(BaseModel):
    packets: int
    bytes: int
    duration_seconds: float
    conversations: int
    start_time_epoch: Optional[float] = None
    end_time_epoch: Optional[float] = None
    avg_packets_per_second: float = 0.0
    avg_bytes_per_second: float = 0.0


class ProtocolStat(BaseModel):
    protocol: str
    packets: int
    bytes: int
    packet_pct: float
    bytes_pct: float


class TimeSeriesPoint(BaseModel):
    """Per-second traffic bucket. ``t`` is seconds since capture start.

    Sparse: seconds without traffic are omitted; the frontend fills gaps.
    """

    t: int
    packets: int
    bytes: int
    retransmissions: int


class TcpConversation(BaseModel):
    stream_id: int
    src: str
    src_port: int
    dst: str
    dst_port: int
    packets: int
    bytes: int
    bytes_src_to_dst: int
    bytes_dst_to_src: int
    start_time_epoch: float
    end_time_epoch: float
    duration_seconds: float
    retransmissions: int
    retransmission_pct: float
    zero_window_events: int
    mss_client: Optional[int] = None
    mss_server: Optional[int] = None
    handshake_rtt_ms: Optional[float] = None
    # Wireshark "SEQ/ACK analysis" counters
    dup_acks: int = 0
    out_of_order: int = 0
    lost_segments: int = 0
    window_full: int = 0
    resets_midstream: int = 0
    rtt_avg_ms: Optional[float] = None  # tcp.analysis.ack_rtt
    rtt_max_ms: Optional[float] = None


class UdpConversation(BaseModel):
    stream_id: int
    src: str
    src_port: int
    dst: str
    dst_port: int
    packets: int
    bytes: int
    bytes_src_to_dst: int
    bytes_dst_to_src: int
    start_time_epoch: float
    end_time_epoch: float
    duration_seconds: float


class TopTalker(BaseModel):
    address: str
    packets: int
    bytes_sent: int
    bytes_received: int
    bytes_total: int


class Conversations(BaseModel):
    tcp: List[TcpConversation]
    udp: List[UdpConversation]
    top_talkers: List[TopTalker]


class PacketRow(BaseModel):
    """One row of the Wireshark-style packet list."""

    number: int
    time: float  # seconds since capture start
    src: str
    dst: str
    protocol: str
    length: int
    info: str
    stream: Optional[int] = None  # tcp.stream id (None for non-TCP)
    # Extra per-packet fields (all optional: absent for protocols without them).
    sport: Optional[int] = None
    dport: Optional[int] = None
    ttl: Optional[int] = None
    tcp_flags: List[str] = Field(default_factory=list)  # SYN, ACK, RST, FIN, PSH
    seq: Optional[int] = None  # relative tcp.seq
    ack: Optional[int] = None  # relative tcp.ack
    win: Optional[int] = None  # calculated window size
    payload: Optional[int] = None  # tcp.len
    rtt_ms: Optional[float] = None  # tcp.analysis.ack_rtt
    # Wireshark TCP-analysis flags raised on this packet (see engine._ANALYSIS_FLAGS)
    analysis: List[str] = Field(default_factory=list)
    expert: Optional[str] = None  # highest expert severity: error|warning|note|chat
    expert_message: Optional[str] = None


class PacketList(BaseModel):
    rows: List[PacketRow] = Field(default_factory=list)
    total: int = 0
    truncated: bool = False


class ServiceResponseTime(BaseModel):
    """Aggregated request→response latency for one protocol (Wireshark SRT)."""

    protocol: str
    samples: int
    min_ms: float
    avg_ms: float
    max_ms: float


class TlsSession(BaseModel):
    """One TLS session summary (Wireshark TLS view)."""

    stream_id: int
    client: str
    server: str
    version: Optional[str] = None
    cipher: Optional[str] = None
    sni: Optional[str] = None
    alert: Optional[str] = None


class HttpRequestRow(BaseModel):
    """One HTTP request with its response status (Wireshark HTTP stats)."""

    time: float
    client: str
    server: str
    method: str
    host: str
    uri: str
    status: Optional[int] = None  # None while unanswered in the capture


class DnsQueryRow(BaseModel):
    """One DNS query with its resolution outcome (Wireshark 'DNS' stats)."""

    name: str
    client: str
    server: str
    status: str  # ok | slow | unanswered | servfail | nxdomain
    latency_ms: Optional[float] = None


class DhcpLeaseRow(BaseModel):
    """One DHCP transaction (grouped by xid) with its outcome."""

    client_mac: str
    hostname: Optional[str] = None
    ip: Optional[str] = None
    server: Optional[str] = None
    # bound | nak | no_offer | offered | declined | released
    status: str
    latency_ms: Optional[float] = None


ExpertSeverity = Literal["error", "warning", "note", "chat"]


class ExpertEntry(BaseModel):
    """One line of Wireshark's "Expert Information" (grouped by what it says)."""

    severity: ExpertSeverity
    group: str  # Sequence, Checksum, Malformed, Protocol, Security...
    summary: str
    count: int
    first_packet: int


class ResolvedName(BaseModel):
    """IP -> name learned from DNS answers in the capture (Resolved Addresses)."""

    address: str
    name: str


class Tunnel(BaseModel):
    """VPN/tunnel traffic identified passively (ESP, IKE, WireGuard, ...)."""

    type: str
    peer_a: str
    peer_b: str
    packets: int
    packets_a_to_b: int
    packets_b_to_a: int
    bytes: int


class Issue(BaseModel):
    """Common output of every detector (see CLAUDE.md conventions)."""

    id: str
    type: str
    severity: Severity
    title: str
    detail: str
    # English rendering of title/detail; the primary fields stay in Spanish.
    title_en: Optional[str] = None
    detail_en: Optional[str] = None
    conversation: Optional[str] = None
    evidence: Dict[str, object] = Field(default_factory=dict)


class Meta(BaseModel):
    engine_version: str
    tshark_version: str
    analysis_duration_ms: int
    truncated_sections: List[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    file: FileInfo
    summary: Summary
    protocols: List[ProtocolStat]
    time_series: List[TimeSeriesPoint]
    conversations: Conversations
    tunnels: List[Tunnel]
    issues: List[Issue]
    packet_list: PacketList = Field(default_factory=PacketList)
    dns_queries: List[DnsQueryRow] = Field(default_factory=list)
    dhcp_leases: List[DhcpLeaseRow] = Field(default_factory=list)
    http_requests: List[HttpRequestRow] = Field(default_factory=list)
    service_response_times: List[ServiceResponseTime] = Field(default_factory=list)
    tls_sessions: List[TlsSession] = Field(default_factory=list)
    expert_info: List[ExpertEntry] = Field(default_factory=list)
    resolved_names: List[ResolvedName] = Field(default_factory=list)
    meta: Meta
