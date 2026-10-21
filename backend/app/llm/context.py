"""Build the compact capture summary the LLM receives.

Privacy rule (CLAUDE.md): the model gets a structured JSON summary, never the
raw pcap. Caps keep the context small even for large captures.
"""
from __future__ import annotations

from typing import Any, Dict

from ..models import AnalysisResult

MAX_ISSUES = 30
MAX_TCP_CONVERSATIONS = 12
MAX_UDP_CONVERSATIONS = 6
MAX_TALKERS = 6
MAX_PROTOCOLS = 10
MAX_TUNNELS = 12


def build_llm_context(analysis: AnalysisResult) -> Dict[str, Any]:
    """Trim an AnalysisResult into the dict sent to the model."""
    summary = analysis.summary
    peak = max(analysis.time_series, key=lambda p: p.packets, default=None)

    return {
        "file": {"name": analysis.file.name, "size_bytes": analysis.file.size_bytes},
        "summary": {
            "packets": summary.packets,
            "bytes": summary.bytes,
            "duration_seconds": summary.duration_seconds,
            "conversations": summary.conversations,
            "avg_packets_per_second": summary.avg_packets_per_second,
            "peak_packets_per_second": peak.packets if peak else 0,
            "total_retransmissions": sum(p.retransmissions for p in analysis.time_series),
        },
        "protocols": [
            {"protocol": p.protocol, "packets": p.packets, "packet_pct": p.packet_pct}
            for p in analysis.protocols[:MAX_PROTOCOLS]
        ],
        "top_talkers": [
            {"address": t.address, "bytes_total": t.bytes_total}
            for t in analysis.conversations.top_talkers[:MAX_TALKERS]
        ],
        "tcp_conversations": [
            {
                "stream_id": c.stream_id,
                "src": "%s:%d" % (c.src, c.src_port),
                "dst": "%s:%d" % (c.dst, c.dst_port),
                "packets": c.packets,
                "bytes": c.bytes,
                "retransmission_pct": c.retransmission_pct,
                "zero_window_events": c.zero_window_events,
                "mss_client": c.mss_client,
                "mss_server": c.mss_server,
                "handshake_rtt_ms": c.handshake_rtt_ms,
            }
            for c in analysis.conversations.tcp[:MAX_TCP_CONVERSATIONS]
        ],
        "udp_conversations": [
            {
                "stream_id": c.stream_id,
                "src": "%s:%d" % (c.src, c.src_port),
                "dst": "%s:%d" % (c.dst, c.dst_port),
                "packets": c.packets,
                "bytes": c.bytes,
            }
            for c in analysis.conversations.udp[:MAX_UDP_CONVERSATIONS]
        ],
        "tunnels": [t.model_dump() for t in analysis.tunnels[:MAX_TUNNELS]],
        "tunnels_truncated": max(0, len(analysis.tunnels) - MAX_TUNNELS),
        "issues": [
            {
                "id": i.id,
                "type": i.type,
                "severity": i.severity,
                "title": i.title,
                "detail": i.detail,
                "conversation": i.conversation,
                "evidence": i.evidence,
            }
            for i in analysis.issues[:MAX_ISSUES]
        ],
        "issues_truncated": max(0, len(analysis.issues) - MAX_ISSUES),
    }
