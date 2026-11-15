"""Issue detectors.

One module per detection pattern (see CLAUDE.md). Every module implements the
same interface: a ``detect(state: CaptureState) -> List[Issue]`` function.
"""
from __future__ import annotations

from typing import List

from ..models import Issue
from . import (
    dhcp_problems,
    dns_errors,
    dns_problems,
    duplicate_ip,
    http_errors,
    icmp_ttl_exceeded,
    icmp_unreachable,
    ip_fragmentation,
    mtu_mss,
    tcp_dup_acks,
    tcp_handshake,
    tcp_lost_segments,
    tcp_out_of_order,
    tcp_resets,
    tcp_retransmissions,
    tcp_syn_rst,
    tcp_window_full,
    tcp_zero_window,
    tls_alerts,
    tls_legacy,
    vpn_tunnels,
)

_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}

DETECTORS = [
    tcp_syn_rst,
    tcp_retransmissions,
    duplicate_ip,
    vpn_tunnels,
    ip_fragmentation,
    mtu_mss,
    dns_problems,
    dns_errors,
    tcp_handshake,
    tcp_zero_window,
    tls_alerts,
    tcp_dup_acks,
    tcp_lost_segments,
    tcp_out_of_order,
    tcp_window_full,
    tcp_resets,
    icmp_unreachable,
    icmp_ttl_exceeded,
    http_errors,
    dhcp_problems,
    tls_legacy,
]


def build_issues(state) -> List[Issue]:
    issues: List[Issue] = []
    for detector in DETECTORS:
        issues.extend(detector.detect(state))
    issues.sort(key=lambda issue: _SEVERITY_ORDER[issue.severity])
    return issues
