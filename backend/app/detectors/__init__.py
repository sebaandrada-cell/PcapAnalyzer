"""Issue detectors.

One module per detection pattern (see CLAUDE.md). Every module implements the
same interface: a ``detect(state: CaptureState) -> List[Issue]`` function.
"""
from __future__ import annotations

from typing import List

from ..models import Issue
from . import (
    dns_errors,
    dns_problems,
    duplicate_ip,
    ip_fragmentation,
    mtu_mss,
    tcp_handshake,
    tcp_retransmissions,
    tcp_syn_rst,
    tcp_zero_window,
    tls_alerts,
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
]


def build_issues(state) -> List[Issue]:
    issues: List[Issue] = []
    for detector in DETECTORS:
        issues.extend(detector.detect(state))
    issues.sort(key=lambda issue: _SEVERITY_ORDER[issue.severity])
    return issues
