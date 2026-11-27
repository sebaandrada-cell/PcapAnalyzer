"""Which tshark fields the agent may request.

Headers and metadata are always allowed. Fields that carry application
payload are only allowed once the user switched on "allow content" for the
session, because that data (and anything that looks like it) leaves the
machine towards the model API.
"""
from __future__ import annotations

import re
from typing import List, Tuple

ALLOWED_PREFIXES: Tuple[str, ...] = (
    "frame.", "eth.", "ip.", "ipv6.", "tcp.", "udp.", "icmp.", "icmpv6.", "arp.",
    "dns.", "http.request.", "http.response.", "http.host", "http.user_agent",
    "http.content_type", "http.content_length", "tls.handshake.", "tls.record.",
    "tls.alert_message", "dhcp.", "_ws.col.", "_ws.expert",
)

# Prefix match: "data" also covers "data.data", "imf." covers every imf field.
CONTENT_FIELDS: Tuple[str, ...] = (
    "data", "tcp.payload", "tcp.segment_data", "tcp.reassembled.data", "tls.segment", "udp.payload", "http.file_data", "http.request.line",
    "http.response.line", "http.cookie", "http.authorization", "dns.txt", "smb",
    "smb2", "sip.msg_body", "ftp.request.arg", "imf.", "mime_multipart.",
    # URL query strings often carry tokens or session ids.
    "http.request.uri.query",
)

# Protocols whose Info column shows login commands and their arguments
# (FTP "PASS x", IMAP "LOGIN user pass", SMTP "AUTH PLAIN ...").
SENSITIVE_INFO_PROTOCOLS: Tuple[str, ...] = ("ftp", "pop", "imap", "smtp", "telnet")
# Fields whose value is a URL: the path is kept, the query is hidden.
URL_FIELDS: Tuple[str, ...] = ("http.request.uri", "http.request.full_uri")
_QUERY = re.compile(r"\?[^\s]*")


def strip_query(text: str) -> str:
    """Hide every URL query string in ``text``, keeping the path."""
    return _QUERY.sub("?[query hidden]", text)

_FIELD_NAME = re.compile(r"^[A-Za-z0-9_.]+$")


def _is_content(name: str) -> bool:
    return any(name == c or name.startswith(c if c.endswith(".") else c + ".") for c in CONTENT_FIELDS)


def check_fields(fields: List[str], content_allowed: bool) -> List[str]:
    """Return the field names that must be rejected."""
    rejected = []
    for name in fields:
        if not _FIELD_NAME.match(name):
            rejected.append(name)
        elif _is_content(name):
            if not content_allowed:
                rejected.append(name)
        elif not name.startswith(ALLOWED_PREFIXES):
            rejected.append(name)
    return rejected
