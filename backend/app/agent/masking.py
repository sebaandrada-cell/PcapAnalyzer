"""Hide credentials in stream content before it leaves the machine."""
from __future__ import annotations

import re

_HEADERS = ("authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token")
_HEADER_RE = re.compile(r"(?im)^(%s)\s*:\s*[^\r\n]*" % "|".join(re.escape(h) for h in _HEADERS))
_PAIR_RE = re.compile(r"(?i)\b(password|passwd|pwd|token|secret)=[^&\s\"']*")
_SCHEME_RE = re.compile(r"(?i)\b(Basic|Bearer)\s+[A-Za-z0-9._~+/=-]+")


def mask_sensitive(text: str) -> str:
    text = _HEADER_RE.sub(lambda m: "%s: ***" % m.group(1), text)
    text = _PAIR_RE.sub(lambda m: "%s=***" % m.group(1), text)
    return _SCHEME_RE.sub(lambda m: "%s ***" % m.group(1), text)
