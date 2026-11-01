"""Parsers for the text that ``tshark -z`` and ``-z follow`` print.

They are deliberately tolerant: tshark's layout varies slightly between
versions, so each parser keys on the stable tokens of a line and ignores
headers, separators and anything it does not recognise.
"""
from __future__ import annotations

import re
from typing import Dict, List

_UNITS = {"bytes": 1, "kb": 1000, "mb": 1000 ** 2, "gb": 1000 ** 3, "tb": 1000 ** 4}


def _size(amount: str, unit: str) -> int:
    return int(round(float(amount) * _UNITS.get(unit.lower(), 1)))


_CONV = re.compile(
    r"^(?P<a>\S+)\s+<->\s+(?P<b>\S+)\s+"
    r"(?P<f1>\d+)\s+(?P<b1>[\d.]+)\s+(?P<u1>\S+)\s+"
    r"(?P<f2>\d+)\s+(?P<b2>[\d.]+)\s+(?P<u2>\S+)\s+"
    r"(?P<ft>\d+)\s+(?P<bt>[\d.]+)\s+(?P<ut>\S+)\s+"
    r"(?P<start>[\d.]+)\s+(?P<dur>[\d.]+)\s*$"
)


def parse_conversations(text: str) -> List[dict]:
    rows = []
    for line in text.splitlines():
        m = _CONV.match(line.strip())
        if not m:
            continue
        rows.append({
            "a": m["a"], "b": m["b"],
            "frames_b_to_a": int(m["f1"]), "bytes_b_to_a": _size(m["b1"], m["u1"]),
            "frames_a_to_b": int(m["f2"]), "bytes_a_to_b": _size(m["b2"], m["u2"]),
            "frames": int(m["ft"]), "bytes": _size(m["bt"], m["ut"]),
            "rel_start": float(m["start"]), "duration": float(m["dur"]),
        })
    return rows


_ENDPOINT = re.compile(
    r"^(?P<addr>\S+)\s+(?P<p>\d+)\s+(?P<b>[\d.]+)\s+(?P<u>\S+)\s+"
    r"(?P<tp>\d+)\s+(?P<tb>[\d.]+)\s+(?P<tu>\S+)\s+"
    r"(?P<rp>\d+)\s+(?P<rb>[\d.]+)\s+(?P<ru>\S+)\s*$"
)


def parse_endpoints(text: str) -> List[dict]:
    rows = []
    for line in text.splitlines():
        m = _ENDPOINT.match(line.strip())
        if not m or m["addr"].startswith("|"):
            continue
        rows.append({
            "address": m["addr"], "packets": int(m["p"]), "bytes": _size(m["b"], m["u"]),
            "tx_packets": int(m["tp"]), "tx_bytes": _size(m["tb"], m["tu"]),
            "rx_packets": int(m["rp"]), "rx_bytes": _size(m["rb"], m["ru"]),
        })
    return rows


_IO = re.compile(r"^\|\s*(?P<start>[\d.]+)\s*<>\s*\S+\s*\|\s*(?P<frames>\d+)\s*\|\s*(?P<bytes>\d+)\s*\|")


def parse_io_stat(text: str) -> List[dict]:
    rows = []
    for line in text.splitlines():
        m = _IO.match(line)
        if m:
            rows.append({"interval_start": float(m["start"]), "frames": int(m["frames"]), "bytes": int(m["bytes"])})
    return rows


_PHS = re.compile(r"^(?P<indent> *)(?P<name>\S+)\s+frames:(?P<frames>\d+)\s+bytes:(?P<bytes>\d+)")


def parse_protocol_hierarchy(text: str) -> List[dict]:
    rows: List[dict] = []
    stack: List[str] = []
    for line in text.splitlines():
        m = _PHS.match(line)
        if not m:
            continue
        depth = len(m["indent"]) // 2
        stack = stack[:depth] + [m["name"]]
        rows.append({"protocol": ":".join(stack), "frames": int(m["frames"]), "bytes": int(m["bytes"])})
    return rows


_SEVERITY_HEADERS = {"errors": "error", "warns": "warning", "notes": "note", "chats": "chat", "comments": "comment"}
_EXPERT_ROW = re.compile(r"^\s*(?P<freq>\d+)\s+(?P<group>\S+)\s+(?P<proto>\S+)\s+(?P<summary>.+?)\s*$")


def parse_expert(text: str) -> List[dict]:
    rows: List[dict] = []
    severity = None
    for line in text.splitlines():
        head = re.match(r"^(\w+)\s+\(\d+\)\s*$", line.strip())
        if head:
            severity = _SEVERITY_HEADERS.get(head.group(1).lower(), head.group(1).lower())
            continue
        if severity is None or line.strip().startswith("Frequency") or set(line.strip()) <= {"="}:
            continue
        m = _EXPERT_ROW.match(line)
        if m:
            rows.append({
                "severity": severity, "frequency": int(m["freq"]), "group": m["group"],
                "protocol": m["proto"], "summary": m["summary"],
            })
    return rows


def parse_dns_tree(text: str) -> dict:
    """Sections of ``-z dns,tree`` as {section: {label: count}} plus totals."""
    out: Dict[str, Dict[str, int]] = {}
    section = None
    for line in text.splitlines():
        if not line.strip() or line.startswith(("=", "-", "DNS:", "Packet Type")):
            continue
        m = re.match(r"^( *)(?P<label>.+?)\s{2,}(?P<count>\d+)\s", line)
        if not m:
            continue
        indent = len(m.group(1))
        if indent == 0:
            section = m["label"].strip()
            out.setdefault(section, {})
            out[section]["_total"] = int(m["count"])
        elif section is not None:
            out[section][m["label"].strip()] = int(m["count"])
    return out


_SRT_NUMS = re.compile(r"^([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)\s+(\d+)\s*$")


def parse_srt(text: str) -> List[dict]:
    """Rows of a ``-z <proto>,srt`` table (icmp-style summary or per-procedure tables)."""
    rows: List[dict] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = _SRT_NUMS.match(line.strip())
        if m:
            rows.append({
                "procedure": "all", "min_srt": float(m[1]), "max_srt": float(m[2]),
                "avg_srt": float(m[3]), "median_srt": float(m[4]), "min_frame": int(m[6]), "max_frame": int(m[7]),
            })
            continue
        pm = re.match(r"^(?P<proc>.+?)\s{2,}(?P<calls>\d+)\s+(?P<min>[\d.]+)\s+(?P<max>[\d.]+)\s+(?P<avg>[\d.]+)", line.strip())
        if pm and not line.strip().startswith(("Procedure", "Index", "Requests")):
            rows.append({
                "procedure": pm["proc"], "calls": int(pm["calls"]), "min_srt": float(pm["min"]),
                "max_srt": float(pm["max"]), "avg_srt": float(pm["avg"]),
            })
    return rows


def parse_follow(text: str) -> dict:
    """``-z follow,...,ascii,N`` output -> nodes and directional text chunks."""
    nodes: Dict[str, str] = {}
    chunks: List[dict] = []
    current = None
    for line in text.splitlines():
        if line.startswith("Node 0:"):
            nodes["a"] = line.split(":", 1)[1].strip()
            continue
        if line.startswith("Node 1:"):
            nodes["b"] = line.split(":", 1)[1].strip()
            continue
        if "b" not in nodes or set(line.strip()) <= {"="} and line.strip():
            continue
        stripped = line.lstrip("\t")
        if stripped.isdigit():  # a byte count opens a chunk; node 1's are tab-indented
            current = {"direction": "b_to_a" if line.startswith("\t") else "a_to_b", "lines": []}
            chunks.append(current)
            continue
        if current is not None:
            current["lines"].append(line)
    return {"nodes": nodes, "chunks": [{"direction": c["direction"], "text": "\n".join(c["lines"])} for c in chunks]}
