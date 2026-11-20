"""tshark discovery and streaming JSON invocation (no pyshark).

Packets are read with ``tshark -T ek`` (newline-delimited JSON) restricted to
the exact fields the engine needs via ``-e``, which keeps a single pass fast
and memory-flat even for large captures. In ek output field names use
underscores instead of dots and values arrive as lists of strings
(booleans as "True"/"False").
"""
from __future__ import annotations

import json
import os
import selectors
import shutil
import subprocess
import sys
import time
from typing import Iterator, List, Optional

from . import config
from .i18n import tr

_TSHARK_CANDIDATES = [
    "/opt/homebrew/bin/tshark",
    "/usr/local/bin/tshark",
    "/usr/bin/tshark",
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    r"C:\Program Files\Wireshark\tshark.exe",
]

# Every field the analysis engine consumes. Adding a detector usually means
# adding its fields here and handling them in analysis/engine.py.
FIELDS: List[str] = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "frame.protocols",
    "_ws.col.protocol",
    "_ws.col.info",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.id",
    "ip.proto",
    "ip.flags.mf",
    "ip.frag_offset",
    "tcp.stream",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.len",
    "tcp.options.mss_val",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.reset",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission",
    "tcp.analysis.zero_window",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.out_of_order",
    "tcp.analysis.lost_segment",
    "tcp.analysis.window_full",
    "tcp.analysis.window_update",
    "tcp.analysis.keep_alive",
    "tcp.analysis.zero_window_probe",
    "tcp.analysis.ack_rtt",
    "tcp.flags.fin",
    "tcp.flags.push",
    "tcp.seq",
    "tcp.ack",
    "tcp.window_size",
    "tcp.options.timestamp.tsval",
    "tcp.options.sack_re",
    "ip.ttl",
    "icmpv6.code",
    "dns.a",
    "dns.aaaa",
    "_ws.expert.message",
    "_ws.expert.severity",
    "_ws.expert.group",
    "udp.stream",
    "udp.srcport",
    "udp.dstport",
    "dns.id",
    "dns.flags.response",
    "dns.qry.name",
    "dns.flags.rcode",
    "tls.alert_message.level",
    "tls.alert_message.desc",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.response.code",
    "http.time",
    "tls.handshake.type",
    "tls.handshake.version",
    "tls.record.version",
    "tls.handshake.extensions_server_name",
    "tls.handshake.ciphersuite",
    "icmp.type",
    "icmp.code",
    "icmp.mtu",
    "icmpv6.type",
    "icmpv6.mtu",
    "esp.spi",
    "ip.fragment.overlap.conflict",
    "ftp.request.command",
    "pop.request.command",
    "imap.request.command",
    "smtp.req.command",
    "http.authbasic",
    "snmp.version",
    "isakmp.exchangetype",
    "isakmp.rspi",
    "isakmp.flag_r",
    "wg.type",
    "openvpn.opcode",
    "arp.src.proto_ipv4",
    "arp.src.hw_mac",
    "arp.opcode",
    "arp.dst.proto_ipv4",
    "dhcp.id",
    "dhcp.option.dhcp",
    "dhcp.hw.mac_addr",
    "dhcp.ip.your",
    "dhcp.option.hostname",
    "dhcp.option.dhcp_server_id",
]
# What one row of the packet list needs (analysis.engine.build_packet_row).
ROW_FIELDS: List[str] = [
    "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
    "_ws.col.protocol", "_ws.col.info",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "ip.ttl",
    "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.len", "tcp.seq", "tcp.ack",
    "tcp.window_size",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset", "tcp.flags.fin", "tcp.flags.push",
    "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission", "tcp.analysis.zero_window",
    "tcp.analysis.duplicate_ack", "tcp.analysis.out_of_order",
    "tcp.analysis.lost_segment", "tcp.analysis.window_full",
    "tcp.analysis.window_update", "tcp.analysis.keep_alive",
    "tcp.analysis.zero_window_probe", "tcp.analysis.ack_rtt",
    "_ws.expert.message", "_ws.expert.severity", "_ws.expert.group",
    "udp.srcport", "udp.dstport",
]
MAX_EK_LINE_BYTES = 1024 * 1024


class TsharkNotFoundError(RuntimeError):
    pass


class TsharkError(RuntimeError):
    pass


class TsharkTimeoutError(TsharkError):
    pass


def find_tshark() -> Optional[str]:
    env_path = os.environ.get(config.TSHARK_PATH_ENV)
    if env_path:
        return env_path if os.path.isfile(env_path) else None
    found = shutil.which("tshark")
    if found:
        return found
    for candidate in _TSHARK_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    return None


def install_instructions() -> str:
    if sys.platform == "darwin":
        return tr(
            "tshark no está instalado. En macOS: 'brew install wireshark' "
            "(solo CLI) o 'brew install --cask wireshark' (app completa). "
            "También puedes definir TSHARK_PATH apuntando al binario.",
            "tshark is not installed. On macOS: 'brew install wireshark' "
            "(CLI only) or 'brew install --cask wireshark' (full app). "
            "You can also set TSHARK_PATH to the binary.",
        )
    if sys.platform.startswith("linux"):
        return tr(
            "tshark no está instalado. Debian/Ubuntu: 'sudo apt install tshark'. "
            "Fedora: 'sudo dnf install wireshark-cli'. "
            "También puedes definir TSHARK_PATH apuntando al binario.",
            "tshark is not installed. Debian/Ubuntu: 'sudo apt install tshark'. "
            "Fedora: 'sudo dnf install wireshark-cli'. "
            "You can also set TSHARK_PATH to the binary.",
        )
    return tr(
        "tshark no está instalado. Descarga Wireshark desde "
        "https://www.wireshark.org/download.html (incluye tshark) o define "
        "TSHARK_PATH apuntando al binario.",
        "tshark is not installed. Download Wireshark from "
        "https://www.wireshark.org/download.html (includes tshark) or set "
        "TSHARK_PATH to the binary.",
    )


def tshark_version(tshark_path: str) -> str:
    try:
        out = subprocess.run(
            [tshark_path, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        ).stdout
        return out.splitlines()[0].strip() if out else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def field(layers: dict, name: str, default: Optional[str] = None) -> Optional[str]:
    """First value of a tshark field from an ek 'layers' object."""
    value = layers.get(name.replace(".", "_"))
    if value is None:
        return default
    if isinstance(value, list):
        return str(value[0]) if value else default
    return str(value)


def field_bool(layers: dict, name: str) -> bool:
    return field(layers, name) in ("True", "true", "1")


def field_present(layers: dict, name: str) -> bool:
    return name.replace(".", "_") in layers


def iter_packets(
    tshark_path: str,
    pcap_path: str,
    timeout_s: Optional[int] = None,
    display_filter: Optional[str] = None,
    fields: Optional[List[str]] = None,
) -> Iterator[dict]:
    """Stream per-packet field dicts from a single tshark pass.

    ``display_filter`` limits the output to matching packets (tshark still
    dissects every packet in order, so TCP analysis stays correct). Closing the
    generator early kills tshark.
    """
    timeout_s = timeout_s or config.TSHARK_TIMEOUT_S
    cmd = [tshark_path, "-r", pcap_path, "-n", "-T", "ek"]
    if display_filter:
        cmd += ["-Y", display_filter]
    for name in (fields or FIELDS):
        cmd += ["-e", name]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + timeout_s
    stderr_parts: List[bytes] = []
    stdout_buffer = b""
    selector = selectors.DefaultSelector()
    try:
        assert proc.stdout is not None
        assert proc.stderr is not None
        selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
        selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TsharkTimeoutError(
                    tr("tshark excedió el tiempo máximo de análisis (%ds)", "tshark exceeded the maximum analysis time (%ds)") % timeout_s
                )
            for key, _ in selector.select(timeout=min(remaining, 0.25)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stderr":
                    # Keep a useful error message without allowing malformed input
                    # to consume unbounded memory.
                    if sum(map(len, stderr_parts)) < 8192:
                        stderr_parts.append(chunk)
                    continue
                stdout_buffer += chunk
                if len(stdout_buffer) > MAX_EK_LINE_BYTES and b"\n" not in stdout_buffer:
                    raise TsharkError(
                        tr("tshark devolvió una línea JSON superior al límite de 1 MiB.", "tshark returned a JSON line over the 1 MiB limit.")
                    )
                while b"\n" in stdout_buffer:
                    raw_line, stdout_buffer = stdout_buffer.split(b"\n", 1)
                    if len(raw_line) > MAX_EK_LINE_BYTES:
                        raise TsharkError(
                            tr("tshark devolvió una línea JSON superior al límite de 1 MiB.", "tshark returned a JSON line over the 1 MiB limit.")
                        )
                    line = raw_line.decode("utf-8", errors="replace")
                    if '"layers"' not in line:
                        continue
                    try:
                        doc = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    layers = doc.get("layers")
                    if isinstance(layers, dict):
                        yield layers
        returncode = proc.wait(timeout=max(0.1, deadline - time.monotonic()))
        if returncode != 0:
            raise TsharkError(
                tr("tshark terminó con código %d: %s", "tshark exited with code %d: %s") % (
                    returncode,
                    b"".join(stderr_parts).decode("utf-8", errors="replace").strip()[:500],
                )
            )
    finally:
        selector.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
