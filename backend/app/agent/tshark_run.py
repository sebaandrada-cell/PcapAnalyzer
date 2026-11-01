"""Run tshark for the agent tools: argument lists only, bounded time and output."""
from __future__ import annotations

import subprocess
from typing import List, Optional

from .. import config
from ..tshark import find_tshark


class ToolError(Exception):
    """tshark failed or rejected the request; the message is safe to show the model."""


class ToolTimeout(ToolError):
    """tshark exceeded the per-tool time budget."""


_MAX_FILTER_LEN = 2000


def run_tshark(
    args: List[str],
    timeout_s: Optional[int] = None,
    max_bytes: Optional[int] = None,
) -> str:
    """Execute tshark with ``args`` and return its stdout as text.

    ``-n`` (no name resolution) is added to every capture read. The output is
    cut at ``max_bytes`` (callers shape it further); stderr's tail becomes the
    error message on a non-zero exit.
    """
    timeout_s = timeout_s or config.TOOL_TIMEOUT_S
    max_bytes = max_bytes or config.TOOL_MAX_OUTPUT_BYTES * 4
    tshark = find_tshark()
    if tshark is None:
        raise ToolError("tshark no está disponible.")
    cmd = [tshark]
    if "-r" in args:
        cmd.append("-n")
    cmd += list(args)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        raise ToolTimeout("tshark excedió el tiempo máximo (%ds)." % timeout_s)
    except OSError as exc:
        raise ToolError("No se pudo ejecutar tshark: %s" % exc)
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise ToolError(tail[-1] if tail else "tshark terminó con error %d." % proc.returncode)
    return proc.stdout[:max_bytes].decode("utf-8", "replace")


def validate_filter(pcap_path: str, display_filter: str) -> None:
    """Raise ToolError unless tshark accepts ``display_filter``."""
    if len(display_filter) > _MAX_FILTER_LEN:
        raise ToolError("Filtro no válido: demasiado largo (máximo %d caracteres)." % _MAX_FILTER_LEN)
    if any(ch in display_filter for ch in "\n\r\x00"):
        raise ToolError("Filtro no válido: no se admiten saltos de línea.")
    try:
        run_tshark([
            "-r", pcap_path, "-Y", display_filter, "-c", "1",
            "-T", "fields", "-e", "frame.number",
        ])
    except ToolTimeout:
        raise
    except ToolError as exc:
        raise ToolError("Filtro no válido: %s" % exc)
