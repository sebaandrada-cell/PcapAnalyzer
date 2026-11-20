"""Run tshark for the agent tools: argument lists only, bounded time and output."""
from __future__ import annotations

import os
import selectors
import subprocess
import time
from typing import List, Optional, Tuple

from .. import config
from ..tshark import find_tshark
from ..i18n import tr


class ToolError(Exception):
    """tshark failed or rejected the request; the message is safe to show the model."""


class ToolTimeout(ToolError):
    """tshark exceeded the per-tool time budget."""


_MAX_FILTER_LEN = 2000


_STDERR_CAP = 8192


def run_tshark_bounded(
    args: List[str],
    timeout_s: Optional[int] = None,
    max_bytes: Optional[int] = None,
) -> Tuple[str, bool]:
    """Execute tshark and return ``(stdout_text, truncated)``.

    stdout is read incrementally and the process is killed as soon as
    ``max_bytes`` have been collected, so a huge result never sits in RAM.
    ``-n`` (no name resolution) is added to every capture read. On a non-zero
    exit (of a process we did not kill) stderr's last line is the error.
    """
    timeout_s = timeout_s or config.TOOL_TIMEOUT_S
    max_bytes = max_bytes or config.TOOL_MAX_OUTPUT_BYTES * 4
    tshark = find_tshark()
    if tshark is None:
        raise ToolError(tr("tshark no está disponible.", "tshark is not available."))
    cmd = [tshark]
    if "-r" in args:
        cmd.append("-n")
    cmd += list(args)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        raise ToolError(tr("No se pudo ejecutar tshark: %s", "Could not run tshark: %s") % exc)
    assert proc.stdout is not None and proc.stderr is not None
    out_parts: List[bytes] = []
    err_parts: List[bytes] = []
    total = 0
    truncated = False
    deadline = time.monotonic() + timeout_s
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, "out")
    selector.register(proc.stderr, selectors.EVENT_READ, "err")
    try:
        while selector.get_map() and not truncated:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                proc.wait()
                raise ToolTimeout("tshark excedió el tiempo máximo (%ds)." % timeout_s)
            for key, _ in selector.select(timeout=min(remaining, 0.25)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "err":
                    if sum(map(len, err_parts)) < _STDERR_CAP:
                        err_parts.append(chunk)
                    continue
                room = max_bytes - total
                if len(chunk) >= room:
                    out_parts.append(chunk[:room])
                    total += room
                    truncated = True
                    break
                out_parts.append(chunk)
                total += len(chunk)
        if truncated:
            proc.kill()
        proc.wait(timeout=max(1, int(deadline - time.monotonic())) if not truncated else 10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise ToolTimeout("tshark excedió el tiempo máximo (%ds)." % timeout_s)
    finally:
        selector.close()
        proc.stdout.close()
        proc.stderr.close()
    if not truncated and proc.returncode != 0:
        lines = [ln.strip() for ln in
                 b"".join(err_parts).decode("utf-8", "replace").strip().splitlines() if ln.strip()]
        # tshark prints the reason on a "tshark: ..." line, then the filter and a
        # caret line pointing at the error; the reason is what helps.
        reason = next((ln for ln in lines if ln.startswith("tshark:")), lines[-1] if lines else "")
        raise ToolError(reason or "tshark terminó con error %d." % proc.returncode)
    return b"".join(out_parts).decode("utf-8", "replace"), truncated


def run_tshark(
    args: List[str],
    timeout_s: Optional[int] = None,
    max_bytes: Optional[int] = None,
) -> str:
    """``run_tshark_bounded`` for callers that only need the (bounded) text."""
    return run_tshark_bounded(args, timeout_s=timeout_s, max_bytes=max_bytes)[0]


def validate_filter(pcap_path: str, display_filter: str) -> None:
    """Raise ToolError unless tshark accepts ``display_filter``."""
    if len(display_filter) > _MAX_FILTER_LEN:
        raise ToolError(tr("Filtro no válido: demasiado largo (máximo %d caracteres).", "Invalid filter: too long (maximum %d characters).") % _MAX_FILTER_LEN)
    if any(ch in display_filter for ch in "\n\r\x00"):
        raise ToolError(tr("Filtro no válido: no se admiten saltos de línea.", "Invalid filter: line breaks are not allowed."))
    try:
        run_tshark([
            "-r", pcap_path, "-Y", display_filter, "-c", "1",
            "-T", "fields", "-e", "frame.number",
        ])
    except ToolTimeout:
        raise
    except ToolError as exc:
        raise ToolError(tr("Filtro no válido: %s", "Invalid filter: %s") % exc)
