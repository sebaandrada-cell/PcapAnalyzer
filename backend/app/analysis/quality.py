"""Capture quality: what the capture itself cannot show, assessed first.

A network problem and a capture artefact look alike in the packet list. A port
mirror that copies ingress and egress shows every frame twice, which Wireshark
flags as retransmissions; a capture that sees one direction makes every
request look unanswered. These checks describe the capture, not the network,
so the findings can be read with the right amount of trust.
"""
from __future__ import annotations

from collections import OrderedDict
from typing import List, Optional, Tuple

from .. import config
from ..models import CaptureQuality, Issue, QualityNote
from ..tshark import field as fget

# Findings that mean "the other side never answered": not trustworthy when the
# capture only sees one direction of the traffic.
NO_RESPONSE_TYPES = frozenset({"dns_unanswered", "ike_no_response", "esp_one_way"})

_ONE_WAY_CAVEAT = (
    " Ojo: la captura solo ve un solo sentido del tráfico en la mayoría de las "
    "conversaciones, así que la respuesta pudo existir y no haberse capturado."
)
_ONE_WAY_CAVEAT_EN = (
    " Caution: the capture only sees one direction of most conversations, so "
    "the answer may have existed and simply not been captured."
)


def _nonzero_id(value: Optional[str]) -> bool:
    try:
        return value is not None and int(value, 0) != 0
    except ValueError:
        return False


def duplicate_key(layers: dict, chain: List[str], src: Optional[str],
                  dst: Optional[str]) -> Optional[Tuple]:
    """Identity of a frame on the wire, or None when it cannot be established.

    TCP segments are identified by their header (sequence, ACK, flags, window,
    timestamp and SACK edges), which also works for IPv6 and for stacks that
    send IP ID 0. Anything else needs a non-zero IPv4 ID.
    """
    if not src or not dst or "icmp" in chain or "icmpv6" in chain:
        return None  # ICMP errors quote another packet's fields
    ip_id = fget(layers, "ip.id")
    strong = _nonzero_id(ip_id)
    frag = fget(layers, "ip.frag_offset") or "0"
    if fget(layers, "tcp.srcport") is not None:
        sack = layers.get("tcp_options_sack_re")
        return (
            src, dst, ip_id if strong else "", frag, "tcp",
            fget(layers, "tcp.srcport"), fget(layers, "tcp.dstport"),
            fget(layers, "tcp.seq"), fget(layers, "tcp.ack"), fget(layers, "tcp.len"),
            fget(layers, "tcp.flags.syn"), fget(layers, "tcp.flags.ack"),
            fget(layers, "tcp.flags.fin"), fget(layers, "tcp.flags.reset"),
            fget(layers, "tcp.flags.push"), fget(layers, "tcp.window_size"),
            fget(layers, "tcp.options.timestamp.tsval"),
            tuple(sack) if isinstance(sack, list) else sack,
        )
    if strong:
        return (
            src, dst, ip_id, frag, fget(layers, "ip.proto"),
            fget(layers, "udp.srcport"), fget(layers, "udp.dstport"),
            fget(layers, "frame.len"),
        )
    return None


def is_duplicate(recent: "OrderedDict[Tuple, float]", key: Optional[Tuple], ts: float) -> bool:
    """True when ``key`` was seen within the duplicate window; remembers it otherwise."""
    if key is None:
        return False
    previous = recent.get(key)
    if previous is not None and 0 <= ts - previous <= config.DUP_FRAME_WINDOW_S:
        return True
    recent[key] = ts
    recent.move_to_end(key)
    if len(recent) > config.DUP_FRAME_TRACK:
        recent.popitem(last=False)
    return False


def _pct(part: int, whole: int) -> float:
    return round(100.0 * part / whole, 1) if whole else 0.0


def build_capture_quality(state) -> CaptureQuality:
    notes: List[QualityNote] = []

    dup_pct = _pct(state.duplicate_frames, state.packets)
    if state.duplicate_frames:
        notes.append(QualityNote(
            code="duplicate_frames",
            severity="warning" if dup_pct >= config.QUALITY_DUP_WARN_PCT else "info",
            title="Tramas duplicadas en la captura (%s%%)" % dup_pct,
            detail=(
                "%d de %d tramas son copias exactas de otra vista menos de %g ms antes. "
                "Es lo que produce un port mirror que copia entrada y salida, o capturar "
                "en varias interfaces a la vez. Se dejan fuera del análisis para que no "
                "aparezcan como retransmisiones ni ACK duplicados; los totales de la "
                "captura sí las cuentan."
                % (state.duplicate_frames, state.packets, config.DUP_FRAME_WINDOW_S * 1000)
            ),
            title_en="Duplicate frames in the capture (%s%%)" % dup_pct,
            detail_en=(
                "%d of %d frames are exact copies of one seen less than %g ms earlier. "
                "This is what a port mirror copying ingress and egress produces, or "
                "capturing on several interfaces at once. They are left out of the "
                "analysis so they do not show up as retransmissions or duplicate ACKs; "
                "the capture totals still count them."
                % (state.duplicate_frames, state.packets, config.DUP_FRAME_WINDOW_S * 1000)
            ),
        ))

    relevant = [conv for conv in state.tcp_convs.values()
                if conv.packets >= config.QUALITY_MIN_CONV_PACKETS]
    checked = [conv for conv in relevant if conv.ack_seen]
    one_way = [conv for conv in checked if conv.bytes_fwd == 0 or conv.bytes_rev == 0]
    one_way_pct = _pct(len(one_way), len(checked))
    if len(one_way) >= config.QUALITY_ONE_WAY_MIN_CONVS and \
            one_way_pct >= config.QUALITY_ONE_WAY_INFO_PCT:
        mostly = one_way_pct >= config.QUALITY_ONE_WAY_WARN_PCT
        notes.append(QualityNote(
            code="one_way",
            severity="warning" if mostly else "info",
            title=("La captura solo ve un sentido del tráfico" if mostly
                   else "Parte del tráfico solo se ve en un sentido"),
            detail=(
                "En %d de %d conversaciones TCP un lado confirma datos que no están en "
                "la captura (%s%%). %s"
                % (len(one_way), len(checked), one_way_pct,
                   "Faltan las respuestas: los avisos de tipo «sin respuesta» no son "
                   "fiables y las latencias no se pueden medir. Revisa el punto de "
                   "captura (mirror de un solo sentido, rutas asimétricas)." if mostly else
                   "Suele deberse a rutas asimétricas o a un mirror que no cubre todos "
                   "los enlaces; esas conversaciones se analizan con datos incompletos.")
            ),
            title_en=("The capture only sees one direction of the traffic" if mostly
                      else "Part of the traffic is only seen in one direction"),
            detail_en=(
                "In %d of %d TCP conversations one side acknowledges data that is not in "
                "the capture (%s%%). %s"
                % (len(one_way), len(checked), one_way_pct,
                   "The answers are missing: \"no response\" findings are not reliable "
                   "and latencies cannot be measured. Check the capture point (one-way "
                   "mirror, asymmetric routing)." if mostly else
                   "Usually asymmetric routing or a mirror that does not cover every "
                   "link; those conversations are analysed with incomplete data.")
            ),
        ))

    if state.truncated_frames:
        notes.append(QualityNote(
            code="truncated_frames",
            severity="warning",
            title="Tramas recortadas al capturar (%d)" % state.truncated_frames,
            detail=(
                "%d tramas se guardaron incompletas (límite de bytes por paquete, "
                "«snaplen»). Las cabeceras suelen estar, pero HTTP, TLS o DNS pueden "
                "salir a medias o no reconocerse." % state.truncated_frames
            ),
            title_en="Frames cut short at capture time (%d)" % state.truncated_frames,
            detail_en=(
                "%d frames were stored incomplete (per-packet byte limit, \"snaplen\"). "
                "Headers are usually there, but HTTP, TLS or DNS may be partial or go "
                "unrecognised." % state.truncated_frames
            ),
        ))

    midstream = [conv for conv in relevant if conv.syn_ts is None and not conv.synack_seen]
    midstream_pct = _pct(len(midstream), len(relevant))
    if midstream and midstream_pct >= config.QUALITY_MIDSTREAM_INFO_PCT:
        notes.append(QualityNote(
            code="midstream",
            severity="info",
            title="Conexiones ya abiertas al empezar la captura",
            detail=(
                "%d de %d conversaciones TCP no incluyen su inicio (%s%%). Para ellas no "
                "hay MSS negociado, escalado de ventana ni tiempo de establecimiento, y "
                "los tamaños de ventana pueden verse más pequeños de lo real."
                % (len(midstream), len(relevant), midstream_pct)
            ),
            title_en="Connections already open when the capture started",
            detail_en=(
                "%d of %d TCP conversations do not include their start (%s%%). For those "
                "there is no negotiated MSS, window scaling or setup time, and window "
                "sizes may look smaller than they really are."
                % (len(midstream), len(relevant), midstream_pct)
            ),
        ))

    if state.skipped_packets:
        notes.append(QualityNote(
            code="malformed_packets",
            severity="warning",
            title="Paquetes ilegibles omitidos (%d)" % state.skipped_packets,
            detail=(
                "%d paquetes tenían campos que no se pudieron interpretar y quedaron "
                "fuera del análisis. Puede ser una captura dañada o cortada."
                % state.skipped_packets
            ),
            title_en="Unreadable packets skipped (%d)" % state.skipped_packets,
            detail_en=(
                "%d packets had fields that could not be parsed and were left out of "
                "the analysis. The capture may be damaged or cut short."
                % state.skipped_packets
            ),
        ))

    severities = {note.severity for note in notes}
    return CaptureQuality(
        verdict="poor" if "warning" in severities else "fair" if notes else "good",
        duplicate_frames=state.duplicate_frames,
        duplicate_pct=dup_pct,
        truncated_frames=state.truncated_frames,
        tcp_conversations_checked=len(checked),
        one_way_conversations=len(one_way),
        midstream_conversations=len(midstream),
        skipped_packets=state.skipped_packets,
        notes=notes,
    )


def apply_quality_caveats(issues: List[Issue], quality: CaptureQuality) -> List[Issue]:
    """Lower the weight of findings the capture cannot support."""
    one_way = any(note.code == "one_way" and note.severity == "warning"
                  for note in quality.notes)
    if not one_way:
        return issues
    out: List[Issue] = []
    for issue in issues:
        if issue.type in NO_RESPONSE_TYPES:
            issue = issue.model_copy(update={
                "severity": "info",
                "detail": issue.detail + _ONE_WAY_CAVEAT,
                "detail_en": (issue.detail_en or issue.detail) + _ONE_WAY_CAVEAT_EN,
                "evidence": dict(issue.evidence, capture_one_way=True),
            })
        out.append(issue)
    return out
