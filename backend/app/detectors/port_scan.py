"""Port scans: one source probing many ports of a host, or one port on many
hosts, with most probes left unanswered (RST or silence)."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set, Tuple

from .. import config
from ..models import Issue

_SAMPLE = 10


def _mostly_unanswered(probes: Dict[Tuple[str, int], bool], keys) -> Tuple[int, bool]:
    answered = sum(1 for key in keys if probes[key])
    return answered, 100.0 * answered / len(keys) <= config.SCAN_MAX_ANSWERED_PCT


def detect(state) -> List[Issue]:
    issues: List[Issue] = []
    for scanner, probes in state.security.syn_probes.items():
        by_host: Dict[str, Set[int]] = defaultdict(set)
        by_port: Dict[int, Set[str]] = defaultdict(set)
        for host, port in probes:
            by_host[host].add(port)
            by_port[port].add(host)

        for host, ports in sorted(by_host.items()):
            if len(ports) < config.SCAN_MIN_PORTS:
                continue
            answered, scan = _mostly_unanswered(probes, [(host, p) for p in ports])
            if scan:
                issues.append(_issue(scanner, "ports", len(ports), answered, target=host,
                                     sample=sorted(ports)[:_SAMPLE]))
        for port, hosts in sorted(by_port.items()):
            if len(hosts) < config.SCAN_MIN_HOSTS:
                continue
            answered, scan = _mostly_unanswered(probes, [(h, port) for h in hosts])
            if scan:
                issues.append(_issue(scanner, "hosts", len(hosts), answered, port=port,
                                     sample=sorted(hosts)[:_SAMPLE]))
    return issues


def _issue(scanner, kind, probes, answered, target=None, port=None, sample=()) -> Issue:
    if kind == "ports":
        what_es = "%d puertos de %s" % (probes, target)
        what_en = "%d ports on %s" % (probes, target)
    else:
        what_es = "el puerto %d en %d equipos" % (port, probes)
        what_en = "port %d on %d hosts" % (port, probes)
    evidence = {"scanner": scanner, "kind": kind, "probes": probes, "answered": answered,
                "sample": list(sample)}
    evidence.update({"target": target} if kind == "ports" else {"port": port})
    return Issue(
        id="port-scan-%s-%s-%s" % (scanner, kind, target or port),
        type="port_scan",
        severity="warning",
        title="Escaneo desde %s: %s" % (scanner, what_es),
        detail=(
            "%s intentó conectar con %s y solo %d respondieron (SYN-ACK). Es el patrón "
            "de un escaneo de puertos o un barrido de red: puede ser una herramienta "
            "de inventario o de seguridad legítima, o un equipo comprometido buscando "
            "servicios. Confirma quién es %s y si debe hacerlo."
            % (scanner, what_es, answered, scanner)
        ),
        title_en="Scan from %s: %s" % (scanner, what_en),
        detail_en=(
            "%s tried to connect to %s and only %d answered (SYN-ACK). This is the "
            "pattern of a port scan or network sweep: it may be a legitimate inventory "
            "or security tool, or a compromised host looking for services. Confirm "
            "who %s is and whether it should be doing this."
            % (scanner, what_en, answered, scanner)
        ),
        conversation=scanner,
        evidence=evidence,
    )
