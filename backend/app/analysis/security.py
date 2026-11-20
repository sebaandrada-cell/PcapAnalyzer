"""Security signals gathered during the single pass over the capture.

Privacy: credentials and payloads are never stored. A login is recorded as
"protocol + server + client" only; the command or header that carries the
secret is checked for presence and then dropped.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .. import config
from ..tshark import field as fget
from ..tshark import field_bool

# Requests that carry a login in clear text: (tshark field, values) -> label.
_LOGIN_COMMANDS: List[Tuple[str, Set[str], str]] = [
    ("ftp.request.command", {"PASS"}, "FTP"),
    ("pop.request.command", {"PASS"}, "POP3"),
    ("imap.request.command", {"LOGIN", "AUTHENTICATE"}, "IMAP"),
    ("smtp.req.command", {"AUTH"}, "SMTP"),
]

# Insecure protocols by their tshark protocol token (exact chain element).
# SMB2/3 dissect as "smb2"; "smb" is SMBv1.
_INSECURE_TOKENS = {"telnet": "Telnet", "smb": "SMBv1"}
_SNMP_VERSIONS = {"0": "SNMP v1", "1": "SNMP v2c"}
_WELL_KNOWN_PORTS = {"Telnet": {23}, "SMBv1": {139, 445}, "SNMP v1": {161, 162},
                     "SNMP v2c": {161, 162}}


@dataclass
class LoginUse:
    count: int = 0
    clients: Set[str] = field(default_factory=set)


@dataclass
class InsecureUse:
    packets: int = 0
    servers: Set[str] = field(default_factory=set)
    clients: Set[str] = field(default_factory=set)


@dataclass
class SecurityState:
    # scanner -> {(target, port): answered with SYN-ACK}
    syn_probes: Dict[str, Dict[Tuple[str, int], bool]] = field(default_factory=dict)
    logins: Dict[Tuple[str, str], LoginUse] = field(default_factory=dict)  # (protocol, server)
    insecure: Dict[str, InsecureUse] = field(default_factory=dict)        # protocol label
    overlaps: Dict[Tuple[str, str], int] = field(default_factory=dict)     # (src, dst) -> datagrams
    truncated: bool = False


def _int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def track(sec: SecurityState, layers: dict, chain: List[str],
          src: Optional[str], dst: Optional[str]) -> None:
    if not (src and dst):
        return
    _track_syn(sec, layers, src, dst)
    _track_login(sec, layers, src, dst)
    _track_insecure(sec, layers, chain, src, dst)
    if field_bool(layers, "ip.fragment.overlap.conflict"):
        key = (src, dst)
        if key in sec.overlaps or len(sec.overlaps) < config.MAX_SECURITY_ENTRIES:
            sec.overlaps[key] = sec.overlaps.get(key, 0) + 1
        else:
            sec.truncated = True


def _track_syn(sec: SecurityState, layers: dict, src: str, dst: str) -> None:
    if not field_bool(layers, "tcp.flags.syn"):
        return
    if field_bool(layers, "tcp.flags.ack"):
        # SYN-ACK from dst's target back to the prober.
        probes = sec.syn_probes.get(dst)
        port = _int(fget(layers, "tcp.srcport"))
        if probes is not None and port is not None and (src, port) in probes:
            probes[(src, port)] = True
        return
    port = _int(fget(layers, "tcp.dstport"))
    if port is None:
        return
    probes = sec.syn_probes.get(src)
    if probes is None:
        if len(sec.syn_probes) >= config.MAX_SECURITY_ENTRIES:
            sec.truncated = True
            return
        probes = sec.syn_probes[src] = {}
    if (dst, port) not in probes:
        if len(probes) >= config.MAX_SCAN_PROBES_PER_SOURCE:
            sec.truncated = True
            return
        probes[(dst, port)] = False


def _track_login(sec: SecurityState, layers: dict, src: str, dst: str) -> None:
    protocol = None
    for field_name, commands, label in _LOGIN_COMMANDS:
        command = fget(layers, field_name)
        if command and command.strip().upper() in commands:
            protocol = label
            break
    if protocol is None and (fget(layers, "http.authbasic")
                             or (fget(layers, "http.authorization") or "").lower().startswith("basic ")):
        protocol = "HTTP Basic"
    if protocol is None:
        return
    key = (protocol, dst)
    use = sec.logins.get(key)
    if use is None:
        if len(sec.logins) >= config.MAX_SECURITY_ENTRIES:
            sec.truncated = True
            return
        use = sec.logins[key] = LoginUse()
    use.count += 1
    if len(use.clients) < config.MAX_SECURITY_HOSTS_LISTED:
        use.clients.add(src)


def _track_insecure(sec: SecurityState, layers: dict, chain: List[str], src: str, dst: str) -> None:
    label = next((_INSECURE_TOKENS[token] for token in chain if token in _INSECURE_TOKENS), None)
    if label == "SMBv1" and "tcp" not in chain:
        label = None  # NetBIOS browser announcements (UDP 138 mailslots), not file sharing
    if label is None and "snmp" in chain:
        label = _SNMP_VERSIONS.get(fget(layers, "snmp.version") or "")
    if label is None:
        return
    ports = _WELL_KNOWN_PORTS[label]
    sport = _int(fget(layers, "tcp.srcport") or fget(layers, "udp.srcport"))
    server, client = (src, dst) if sport in ports else (dst, src)
    use = sec.insecure.setdefault(label, InsecureUse())
    use.packets += 1
    if len(use.servers) < config.MAX_SECURITY_HOSTS_LISTED:
        use.servers.add(server)
    if len(use.clients) < config.MAX_SECURITY_HOSTS_LISTED:
        use.clients.add(client)
