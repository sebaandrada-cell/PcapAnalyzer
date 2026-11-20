"""Security analysis: scans, cleartext logins, insecure protocols, ARP spoofing,
overlapping fragments. Issues name protocols and hosts, never credentials."""
from __future__ import annotations

import json

from app import config
from app.analysis.engine import CaptureState, _consume_packet
from app.detectors import (
    arp_spoofing,
    cleartext_credentials,
    insecure_protocols,
    ip_fragment_overlap,
    port_scan,
)

SCANNER, TARGET = "10.0.0.66", "10.0.0.10"


def _pkt(ts, src, dst, chain, **extra):
    layers = {
        "frame_time_epoch": [str(ts)],
        "frame_len": ["60"],
        "frame_protocols": [chain],
        "ip_src": [src], "ip_dst": [dst],
    }
    layers.update({key: [value] for key, value in extra.items()})
    return layers


def _syn(ts, src, dst, dport, sport=40000):
    return _pkt(ts, src, dst, "eth:ethertype:ip:tcp", tcp_srcport=str(sport),
                tcp_dstport=str(dport), tcp_flags_syn="True", tcp_flags_ack="False")


def _synack(ts, src, dst, sport, dport=40000):
    return _pkt(ts, src, dst, "eth:ethertype:ip:tcp", tcp_srcport=str(sport),
                tcp_dstport=str(dport), tcp_flags_syn="True", tcp_flags_ack="True")


def _rst(ts, src, dst, sport, dport=40000):
    return _pkt(ts, src, dst, "eth:ethertype:ip:tcp", tcp_srcport=str(sport),
                tcp_dstport=str(dport), tcp_flags_syn="False", tcp_flags_ack="True",
                tcp_flags_reset="True")


def _run(packets):
    state = CaptureState()
    for packet in packets:
        _consume_packet(state, packet)
    return state


def _dump(issues):
    return json.dumps([issue.model_dump() for issue in issues])


# --- port scans -------------------------------------------------------------

def test_vertical_port_scan():
    packets = []
    for port in range(1, config.SCAN_MIN_PORTS + 1):
        packets += [_syn(port, SCANNER, TARGET, port), _rst(port + 0.01, TARGET, SCANNER, port)]
    issues = port_scan.detect(_run(packets))
    assert [i.type for i in issues] == ["port_scan"]
    ev = issues[0].evidence
    assert ev["scanner"] == SCANNER and ev["kind"] == "ports"
    assert ev["target"] == TARGET and ev["probes"] == config.SCAN_MIN_PORTS
    assert ev["answered"] == 0
    assert issues[0].title_en and issues[0].detail_en


def test_horizontal_sweep():
    packets = [_syn(i, SCANNER, "10.0.1.%d" % i, 445) for i in range(1, config.SCAN_MIN_HOSTS + 1)]
    issues = port_scan.detect(_run(packets))
    assert [i.type for i in issues] == ["port_scan"]
    assert issues[0].evidence["kind"] == "hosts" and issues[0].evidence["port"] == 445


def test_browsing_many_answered_hosts_is_not_a_scan():
    packets = []
    for i in range(1, config.SCAN_MIN_HOSTS + 10):
        host = "198.51.100.%d" % i
        packets += [_syn(i, "10.0.0.5", host, 443), _synack(i + 0.01, host, "10.0.0.5", 443)]
    assert port_scan.detect(_run(packets)) == []


# --- cleartext credentials --------------------------------------------------

def test_ftp_login_in_cleartext_never_shows_the_password():
    packets = [
        _pkt(1, "10.0.0.5", "10.0.0.21", "eth:ethertype:ip:tcp:ftp",
             tcp_dstport="21", ftp_request_command="USER", ftp_request_arg="alice"),
        _pkt(2, "10.0.0.5", "10.0.0.21", "eth:ethertype:ip:tcp:ftp",
             tcp_dstport="21", ftp_request_command="PASS", ftp_request_arg="s3cr3t-pw"),
    ]
    issues = cleartext_credentials.detect(_run(packets))
    assert [i.type for i in issues] == ["cleartext_credentials"]
    ev = issues[0].evidence
    assert ev["protocol"] == "FTP" and ev["server"] == "10.0.0.21" and ev["logins"] == 1
    assert "s3cr3t-pw" not in _dump(issues) and "alice" not in _dump(issues)


def test_http_basic_auth_never_shows_the_credentials():
    packets = [_pkt(1, "10.0.0.5", "10.0.0.80", "eth:ethertype:ip:tcp:http", tcp_dstport="80",
                    http_authbasic="bob:hunter2", http_authorization="Basic Ym9iOmh1bnRlcjI=")]
    issues = cleartext_credentials.detect(_run(packets))
    assert [i.evidence["protocol"] for i in issues] == ["HTTP Basic"]
    assert "hunter2" not in _dump(issues) and "Ym9i" not in _dump(issues)


def test_pop_imap_smtp_logins():
    packets = [
        _pkt(1, "10.0.0.5", "10.0.0.110", "eth:ethertype:ip:tcp:pop", tcp_dstport="110",
             pop_request_command="PASS"),
        _pkt(2, "10.0.0.5", "10.0.0.143", "eth:ethertype:ip:tcp:imap", tcp_dstport="143",
             imap_request_command="LOGIN"),
        _pkt(3, "10.0.0.5", "10.0.0.25", "eth:ethertype:ip:tcp:smtp", tcp_dstport="25",
             smtp_req_command="AUTH"),
    ]
    protocols = sorted(i.evidence["protocol"] for i in cleartext_credentials.detect(_run(packets)))
    assert protocols == ["IMAP", "POP3", "SMTP"]


# --- insecure protocols -----------------------------------------------------

def test_telnet_smbv1_and_snmp_v2c_are_reported():
    packets = [
        _pkt(1, "10.0.0.5", "10.0.0.23", "eth:ethertype:ip:tcp:telnet", tcp_srcport="50000", tcp_dstport="23"),
        _pkt(2, "10.0.0.5", "10.0.0.45", "eth:ethertype:ip:tcp:nbss:smb", tcp_srcport="50001", tcp_dstport="445"),
        _pkt(3, "10.0.0.5", "10.0.0.161", "eth:ethertype:ip:udp:snmp", udp_srcport="50002",
             udp_dstport="161", snmp_version="1"),
    ]
    issues = insecure_protocols.detect(_run(packets))
    found = {(i.evidence["protocol"], tuple(i.evidence["servers"])) for i in issues}
    assert found == {("Telnet", ("10.0.0.23",)), ("SMBv1", ("10.0.0.45",)),
                     ("SNMP v2c", ("10.0.0.161",))}


def test_smb2_and_snmp_v3_are_fine():
    packets = [
        _pkt(1, "10.0.0.5", "10.0.0.45", "eth:ethertype:ip:tcp:nbss:smb2", tcp_dstport="445"),
        _pkt(2, "10.0.0.5", "10.0.0.161", "eth:ethertype:ip:udp:snmp", udp_dstport="161", snmp_version="3"),
    ]
    assert insecure_protocols.detect(_run(packets)) == []


# --- ARP spoofing -----------------------------------------------------------

def _arp(ts, ip, mac, opcode="2"):
    return {"frame_time_epoch": [str(ts)], "frame_len": ["60"], "frame_protocols": ["eth:ethertype:arp"],
            "arp_opcode": [opcode], "arp_src_proto_ipv4": [ip], "arp_src_hw_mac": [mac]}


def test_mac_claiming_a_contested_ip_and_others_is_spoofing():
    packets = [
        _arp(1, "10.0.0.1", "02:00:00:00:00:01"),   # real gateway
        _arp(2, "10.0.0.1", "02:00:00:00:00:66"),   # attacker claims the gateway
        _arp(3, "10.0.0.7", "02:00:00:00:00:66"),   # ... and a victim
        _arp(4, "10.0.0.7", "02:00:00:00:00:07"),   # real victim
    ]
    issues = arp_spoofing.detect(_run(packets))
    assert [i.type for i in issues] == ["arp_spoofing"]
    ev = issues[0].evidence
    assert ev["mac"] == "02:00:00:00:00:66"
    assert ev["contested_ips"] == ["10.0.0.1", "10.0.0.7"]


def test_router_with_many_uncontested_ips_is_fine():
    packets = [_arp(i, "10.0.%d.1" % i, "02:00:00:00:00:01", opcode="1") for i in range(1, 10)]
    assert arp_spoofing.detect(_run(packets)) == []


# --- overlapping fragments --------------------------------------------------

def test_conflicting_fragment_overlap_is_reported():
    packet = _pkt(1, "10.1.1.1", "129.111.30.27", "eth:ethertype:ip:udp", ip_flags_mf="False",
                  ip_frag_offset="3", ip_fragment_overlap="True", ip_fragment_overlap_conflict="True")
    issues = ip_fragment_overlap.detect(_run([packet]))
    assert [i.type for i in issues] == ["ip_fragment_overlap"]
    assert issues[0].evidence == {"source": "10.1.1.1", "destination": "129.111.30.27", "datagrams": 1}


def test_identical_overlap_without_conflict_is_ignored():
    packet = _pkt(1, "10.1.1.1", "10.0.0.2", "eth:ethertype:ip:udp",
                  ip_fragment_overlap="True", ip_fragment_overlap_conflict="False")
    assert ip_fragment_overlap.detect(_run([packet])) == []


def test_every_new_type_has_demo_next_steps():
    from app.llm.demo import _NEXT_STEP_BY_TYPE, _NEXT_STEP_BY_TYPE_EN
    for kind in ("port_scan", "cleartext_credentials", "insecure_protocol",
                 "arp_spoofing", "ip_fragment_overlap"):
        assert kind in _NEXT_STEP_BY_TYPE and kind in _NEXT_STEP_BY_TYPE_EN, kind


def test_netbios_browser_announcements_are_not_smbv1_use():
    # Windows "browser" announcements ride on SMB mailslots over UDP 138 to the
    # broadcast address: not file sharing over SMBv1.
    packet = _pkt(1, "192.168.2.16", "192.168.2.255", "eth:ethertype:ip:udp:nbdgm:smb:browser",
                  udp_srcport="138", udp_dstport="138")
    assert insecure_protocols.detect(_run([packet])) == []
