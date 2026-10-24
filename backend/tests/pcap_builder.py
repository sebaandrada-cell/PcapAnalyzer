"""Deterministic sample pcap generator (no external deps).

Crafts raw Ethernet/IPv4/TCP/UDP packets with struct and writes a classic
libpcap file. The generated capture exercises every detector in the analysis
engine:

  * TCP stream 0 (10.0.0.1:34567 -> 10.0.0.2:80): handshake, HTTP GET,
    2 retransmissions of the same segment, a zero-window ACK from the server,
    a window update and an HTTP 200 response.
  * TCP stream 1 (10.0.0.1:34568 -> 10.0.0.3:8443): SYN answered immediately
    with RST (firewall / closed-port pattern), no SYN-ACK ever seen.
  * TCP stream 2 (10.0.0.1:34569 -> 10.0.0.2:443): handshake followed by a
    fatal TLS alert handshake_failure (level 2, description 40) from the server.
  * DNS over UDP to 10.0.0.53: one fast query/response (20 ms), one slow
    query/response (700 ms) and one query that never gets a response.
  * TCP stream 3 (:8080): MSS 1240 negotiated, then a full-size segment
    retransmitted 3x with no ICMP feedback (mss_low + PMTUD black hole).
  * TCP stream 4 (:9090): 600 ms SYN -> SYN-ACK handshake.
  * ICMP Fragmentation Needed from 10.0.0.254 (path MTU 1400).
  * One fully fragmented UDP datagram + one missing its last fragment.
  * One-way ESP and unanswered IKE towards 10.0.0.6; bidirectional IKE with
    no ESP towards 10.0.0.7.
  * DNS errors: one SERVFAIL and three NXDOMAIN responses.
  * Gratuitous ARP: 10.0.0.99 claimed by two different MACs (duplicate IP).
"""
from __future__ import annotations

import struct

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
BLOCKED = "10.0.0.3"
ICMP_TARGET = "10.0.0.5"
VPN_GW_DEAD = "10.0.0.6"      # IKE unanswered + one-way ESP
VPN_GW_HALF = "10.0.0.7"      # IKE completes but no ESP follows
ROUTER = "10.0.0.254"
DNS_SERVER = "10.0.0.53"
DUP_IP = "10.0.0.99"          # claimed by two different MACs via ARP

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")
MAC_DUP_1 = bytes.fromhex("02000000000a")
MAC_DUP_2 = bytes.fromhex("02000000000b")
MAC_BCAST = b"\xff" * 6

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ip(addr: str) -> bytes:
    return bytes(int(part) for part in addr.split("."))


def ipv4(src: str, dst: str, proto: int, payload: bytes,
         ip_id: int = 0x1234, flags_frag: int = 0x4000) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(payload), ip_id, flags_frag, 64, proto, 0,
        _ip(src), _ip(dst),
    )
    csum = _checksum(header)
    return header[:10] + struct.pack("!H", csum) + header[12:] + payload


def mss_option(mss: int) -> bytes:
    return b"\x02\x04" + struct.pack("!H", mss)


def tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
        flags: int, window: int = 65535, payload: bytes = b"",
        options: bytes = b"") -> bytes:
    if len(options) % 4:
        options += b"\x01" * (4 - len(options) % 4)  # NOP padding
    offset = 5 + len(options) // 4
    header = struct.pack(
        "!HHIIBBHHH", sport, dport, seq, ack, offset << 4, flags, window, 0, 0
    ) + options
    pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    csum = _checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", csum) + header[18:]
    return ipv4(src, dst, 6, header + payload)


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return ipv4(src, dst, 17, header + payload)


def dhcp(msg_type: int, xid: int, mac: bytes, yiaddr: str = "0.0.0.0",
         server_id: str = None, hostname: str = None, reply: bool = False) -> bytes:
    """Minimal BOOTP/DHCP payload (message type, optional server id/hostname)."""
    fixed = struct.pack("!BBBBIHH", 2 if reply else 1, 1, 6, 0, xid, 0, 0)
    fixed += _ip("0.0.0.0") + _ip(yiaddr) + _ip("0.0.0.0") + _ip("0.0.0.0")
    fixed += mac + b"\x00" * 10 + b"\x00" * 64 + b"\x00" * 128
    options = b"\x63\x82\x53\x63" + bytes([53, 1, msg_type])
    if hostname:
        options += bytes([12, len(hostname)]) + hostname.encode()
    if server_id:
        options += bytes([54, 4]) + _ip(server_id)
    return fixed + options + b"\xff"


def _dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_query(txid: int, name: str) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + _dns_name(name) + struct.pack("!HH", 1, 1)


def dns_response(txid: int, name: str, addr: str = None, rcode: int = 0) -> bytes:
    question = _dns_name(name) + struct.pack("!HH", 1, 1)
    ancount = 1 if addr else 0
    body = struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, ancount, 0, 0) + question
    if addr:
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + _ip(addr)
    return body


def icmp_frag_needed(src: str, dst: str, mtu: int,
                     orig_src: str, orig_dst: str) -> bytes:
    """ICMP type 3 code 4 (Fragmentation Needed) quoting the original packet."""
    orig = ipv4(orig_src, orig_dst, 17, struct.pack("!HHHH", 40000, 9999, 1508, 0))
    icmp = struct.pack("!BBHHH", 3, 4, 0, 0, mtu) + orig[:28]
    csum = _checksum(icmp)
    icmp = icmp[:2] + struct.pack("!H", csum) + icmp[4:]
    return ipv4(src, dst, 1, icmp)


def icmp_error(src: str, dst: str, icmp_type: int, code: int,
               orig_src: str, orig_dst: str, orig_proto: int = 17) -> bytes:
    """Generic ICMP error (dest unreachable, time exceeded...) quoting the
    first 28 bytes of the offending datagram, as routers and hosts do."""
    if orig_proto == 17:
        inner = struct.pack("!HHHH", 40000, 9999, 20, 0)
    else:
        inner = struct.pack("!HHII", 40000, 80, 1, 0)
    orig = ipv4(orig_src, orig_dst, orig_proto, inner)
    icmp = struct.pack("!BBHI", icmp_type, code, 0, 0) + orig[:28]
    csum = _checksum(icmp)
    icmp = icmp[:2] + struct.pack("!H", csum) + icmp[4:]
    return ipv4(src, dst, 1, icmp)


def esp(src: str, dst: str, spi: int, seq: int) -> bytes:
    return ipv4(src, dst, 50, struct.pack("!II", spi, seq) + b"\xaa" * 40)


def ike_sa_init(ispi: bytes, rspi: bytes = b"\x00" * 8, response: bool = False) -> bytes:
    """Minimal IKEv2 IKE_SA_INIT header (no payloads)."""
    flags = 0x20 if response else 0x08  # response / initiator
    return ispi + rspi + struct.pack("!BBBBII", 0, 0x20, 34, flags, 0, 28)


def arp_announce(sender_mac: bytes, sender_ip: str) -> bytes:
    """Gratuitous ARP reply claiming sender_ip."""
    payload = (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        + sender_mac + _ip(sender_ip)
        + MAC_BCAST + _ip(sender_ip)
    )
    return MAC_BCAST + sender_mac + b"\x08\x06" + payload


def udp_fragments(src: str, dst: str, sport: int, dport: int,
                  data_len: int, ip_id: int, drop_last: bool = False):
    """Return the IPv4 fragments of one oversized UDP datagram."""
    data = b"z" * data_len
    udp_packet = struct.pack("!HHHH", sport, dport, 8 + data_len, 0) + data
    frags = []
    offset = 0
    while offset < len(udp_packet):
        chunk = udp_packet[offset:offset + 1480]
        last = offset + len(chunk) >= len(udp_packet)
        flags_frag = (0 if last else 0x2000) | (offset // 8)
        frags.append(ipv4(src, dst, 17, chunk, ip_id=ip_id, flags_frag=flags_frag))
        offset += len(chunk)
    return frags[:-1] if drop_last else frags


TLS_ALERT_HANDSHAKE_FAILURE = b"\x15\x03\x03\x00\x02\x02\x28"  # fatal (2), handshake_failure (40)


def tls_client_hello() -> bytes:
    """Minimal valid ClientHello so the TLS dissector locks onto the stream."""
    body = (
        b"\x03\x03" + bytes(32)      # client_version + random
        + b"\x00"                     # session_id length
        + b"\x00\x02\x00\x2f"        # one cipher suite
        + b"\x01\x00"                # null compression
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


HTTP_PAYLOAD = (
    b"GET / HTTP/1.1\r\nHost: server.example\r\nUser-Agent: sample\r\n"
    b"Accept: */*\r\n\r\n" + b"x" * 24
)


def build_sample_packets():
    """Return a list of (timestamp, raw_ethernet_frame) tuples."""

    def a2b(payload: bytes) -> bytes:  # frame client -> anywhere
        return MAC_B + MAC_A + b"\x08\x00" + payload

    def b2a(payload: bytes) -> bytes:  # frame server -> client
        return MAC_A + MAC_B + b"\x08\x00" + payload

    pkts = []

    # --- Stream 0: HTTP with retransmissions + zero window ---------------
    sp, dp, isn_a, isn_b = 34567, 80, 1000, 5000
    pkts.append((0.000, a2b(tcp(CLIENT, SERVER, sp, dp, isn_a, 0, SYN))))
    pkts.append((0.010, b2a(tcp(SERVER, CLIENT, dp, sp, isn_b, isn_a + 1, SYN | ACK))))
    pkts.append((0.020, a2b(tcp(CLIENT, SERVER, sp, dp, isn_a + 1, isn_b + 1, ACK))))
    data = tcp(CLIENT, SERVER, sp, dp, isn_a + 1, isn_b + 1, PSH | ACK, payload=HTTP_PAYLOAD)
    pkts.append((0.030, a2b(data)))
    pkts.append((0.230, a2b(data)))  # retransmission 1
    pkts.append((0.430, a2b(data)))  # retransmission 2
    ack_num = isn_a + 1 + len(HTTP_PAYLOAD)
    pkts.append((0.440, b2a(tcp(SERVER, CLIENT, dp, sp, isn_b + 1, ack_num, ACK, window=0))))  # zero window
    pkts.append((0.500, b2a(tcp(SERVER, CLIENT, dp, sp, isn_b + 1, ack_num, ACK, window=65535))))  # window update
    http_response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
    )
    pkts.append((0.550, b2a(tcp(SERVER, CLIENT, dp, sp, isn_b + 1, ack_num, PSH | ACK,
                                payload=http_response))))

    # --- Stream 1: SYN -> immediate RST (firewall pattern) ---------------
    pkts.append((1.000, a2b(tcp(CLIENT, BLOCKED, 34568, 8443, 3000, 0, SYN))))
    pkts.append((1.005, b2a(tcp(BLOCKED, CLIENT, 8443, 34568, 0, 3001, RST | ACK))))

    # --- Stream 2: TLS fatal handshake_failure alert ---------------------
    sp, isn_a, isn_b = 34569, 2000, 6000
    pkts.append((2.000, a2b(tcp(CLIENT, SERVER, sp, 443, isn_a, 0, SYN))))
    pkts.append((2.010, b2a(tcp(SERVER, CLIENT, 443, sp, isn_b, isn_a + 1, SYN | ACK))))
    pkts.append((2.020, a2b(tcp(CLIENT, SERVER, sp, 443, isn_a + 1, isn_b + 1, ACK))))
    hello = tls_client_hello()
    pkts.append((2.030, a2b(tcp(CLIENT, SERVER, sp, 443, isn_a + 1, isn_b + 1, PSH | ACK, payload=hello))))
    pkts.append((2.050, b2a(tcp(SERVER, CLIENT, 443, sp, isn_b + 1, isn_a + 1 + len(hello), PSH | ACK,
                                payload=TLS_ALERT_HANDSHAKE_FAILURE))))

    # --- DNS: fast, slow (>500 ms) and unanswered -------------------------
    pkts.append((3.000, a2b(udp(CLIENT, DNS_SERVER, 53001, 53, dns_query(0x1111, "fast.example.com")))))
    pkts.append((3.020, b2a(udp(DNS_SERVER, CLIENT, 53, 53001, dns_response(0x1111, "fast.example.com", "93.184.216.34")))))
    pkts.append((4.000, a2b(udp(CLIENT, DNS_SERVER, 53002, 53, dns_query(0x2222, "slow.example.com")))))
    pkts.append((4.700, b2a(udp(DNS_SERVER, CLIENT, 53, 53002, dns_response(0x2222, "slow.example.com", "93.184.216.35")))))
    pkts.append((5.000, a2b(udp(CLIENT, DNS_SERVER, 53003, 53, dns_query(0x3333, "dead.example.com")))))

    # --- Stream 3: low MSS + PMTUD black hole ----------------------------
    # MSS 1240 negotiated, then a full-size (1240 B) segment retransmitted
    # 3 times with no ICMP frag-needed addressed to these hosts.
    sp, isn_a, isn_b = 34570, 7000, 8000
    pkts.append((6.000, a2b(tcp(CLIENT, SERVER, sp, 8080, isn_a, 0, SYN,
                                options=mss_option(1240)))))
    pkts.append((6.010, b2a(tcp(SERVER, CLIENT, 8080, sp, isn_b, isn_a + 1, SYN | ACK,
                                options=mss_option(1460)))))
    pkts.append((6.020, a2b(tcp(CLIENT, SERVER, sp, 8080, isn_a + 1, isn_b + 1, ACK))))
    big = tcp(CLIENT, SERVER, sp, 8080, isn_a + 1, isn_b + 1, ACK, payload=b"\x00" * 1240)
    pkts.append((6.030, a2b(big)))
    pkts.append((6.230, a2b(big)))  # full-size retransmission 1
    pkts.append((6.630, a2b(big)))  # full-size retransmission 2
    pkts.append((7.430, a2b(big)))  # full-size retransmission 3

    # --- Stream 4: slow TCP handshake (600 ms SYN -> SYN-ACK) ------------
    sp, isn_a, isn_b = 34571, 9000, 9500
    pkts.append((8.000, a2b(tcp(CLIENT, SERVER, sp, 9090, isn_a, 0, SYN,
                                options=mss_option(1460)))))
    pkts.append((8.600, b2a(tcp(SERVER, CLIENT, 9090, sp, isn_b, isn_a + 1, SYN | ACK,
                                options=mss_option(1460)))))
    pkts.append((8.620, a2b(tcp(CLIENT, SERVER, sp, 9090, isn_a + 1, isn_b + 1, ACK))))

    # --- ICMP Fragmentation Needed (path MTU 1400) ------------------------
    pkts.append((8.700, b2a(icmp_frag_needed(ROUTER, ICMP_TARGET, 1400,
                                             ICMP_TARGET, "10.0.0.8"))))

    # --- IP fragmentation: one complete datagram, one incomplete ----------
    for i, frag in enumerate(udp_fragments(CLIENT, SERVER, 40000, 9999,
                                           3000, ip_id=0x2001)):
        pkts.append((9.000 + i * 0.010, a2b(frag)))
    for frag in udp_fragments(CLIENT, SERVER, 40001, 9999,
                              3000, ip_id=0x2002, drop_last=True):
        pkts.append((9.100, a2b(frag)))

    # --- VPN: one-way ESP + unanswered IKE towards a dead gateway ---------
    for i in range(4):
        pkts.append((10.0 + i * 0.1, a2b(esp(CLIENT, VPN_GW_DEAD, 0xABCD0001, i + 1))))
    ispi_dead = b"\x11" * 8
    for i in range(3):
        pkts.append((11.0 + i * 0.5, a2b(udp(CLIENT, VPN_GW_DEAD, 500, 500,
                                             ike_sa_init(ispi_dead)))))

    # --- VPN: IKE completes but no ESP ever follows ------------------------
    ispi_half = b"\x22" * 8
    pkts.append((12.500, a2b(udp(CLIENT, VPN_GW_HALF, 500, 500,
                                 ike_sa_init(ispi_half)))))
    pkts.append((12.600, b2a(udp(VPN_GW_HALF, CLIENT, 500, 500,
                                 ike_sa_init(ispi_half, rspi=b"\x33" * 8,
                                             response=True)))))

    # --- DNS errors: one SERVFAIL + three NXDOMAIN -------------------------
    pkts.append((13.000, a2b(udp(CLIENT, DNS_SERVER, 53004, 53, dns_query(0x4444, "fail.example.com")))))
    pkts.append((13.020, b2a(udp(DNS_SERVER, CLIENT, 53, 53004, dns_response(0x4444, "fail.example.com", rcode=2)))))
    for i, txid in enumerate((0x5551, 0x5552, 0x5553)):
        name = "typo%d.example.com" % (i + 1)
        sport = 53005 + i
        pkts.append((13.1 + i * 0.1, a2b(udp(CLIENT, DNS_SERVER, sport, 53, dns_query(txid, name)))))
        pkts.append((13.12 + i * 0.1, b2a(udp(DNS_SERVER, CLIENT, 53, sport, dns_response(txid, name, rcode=3)))))

    # --- Duplicate IP: two MACs claim the same address via ARP -------------
    pkts.append((14.000, arp_announce(MAC_DUP_1, DUP_IP)))
    pkts.append((14.100, arp_announce(MAC_DUP_2, DUP_IP)))

    return pkts


def build_dhcp_packets():
    """Separate capture (kept out of the main sample so its counts stay put):
    one clean DORA, one NAK, and one DISCOVER that never gets an OFFER."""
    mac1 = bytes.fromhex("020000000011")
    mac2 = bytes.fromhex("020000000012")
    mac3 = bytes.fromhex("020000000013")
    srv = "10.0.0.1"
    pkts = []

    def c2s(payload: bytes, mac: bytes) -> bytes:
        return MAC_BCAST + mac + b"\x08\x00" + payload

    def s2c(payload: bytes, mac: bytes) -> bytes:
        return mac + MAC_A + b"\x08\x00" + payload

    def c_udp(msg: bytes) -> bytes:
        return udp("0.0.0.0", "255.255.255.255", 68, 67, msg)

    def s_udp(msg: bytes) -> bytes:
        return udp(srv, "255.255.255.255", 67, 68, msg)

    # Clean DORA for mac1 (xid 0x1001), ACK 120 ms after DISCOVER
    pkts.append((0.000, c2s(c_udp(dhcp(1, 0x1001, mac1, hostname="laptop-1")), mac1)))
    pkts.append((0.050, s2c(s_udp(dhcp(2, 0x1001, mac1, "10.0.0.50", srv, reply=True)), mac1)))
    pkts.append((0.080, c2s(c_udp(dhcp(3, 0x1001, mac1, hostname="laptop-1")), mac1)))
    pkts.append((0.120, s2c(s_udp(dhcp(5, 0x1001, mac1, "10.0.0.50", srv, reply=True)), mac1)))
    # mac2 REQUESTs a stale address and gets a NAK
    pkts.append((1.000, c2s(c_udp(dhcp(3, 0x2002, mac2, hostname="printer")), mac2)))
    pkts.append((1.010, s2c(s_udp(dhcp(6, 0x2002, mac2, "0.0.0.0", srv, reply=True)), mac2)))
    # mac3 DISCOVERs twice and nobody answers
    pkts.append((2.000, c2s(c_udp(dhcp(1, 0x3003, mac3, hostname="camera")), mac3)))
    pkts.append((4.000, c2s(c_udp(dhcp(1, 0x3003, mac3, hostname="camera")), mac3)))
    return pkts


def build_troubleshooting_packets():
    """Separate capture (keeps the main sample's counts untouched) with the
    TCP-analysis and ICMP-error patterns Wireshark flags:

      * stream 0 (:5001): a lost segment followed by 5 duplicate ACKs and a
        fast retransmission
      * stream 1 (:5002): 6 pairs of reordered segments (1 out-of-order,
        5 reported by Wireshark as lost-segment + retransmission)
      * stream 2 (:5003): sender fills the 300-byte receive window 4 times
      * stream 3 (:5004): established connection that ends with a RST
      * ICMP errors: port unreachable, host unreachable, admin-prohibited x2,
        TTL exceeded x6
      * one DNS answer so the capture also teaches name resolution
    """
    c, srv, rtr, fw = "10.1.0.1", "10.1.0.2", "10.1.0.254", "10.1.0.253"
    pkts = []

    def a2b(payload: bytes) -> bytes:
        return MAC_B + MAC_A + b"\x08\x00" + payload

    def b2a(payload: bytes) -> bytes:
        return MAC_A + MAC_B + b"\x08\x00" + payload

    def handshake(t, sport, dport, isn_a, isn_b, win_b=65535):
        pkts.append((t, a2b(tcp(c, srv, sport, dport, isn_a, 0, SYN))))
        pkts.append((t + 0.010, b2a(tcp(srv, c, dport, sport, isn_b, isn_a + 1, SYN | ACK, window=win_b))))
        pkts.append((t + 0.020, a2b(tcp(c, srv, sport, dport, isn_a + 1, isn_b + 1, ACK))))

    seg = b"x" * 100

    # --- stream 0: lost segment, 5 duplicate ACKs, fast retransmission ------
    sp, dp, ia, ib = 40001, 5001, 1000, 9000
    handshake(0.000, sp, dp, ia, ib)
    pkts.append((0.030, a2b(tcp(c, srv, sp, dp, ia + 1, ib + 1, PSH | ACK, payload=seg))))
    pkts.append((0.040, b2a(tcp(srv, c, dp, sp, ib + 1, ia + 101, ACK))))
    for k in range(5):  # segments 3..7 arrive, segment 2 (seq ia+101) is missing
        t = 0.050 + k * 0.010
        pkts.append((t, a2b(tcp(c, srv, sp, dp, ia + 201 + k * 100, ib + 1, PSH | ACK, payload=seg))))
        pkts.append((t + 0.005, b2a(tcp(srv, c, dp, sp, ib + 1, ia + 101, ACK))))
    pkts.append((0.100, a2b(tcp(c, srv, sp, dp, ia + 101, ib + 1, PSH | ACK, payload=seg))))
    pkts.append((0.110, b2a(tcp(srv, c, dp, sp, ib + 1, ia + 701, ACK))))

    # --- stream 1: reordered segments ---------------------------------------
    # Wireshark only labels a late segment "out-of-order" (instead of a plain
    # retransmission) when it follows the jump within a tight window and the
    # round-trip time is not yet established: pair 0 is sent before the
    # handshake ACK on purpose, which yields exactly one such flag. The other
    # five pairs are reported as lost-segment + retransmission.
    sp, dp, ia, ib = 40002, 5002, 2000, 8000
    pkts.append((1.000, a2b(tcp(c, srv, sp, dp, ia, 0, SYN))))
    pkts.append((1.100, b2a(tcp(srv, c, dp, sp, ib, ia + 1, SYN | ACK))))
    pkts.append((1.1005, a2b(tcp(c, srv, sp, dp, ia + 101, ib + 1, PSH | ACK, payload=seg))))
    pkts.append((1.1015, a2b(tcp(c, srv, sp, dp, ia + 1, ib + 1, PSH | ACK, payload=seg))))
    pkts.append((1.200, a2b(tcp(c, srv, sp, dp, ia + 201, ib + 1, ACK))))
    pkts.append((1.250, b2a(tcp(srv, c, dp, sp, ib + 1, ia + 201, ACK))))
    for k in range(1, 6):
        t = 1.300 + k * 0.050
        base = ia + 1 + k * 200
        pkts.append((t, a2b(tcp(c, srv, sp, dp, base + 100, ib + 1, PSH | ACK, payload=seg))))
        pkts.append((t + 0.001, a2b(tcp(c, srv, sp, dp, base, ib + 1, PSH | ACK, payload=seg))))
        pkts.append((t + 0.003, b2a(tcp(srv, c, dp, sp, ib + 1, base + 200, ACK))))

    # --- stream 2: sender fills a 300-byte receive window four times --------
    sp, dp, ia, ib = 40003, 5003, 3000, 7000
    handshake(2.000, sp, dp, ia, ib, win_b=300)
    seq = ia + 1
    for k in range(4):
        t = 2.050 + k * 0.100
        for j in range(3):
            pkts.append((t + j * 0.001, a2b(tcp(c, srv, sp, dp, seq + j * 100, ib + 1, PSH | ACK, payload=seg))))
        pkts.append((t + 0.050, b2a(tcp(srv, c, dp, sp, ib + 1, seq + 300, ACK, window=300))))
        seq += 300

    # --- stream 3: established, then RST -----------------------------------
    sp, dp, ia, ib = 40004, 5004, 4000, 6000
    handshake(3.000, sp, dp, ia, ib)
    pkts.append((3.030, a2b(tcp(c, srv, sp, dp, ia + 1, ib + 1, PSH | ACK, payload=seg))))
    pkts.append((3.040, b2a(tcp(srv, c, dp, sp, ib + 1, ia + 101, PSH | ACK, payload=seg))))
    pkts.append((3.050, a2b(tcp(c, srv, sp, dp, ia + 101, ib + 101, ACK))))
    pkts.append((3.060, b2a(tcp(srv, c, dp, sp, ib + 101, ia + 101, RST | ACK))))

    # --- ICMP errors --------------------------------------------------------
    pkts.append((4.000, b2a(icmp_error(srv, c, 3, 3, c, srv))))                # port unreachable
    pkts.append((4.100, b2a(icmp_error(rtr, c, 3, 1, c, "10.1.0.77"))))        # host unreachable
    for k in range(2):
        pkts.append((4.200 + k * 0.1, b2a(icmp_error(fw, c, 3, 13, c, "10.1.0.88", 6))))  # admin prohibited
    for k in range(6):
        pkts.append((4.500 + k * 0.1, b2a(icmp_error(rtr, c, 11, 0, c, "10.1.0.99"))))    # TTL exceeded

    # --- one DNS answer (name resolution) -----------------------------------
    pkts.append((5.000, a2b(udp(c, "10.1.0.53", 53001, 53, dns_query(0x7001, "intranet.example.com")))))
    pkts.append((5.020, b2a(udp("10.1.0.53", c, 53, 53001, dns_response(0x7001, "intranet.example.com", srv)))))

    pkts.sort(key=lambda item: item[0])
    return pkts


def write_pcap(path: str, packets=None) -> None:
    if packets is None:
        packets = build_sample_packets()
    with open(path, "wb") as fh:
        fh.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in packets:
            sec, usec = int(ts), int(round((ts - int(ts)) * 1_000_000))
            fh.write(struct.pack("!IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)


if __name__ == "__main__":
    import sys

    out = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/sample.pcap"
    write_pcap(out)
    print("wrote %s (%d packets)" % (out, len(build_sample_packets())))
