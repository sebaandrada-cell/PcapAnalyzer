# Path MTU, fragmentation and black holes

Ethernet MTU is 1500 bytes; a TCP MSS of 1460 (IPv4) / 1440 (IPv6) follows from it.
Tunnels (IPsec, GRE, VXLAN, PPPoE at 1492, WireGuard ~1420) and some WAN links have a
smaller MTU somewhere on the path.

Path MTU Discovery (PMTUD) relies on routers sending ICMP "fragmentation needed" (type 3
code 4) / ICMPv6 "Packet Too Big" (type 2) when a DF packet exceeds their MTU. If a
firewall drops those ICMP messages the sender never learns: small packets (handshake,
requests, acknowledgements) pass, but the first full-size data segment is silently
dropped and retransmitted again and again. That is the **PMTUD black hole** signature:

- TCP handshake completes, the request goes out, then the server's (or client's) first
  large segment (length ≈ MSS) is retransmitted with doubling intervals and the
  connection stalls or resets.
- Only full-size segments are retransmitted; small ones are acknowledged normally.
- No ICMP frag-needed in the capture even though the path clearly has a smaller MTU.
- Often "works on HTTP but not HTTPS", "ssh login works but `ls` of a big directory
  hangs", "small files OK, large files stall".

Fixes: let ICMP type 3 code 4 / ICMPv6 type 2 through, clamp the MSS on the tunnel or
edge router (`tcp mss adjust`, MSS clamping), or lower the interface MTU.

Fragmentation itself (`ip.flags.mf == 1` or `ip.frag_offset > 0`) is legal but costly:
one lost fragment loses the whole datagram, many firewalls drop non-initial fragments,
and UDP protocols that send large datagrams (DNS with DNSSEC, NFS, SIP with big SDP,
IKE with certificates) are the usual victims. "First fragment seen, last never seen" =
fragments being dropped on the path.

A negotiated MSS well below 1460 (e.g. 1240, 1350) in the SYN tells you the endpoints
already know about a tunnel or a clamp — helpful context, not an error by itself.
