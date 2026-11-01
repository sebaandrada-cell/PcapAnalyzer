# ICMP and ICMPv6 messages relevant to troubleshooting

ICMPv4 **type 3 (Destination Unreachable)** codes:
- 0 net unreachable, 1 host unreachable: a router (code 1 often the last-hop router) has no
  route or no ARP reply for the target. Routing problem or the host is down.
- 2 protocol unreachable, 3 **port unreachable**: sent by the destination host itself —
  the host is up and reachable, but nothing listens on that UDP port (or the service is
  down). For UDP services (DNS, syslog, SNMP) this is the equivalent of a TCP RST.
- 4 **fragmentation needed and DF set**: a router on the path has a smaller MTU; it
  reports the next-hop MTU. Essential for Path MTU Discovery. If these are filtered, large
  packets silently disappear (PMTUD black hole).
- 9/10 administratively prohibited (network/host), 13 **communication administratively
  filtered**: a firewall or ACL rejected the packet and chose to tell you. The reporter's
  address identifies the filtering device.
- 5 source route failed, 6/7 unknown network/host, 11/12 TOS-related: rare.

**Type 11 (Time Exceeded)**: code 0 = TTL expired in transit (a routing loop if it repeats
for normal traffic; expected for traceroute), code 1 = fragment reassembly time exceeded
(fragments of a datagram never all arrived).

**Type 5 (Redirect)**: a router tells a host to use a better gateway on the same subnet —
usually a misconfigured default gateway. **Type 8/0** echo request/reply: ping.

ICMPv6:
- Type 1 Destination Unreachable: code 0 no route, 1 administratively prohibited, 3
  address unreachable, 4 port unreachable, 5/6 source policy/reject route.
- Type 2 **Packet Too Big**: the IPv6 equivalent of frag-needed; IPv6 routers never
  fragment, so blocking type 2 breaks every large transfer.
- Type 3 Time Exceeded (0 hop limit, 1 reassembly), type 4 Parameter Problem.
- Types 133-137 are Neighbor Discovery (RS/RA/NS/NA/Redirect): duplicate address
  detection, router advertisements. NS without NA = the neighbor is down or off-link.

Always read the quoted inner packet of an error: it names the original source, destination
and port that triggered the message — that is the flow that failed, and the reporter
(outer source) is the device that failed it.
