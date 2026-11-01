# DHCP (IPv4) lease flow and failure patterns

DORA: client **Discover** (broadcast, src 0.0.0.0:68 → 255.255.255.255:67) → server
**Offer** → client **Request** (broadcast, names the chosen server) → server **ACK**. A
renewing client sends a unicast Request to its server at T1 (50% of the lease) and
rebinds by broadcast at T2 (87.5%). Transactions are matched by `dhcp.id` (xid) plus the
client MAC (`dhcp.hw.mac_addr`).

Failure patterns:
- Discover with no Offer: no server on the segment and no relay (`dhcp.option.relay_agent`
  / giaddr empty), the relay points to the wrong server, the pool is exhausted (servers
  stay silent), or a MAC filter.
- Offer but no Request: the client rejected the offer (duplicate address detected via
  ARP, or a policy).
- Request followed by **NAK**: the server refuses the requested address — the client
  asked for a lease from another subnet (moved VLAN), the lease was reassigned, or the
  address is outside the pool. The client must start over with Discover.
- **Decline** from the client: it detected the offered address in use (ARP probe got a
  reply) — a duplicate IP or a static host inside the pool.
- Multiple Offers from different servers: a rogue DHCP server (home router, VM host);
  check which server the client chose in its Request.
- Long Discover→ACK latency (> 1-2 s): relay path, slow server, or retries.

Useful options: 1 subnet mask, 3 router, 6 DNS servers, 15 domain, 51 lease time, 54
server identifier, 60/61 vendor class / client id, 82 relay agent information (which
switch port). A lease with no option 3 or 6 explains "got an IP but nothing works".
