# DNS behaviour and response codes

A query (`dns.flags.response == 0`) should be answered within tens of milliseconds by a
local resolver and within a few hundred milliseconds by a recursive lookup. Clients
typically retry after 1-5 s and then try the next configured server, so "slow DNS"
shows up as duplicated queries with the same transaction id and a stall of several
seconds before any TCP connection to the target.

Response codes (`dns.flags.rcode`):
- 0 NOERROR: fine. NOERROR with zero answers = the name exists but has no record of the
  requested type (common with AAAA queries, harmless).
- 1 FORMERR: malformed query (broken client or middlebox).
- 2 **SERVFAIL**: the server could not complete the lookup — upstream unreachable,
  DNSSEC validation failure, lame delegation, or the recursive resolver timing out. The
  server itself is up; the problem is behind it.
- 3 **NXDOMAIN**: the name does not exist. Bursts of NXDOMAIN for the same client often
  come from a wrong search suffix (`host.corp.local.corp.local`), typos, or malware DGA;
  NXDOMAIN for a name that should exist = split-horizon / wrong resolver.
- 4 NOTIMP, 5 **REFUSED**: the server refuses to serve this client (ACL, not authoritative,
  recursion not allowed). Points at resolver configuration.
- 9 NOTAUTH, 10 NOTZONE: dynamic update / zone problems.

Unanswered queries (no response with the same id within the capture) mean: the server is
down, UDP/53 is filtered (look for ICMP port unreachable from the server = service down,
or nothing at all = filtered or lost), or the capture ended first. Truncated responses
(`dns.flags.truncated`) force a retry over TCP/53 — if TCP/53 is blocked, large answers
(DNSSEC, many records) fail while small ones work.

mDNS (224.0.0.251:5353) and LLMNR (224.0.0.252:5355) are local name resolution, mostly
noise unless Windows name resolution is the problem.
