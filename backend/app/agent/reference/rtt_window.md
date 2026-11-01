# Reading RTT, window and throughput from a capture

**RTT**: the handshake RTT (SYN → SYN/ACK as seen at the client, SYN/ACK → ACK as seen at
the server) is the cleanest network latency measurement because no application is
involved. `tcp.analysis.ack_rtt` on later packets measures data → ACK time and mixes
network RTT with delayed ACKs (up to 40-200 ms) and receiver processing; use its minimum
or median per direction, not its maximum, for the network part. Where the capture was
taken decides what you see: on the client, the SYN/ACK delay is the full path; on the
server, the ACK of the SYN/ACK is the full path.

**Window**: the receiver advertises how many bytes it can still buffer (`tcp.window_size`
after scaling). Throughput of a single connection cannot exceed window / RTT (the
bandwidth-delay product). Examples: 64 KiB window at 50 ms RTT ≈ 10 Mbit/s maximum
regardless of link speed. Missing window scaling (option absent in the SYN) caps the
window at 65535 bytes. A window that shrinks towards zero shows the receiving application
falling behind.

**Throughput**: bytes over time per direction; compare with the link and with the
window/RTT limit. If throughput sits at the window/RTT ceiling with no loss, the window is
the limit. If it drops after retransmissions and recovers slowly, congestion control
reacted to loss. If it is bursty with long idle gaps where neither side sends data, the
application (or something upstream of it, like a database) is the bottleneck, not TCP.

**Idle gaps**: a gap where the last packet was a request and the next is the response =
server/application think time. A gap after the server's last data where the client takes
long to send the next request = client-side processing or user think time. Gaps followed
by a retransmission = loss. Gaps followed by keep-alives = genuinely idle connection.

**Attribution checklist**: who sent the last packet before the delay, is the delay
repeatable across requests, does it correlate with payload size (MTU), with time of day
(congestion), or with a specific destination (routing/firewall path).
