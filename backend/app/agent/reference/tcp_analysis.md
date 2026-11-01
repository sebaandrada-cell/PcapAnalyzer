# Wireshark TCP analysis flags — what each one means and what it does not

- **Retransmission**: a segment whose sequence range was already seen, sent after the
  retransmission timeout (RTO, typically >= 200 ms, often 1 s on first retry). Means the
  sender got no ACK in time: loss on the path, or the ACK was lost, or the receiver is
  unreachable. Several RTO retransmissions of the same segment with doubling intervals
  (1 s, 2 s, 4 s...) = the peer or the path is dead/blackholed.
- **Fast retransmission**: triggered by 3 duplicate ACKs, so the path is alive and only
  one segment was lost. Mild loss, usually congestion or a lossy link.
- **Spurious retransmission**: the data had already been ACKed; the sender retransmitted
  needlessly. Often a sign that ACKs are delayed/lost on the return path, or an RTO that
  is too aggressive.
- **Dup ACK**: the receiver repeats the same ACK number because a segment is missing
  (gap) or arrived out of order. Dup ACKs come from the receiver; the loss happened
  towards the receiver.
- **Previous segment not captured**: a sequence gap at the capture point. If the capture
  was taken on one end host, it is real loss before that host; if taken on a SPAN/tap,
  it can also be the capture dropping packets (check for `frame.cap_len` anomalies and
  the capture tool's drop counters).
- **Out-of-order**: a segment with a lower sequence number arrived after a higher one
  within the RTT. Common with multipath/ECMP, link aggregation or load balancers; harmless
  in small amounts, harmful when it triggers dup ACKs and fast retransmissions.
- **Zero window**: the receiver advertised window 0 — its application is not reading
  from the socket fast enough. The problem is on the receiver host, not the network.
- **Window full**: the sender has filled the receiver's advertised window and must stop.
  The receiver is the bottleneck (small window, slow consumer) or the bandwidth-delay
  product exceeds the window (long fat pipe without scaling).
- **Zero window probe / probe ACK**: the sender polls a zero-window receiver. Normal
  while the condition lasts.
- **Window update**: the receiver reopened the window. Informational.
- **Keep-alive / keep-alive ACK**: idle-connection probes. Informational.
- **ACKed unseen segment**: an ACK for data the capture never saw: asymmetric capture or
  capture drops, not necessarily a network problem.
- **RST**: abortive close. RST in reply to a SYN = closed port or a firewall rejecting;
  RST mid-stream = an application crash, an idle timeout on a middlebox (firewall/NAT
  dropping state), or a security device injecting resets. Look at who sends it and the
  time since the last data.

Interpretation rules: attribute loss to the direction of the missing data; distinguish
"path problem" (retransmissions, dup ACKs, out-of-order) from "endpoint problem" (zero
window, slow responses with clean transport); a capture from one host cannot prove where
on the path a packet was lost.
