# IPsec (IKE/ESP), WireGuard and OpenVPN in a capture

**IKE** (ISAKMP, UDP/500; UDP/4500 when NAT-T is in use) negotiates the tunnel. IKEv2:
IKE_SA_INIT request/response, then IKE_AUTH request/response (encrypted), then
CREATE_CHILD_SA for rekeys. IKEv1: Main Mode (6 messages) or Aggressive Mode (3), then
Quick Mode. Patterns:
- IKE_SA_INIT requests with no response: the peer is down, UDP/500 is filtered, or the
  peer address is wrong. Retransmissions every few seconds then give up.
- IKE_SA_INIT answered but IKE_AUTH fails or is followed by a Notify with an error
  (NO_PROPOSAL_CHOSEN, AUTHENTICATION_FAILED, INVALID_KE_PAYLOAD, TS_UNACCEPTABLE):
  proposal/PSK/certificate/traffic-selector mismatch. The notify type names the cause.
- Complete IKE but **no ESP afterwards**: phase 2 never came up or traffic is not being
  routed into the tunnel (policy/route problem).
- Switch from UDP/500 to UDP/4500: NAT detected; if 4500 is blocked, IKE completes but
  ESP never flows.

**ESP** (IP protocol 50, or UDP/4500 encapsulated) carries the encrypted data; only SPI
and sequence numbers are visible. One-way ESP (packets to the peer, none back) = the
remote end is not decrypting/forwarding, a return route is missing, or an asymmetric
firewall. Sequence gaps = loss inside the tunnel.

**WireGuard** (UDP, often 51820): handshake initiation (type 1) and response (type 2)
should alternate; repeated initiations without a response = peer unreachable or key
mismatch (the responder stays silent on bad keys by design). Transport data is type 4.

**OpenVPN** (UDP/1194 or TCP/443): P_CONTROL_HARD_RESET_CLIENT_V2 with no server reset
back = unreachable/filtered; TLS errors inside the control channel show as the session
resetting shortly after the handshake.

Tunnels also lower the effective MTU (ESP adds 50-70 bytes, WireGuard 60-80): if small
packets pass and large transfers stall inside the tunnel, see the PMTUD note.
