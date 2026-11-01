# TLS handshake and alerts

Handshake order (TLS 1.2): ClientHello → ServerHello → Certificate → (ServerKeyExchange)
→ ServerHelloDone → ClientKeyExchange → ChangeCipherSpec → Finished. TLS 1.3 compresses
this: ClientHello → ServerHello + encrypted extensions/certificate/Finished → client
Finished. In 1.3 the certificate is encrypted, so only the ClientHello (with SNI and
offered versions/ciphers) and the ServerHello (negotiated cipher, `supported_versions`)
are readable.

Timing: ClientHello to ServerHello ≈ one RTT plus server work; a long gap here with a
fast TCP handshake points at the server (OCSP stapling, slow key exchange, overloaded
TLS terminator), not the network.

Alert levels: 1 warning, 2 fatal. Common alert descriptions (`tls.alert_message.desc`):
- 0 close_notify: normal shutdown.
- 10 unexpected_message, 20 bad_record_mac, 50 decode_error, 51 decrypt_error: data
  corruption or a middlebox altering TLS; also a wrong pre-shared key.
- 40 **handshake_failure**: no common cipher suite / version / curve, or a client
  requiring a feature the server lacks. Compare the ClientHello offers with what the
  server supports.
- 42 bad_certificate, 43 unsupported_certificate, 44 certificate_revoked, 45
  certificate_expired, 46 certificate_unknown, 48 **unknown_ca**: the client rejected the
  server certificate (or the server rejected a client certificate for mTLS). Sent by the
  party that validated the chain. Typical causes: missing intermediate, private CA not
  trusted, expired cert, SNI mismatch, TLS-inspecting proxy with an untrusted CA.
- 47 illegal_parameter, 70 **protocol_version**: version negotiation failed (e.g. client
  insists on TLS 1.0, server minimum is 1.2).
- 49 access_denied, 71 insufficient_security: policy refusal.
- 80 internal_error, 86 inappropriate_fallback, 90 user_canceled.
- 109 missing_extension, 110 unsupported_extension, 112 **unrecognized_name**: the SNI
  does not match any virtual host on the server.
- 115 unknown_psk_identity, 116 certificate_required (mTLS client cert missing).

An RST right after the ClientHello with no alert usually means a firewall or IPS doing
SNI-based filtering, or a server that does not speak TLS on that port.
