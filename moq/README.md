# Media over QUIC

This implementation selects the MoQ wire version through an immutable ALPN
profile:

- `moq-quic` and `moq-05` select draft-05.
- `moq-14` selects draft-14.
- `moq-00` is intentionally not registered.

`moq-05` and `moq-14` are private version-selection ALPNs. Peers that only
advertise the standards-defined `moq-00` ALPN do not interoperate with these
modes. SETUP validates the message type and wire version selected by ALPN; it
does not sniff or switch protocol dialects.

`moq-wt` is reserved for future WebTransport support and currently has no
registered profile.
