# MoQT Draft-22 Minimum Endpoint Proposal

## Why

Provide standard MoQT endpoints pinned to
[draft-ietf-moq-transport-22][draft]. Preserve existing draft-05 messages,
media interfaces, and private fast-RTT/0-RTT contracts where available.
The new stream model and Object semantics require more than a version
constant change.

## What Changes

- Add Native QUIC endpoints: codec, Session/Request, publish/subscribe,
  Object delivery, FETCH/Fill, namespace discovery/query, and error,
  authorization, and resource boundaries.
- Use separate `xqc_moqt_*` APIs. Clients select one ALPN explicitly;
  servers register old/new protocols independently. Preserve public
  connect/TLS interfaces and legacy API/ABI.
- Reuse Stream, Request, Subscription, Fetch, and common utilities.
  Group/Subgroup retain only bounded shared summaries, without Object history.
- Plan resumption, nonzero filters/Token Aliases, prefix subscriptions, and
  deployment separately. The [capability table][completeness] owns current
  status and unresolved designs.
- Implement Relay separately through public endpoint APIs. Keep cross-session
  routing, aggregation, fanout, and caching outside the protocol library.
  Integrate WebTransport, media adapters, and independent interop separately.

## Capabilities and Impact

The [protocol specification][protocol] maintains the durable
`moqt-22-protocol` contract. The [relay specification][relay] defines the
unimplemented `moqt-22-relay` target. This change retains motivation, an
architecture-decision index, and implementation outline, avoiding duplicate
specifications and historical progress snapshots.

Affected areas are optional MoQ, a separate public header, common vi64, and
paired tests. `XQC_ENABLE_MOQ` controls both protocols. QUIC varint, media
packaging, and FEC semantics remain. See [design.md](design.md) for tradeoffs
and [tasks.md](tasks.md) for remaining work. Complete documentation is not
complete implementation; retain this ongoing change until final acceptance.

[draft]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22
[protocol]: ../../../spec/moqt/moqt-protocol.md
[relay]: ../../../spec/moqt/moqt-relay.md
[completeness]: ../../../spec/moqt/moqt-protocol.md#functional-completeness
