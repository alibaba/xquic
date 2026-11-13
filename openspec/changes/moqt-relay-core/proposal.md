# MoQT Relay Core

Provide the cacheless Relay required for interop on top of the existing
draft-22 endpoints, reusing validated codecs, requests, and incremental Object
delivery. The [Relay specification](../../../spec/moqt/moqt-relay.md) is the
single normative source for capabilities and entities.

Include multi-source routing, Namespace/St/Pc discovery and source sets,
upstream Established gating, rendezvous, hop-local identifier isolation,
fanout and pause control, total FETCH/Fill budgets, and resource, error, and
overlap isolation. Each behavior needs positive/negative unit tests and real
publisher → Relay → subscriber validation.

Reuse endpoint SUBSCRIBE_TRACKS/PUBLISH_SKIPPED enumeration APIs to provide
the Relay associations required by C10.

Exclude nonzero Range Filters, 0-RTT, history caching, relay-to-relay routing,
media processing, and interop runner integration. Preserve draft-05, public
QUIC/TLS interfaces, and CDN tests. The external runner validates the pinned
namespace-discovery case; local three-node tests are separate evidence.
