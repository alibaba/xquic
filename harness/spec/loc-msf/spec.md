# LOC/MSF Minimum Application Format

## Protocol and Compatibility Boundary

The format APIs implement the explicitly limited profile below, pinned to
[LOC-05 sections 2.2–2.3][loc] and [MSF-01 sections 4–6][msf]. They are
application helpers above the draft-22 MoQT Object API. Existing draft-05
`xqc_moq_*` media/catalog serialization retains its wire and ABI contracts.
Enabling `XQC_ENABLE_MOQ` builds both paths. No transport negotiation or
Session/Relay policy is added by using these helpers.

## LOC Public Properties

`xqc_loc_encode/decode` serialize a complete Object Properties list using
the transport KVP codec and vi64, including delta-encoded property types.
Supported keys are Timescale (0x08), Video Frame Marking (0x09), Audio Level
(0x0c), Video Config (0x0d), Audio Config (0x0f), Timestamp (0x10), and Codec
String (0x11). Unknown keys are skipped by parity/framing. Known duplicates,
truncation, zero Timescale, Audio Level above 255, and frame-marking lengths
outside 1–4 bytes are rejected. Codec/config contents are opaque byte views;
applications validate codec-specific contents and codec strings.

Metadata byte views borrow the input. Absent Timestamp remains absent; absent
Timescale yields 1000000, with timestamp interpreted as Unix microseconds.
At most 64 properties and 65535 encoded bytes are accepted. Encoders support
sizing and leave output untouched on errors. Invalid local views return
`-XQC_EPARAM`; malformed wire returns `-XQC_EILLEGAL_FRAME`; budgets return
`-XQC_ELIMIT`; insufficient encode capacity returns `-XQC_ENOBUF`.

LOC public properties belong in `xqc_moqt_object_t.properties`. Unencrypted
elementary frame bytes belong in `payload`, without the legacy sequence/
timestamp prefix. Secure Objects, immutable/private property interpretation,
codec conversion and payload encryption are outside this profile. Do not
interpret an encrypted/private payload as a clear elementary bitstream.

## Independent MSF Catalog Profile

`xqc_msf_catalog_encode` emits `msfVersion: "draft-01"` and `tracks` with
`name`, `packaging: "loc"`, and Boolean `isLive`. It optionally emits
namespace, codec, mimeType, role, channelConfig, width, height, samplerate and
timescale. Positive numeric fields are bounded to uint32; zero local values
mean omitted. The decoder also accepts bounded generatedAt and
`isComplete: true`, rejecting live tracks in a completed broadcast. Empty
catalogs and empty Track Names are permitted by the format.

Names are MSF UTF-8 strings. A NULL namespace inherits the caller-supplied
catalog namespace; missing caller context means the empty string. Track
names must be unique within the effective namespace. Returned namespace
views are resolved strings. Applications remain responsible for conversion
between the section 11.1.2 string encoding and binary MoQT namespace tuples;
the format parser does not split strings, follow URLs or open subscriptions.

Decoding owns its copied JSON tree until `xqc_msf_catalog_destroy`; queried
read-only track strings borrow that tree/context. Input can be released after
decode. A failed decode does not publish a partial handle, and a failed
encode does not modify caller bytes. Buffers contain JSON bytes without a
NUL terminator. Inputs and output must not overlap.

Unknown fields are ignored. Unsupported versions, non-LOC packaging,
delta, publishTracks, initDataList, initRef, parentName/parentNamespace,
depends and encryption fields return `-XQC_EPROTO`. This explicitly restricted
profile must never consume a dependent/delta/encrypted catalog as a complete
clear snapshot. Other optional fields are not interpreted by these helpers;
applications needing them must select a richer profile. Re-encoding queried
tracks is a projection of supported fields, not a lossless JSON forwarder.

Limits are 32 tracks, 65535 input/output bytes, 4096 UTF-8 bytes per string,
16 nesting levels and 4096 JSON nodes. Reject invalid UTF-8, embedded NUL,
invalid number syntax, duplicate JSON keys, required-field/type errors,
duplicate effective names, and trailing non-whitespace. Resource limits are
implementation policy, not a claim that larger catalogs violate MSF.
Error values follow the public header; JSON allocation failure may surface
as malformed input when the underlying parser cannot distinguish it.

## Object and Application Responsibilities

Under [MSF-01 section 5][catalog], an independent catalog is Object 0 of
Subgroup 0 in a new Group, on the case-sensitive `catalog` Track. This
profile emits independent catalogs only. Applications reject misplaced or
delta Objects before decoding, retain monotonic Group IDs, and obtain the
latest snapshot with the specified Joining FETCH workflow. A JSON codec
alone does not enforce those cross-Object requirements.

Under [sections 4.1 and 6][media], each encoded sample is one Object, samples
of a GOP share a Group, and Object IDs start at zero and increase by one.
The pinned MSF text requires a new stream per Object; an application claiming
that profile uses one Subgroup per Object through the existing transport
API. Datagram composition tests demonstrate byte carriage only, not MSF
stream-mapping conformance. The application owns scheduling, GOPs, full
Object assembly, codec configuration and decoding/display.

## Acceptance and Interop Evidence

| Capability | Required evidence | Status |
| --- | --- | --- |
| Public LOC properties | Independent all-key vector, full-width vi64, unknown-key skip; malformed lengths, duplicate/truncated keys, budgets and atomic output | Implemented; paired unit coverage |
| Full LOC catalog snapshot | Independent JSON, inheritance, selected decoder fields, ownership and encode projection; malformed/schema/unsupported/budget rejection | Implemented; paired unit coverage |
| Object composition | Raw payload/property fidelity and malformed LOC isolation through Object codec | Implemented; format unit coverage |
| Live snapshot/state and media workflow | Joining FETCH, catalog placement, live-to-ended commitment, GOP/stream IDs | Application integration gap |
| Bounded C22 profile | Separate publisher/subscriber, decoded catalog, three VP8 samples, independent decoder/terminal rendering and normal completion | Application adapter in `interop/moqt/`; peer results remain runtime evidence |

No numeric endpoint case IDs are allocated for format units or the named
interop scenarios. The application adapter adds normal catalog/LOC/VP8
delivery and malformed-catalog/LOC recovery over Native QUIC and WT. It uses
three all-keyframe GOPs and a real FFmpeg decoder with terminal luma rendering.
This restricted profile does not complete F44 or imply general-purpose player
interoperability. Joining FETCH of live snapshots, encryption, audio, ABR,
timeline, delta updates and HTTP/URL workflows remain outside this profile.
Case availability does not itself prove an independent peer C22 pass; retain
actual transport, negotiation, decoder and completion evidence separately.

[loc]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-loc-05#section-2.3
[msf]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-msf-01
[catalog]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-msf-01#section-5
[media]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-msf-01#section-6
