# CBMC proofs of the peer-input parsers

Bounded model checking with [CBMC](https://github.com/diffblue/cbmc) of the
code that parses what a peer sends: the frame parsers of
`src/transport/xqc_frame_parser.c` and `xqc_vint_read()`, the transport
parameter decoder, the packet header parsers, and the QPACK integer and
Huffman decoders. `harness/http3.c` also holds harnesses for the HTTP/3 frame
parser and the QPACK string, instruction and field line parsers; they need
more memory than a CI runner has, so `proofs.list` leaves them out.

Each proof gives one parser an unconstrained input of at most `MAXLEN` bytes,
held in an object of exactly that size, and checks every path for
out-of-bounds accesses, invalid pointers, signed overflow, undefined shifts,
leaks and division by zero, plus the contract its caller relies on (for
example: a frame parser that succeeds moves `packet_in->pos` forward and not
past `packet_in->last`). A proof holds for every input up to its bound and
for every loop iteration up to its unwinding bound; an unwinding assertion
fails when a bound is too small.

## Running

CBMC 6.11 (`cbmc`, `goto-cc`, `goto-instrument` on `PATH`) and the OpenSSL
headers are needed. From the repository root:

```bash
proofs/cbmc/ci.sh                                 # proofs.list
proofs/cbmc/run.sh frame_parser harness_stream    # one proof, 64 bytes
CHECKS=core MAXLEN=32 proofs/cbmc/run.sh frame_parser harness_crypto
```

`CHECKS=core` (the CI setting) leaves out CBMC's unsigned overflow,
conversion and pointer-overflow checks, which also report intended unsigned
wraparound; `CHECKS=full` keeps them.

## Stubs

Only code that runs after a parser has decided, and returns no data to it,
is replaced (`stubs/`): connection state changes, CID-set lookups, the
version check and the Retry integrity AEAD return every value the real
functions can return. `stubs/tp_copies.c` holds verbatim copies of
`xqc_cid_set()`, `xqc_cid_is_equal()` and `xqc_set_fec_scheme()`, whose
files need the TLS headers. The ACK proofs use `stubs/vint_contract.c`,
`xqc_vint_read()` reduced to its contract, which `harness_vint_read` proves
for the real function. Logging is compiled out.
