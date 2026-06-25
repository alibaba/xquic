# src/common/ -- Common Utilities

> Module-level conventions for Claude Code. For file list, see `docs_ai/codebase_index.md`.

## Dependency Rule

This is the **leaf module** -- it has no upward dependencies. Every other module depends on `src/common/`. Changes here affect the entire codebase. Run full `run_tests` after any modification.

## Key Components

### Core Types & Macros
- `xqc_common.h` -- Platform detection, endianness, `xqc_pow2_upper()`, `u_char` typedef
- `xqc_common_inc.h` -- Master include for internal modules (includes common.h + log + str + time)
- `xqc_config.h` -- Internal compile-time constants (buffer sizes, limits)
- `xqc_malloc.h` -- `xqc_malloc`/`xqc_calloc`/`xqc_realloc`/`xqc_free` wrappers. All allocations MUST use these, not raw `malloc`/`free`.

### Data Structures (all header-only or minimal .c)
- `xqc_list.h` -- Intrusive doubly-linked list (Linux kernel style `list_head`)
- `xqc_queue.h` -- Queue macros
- `xqc_priority_q.h` -- Min-heap priority queue
- `xqc_rbtree.h` -- Red-black tree
- `xqc_array.h` -- Dynamic array
- `xqc_buf.h` -- Buffer management
- `xqc_fifo.h` -- FIFO queue
- `xqc_hash.h` / `xqc_id_hash.h` / `xqc_cid_hash.h` / `xqc_str_hash.h` -- Hash tables (integer, CID, and string keyed)
- `xqc_siphash.h` -- SipHash for hash randomization (DoS resistance)

### Utility Subdirectories (utils/)
| Directory | Purpose | Used By |
|-----------|---------|---------|
| `huffman/` | Huffman codec for QPACK/HPACK | `src/http3/qpack/` |
| `vint/` | QUIC variable-length integer encoding (RFC 9000 Section 16) | `src/transport/`, `src/http3/` |
| `ringarray/` | Fixed-size ring buffer (array-based) | Transport layer |
| `ringmem/` | Ring memory allocator | Transport layer |
| `2d_hash/` | Two-dimensional hash table | Transport layer |
| `var_buf/` | Variable-length buffer with auto-resize | HTTP/3 layer, QPACK |

## Common Pitfalls

- **List operations**: `xqc_list.h` uses intrusive lists. The `xqc_list_head_t` must be embedded in the container struct. Use `xqc_list_entry()` to get the container.
- **String type**: `xqc_str_t` (in `xqc_str.h`) is `{data, len}` -- NOT null-terminated by default. Use `xqc_str_set()` for string literals (calculates length), `xqc_str_null()` for empty.
- **Endianness**: The codebase assumes little-endian by default (`XQC_LITTLE_ENDIAN`). Network byte order conversions are explicit where needed.
- **No upward includes**: Never add `#include "src/transport/..."` or `#include "src/http3/..."` in common code. If you need something from upper layers, you're violating the dependency graph.

## Impact & Testing

Any change here requires full `run_tests`. See `docs_ai/architecture/module_dependency.md` for downstream impact.
