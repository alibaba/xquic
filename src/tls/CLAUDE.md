# src/tls/ -- TLS 1.3 Integration

> Module-level conventions for Claude Code. For architecture overview, see `docs_ai/architecture/overview.md`. For build configuration, see `docs_ai/build/build_guide.md`.

## Key Conventions

- **Naming**: Core interface uses `xqc_tls_` prefix. SSL backend abstraction uses `xqc_ssl_` prefix.
- **Backend abstraction**: `xqc_ssl_if.h` defines the portable interface. Backend-specific implementations live in `boringssl/` and `babassl/`. The active backend is selected at compile time via CMake `SSL_TYPE` variable.
- **Never include backend headers directly**: Always use `xqc_ssl_if.h` and `xqc_tls.h` from core TLS code. Only `boringssl/*.c` and `babassl/*.c` may include backend-specific headers.

## Architecture

```
xqc_tls.h          -- TLS state machine, handshake driver (used by transport)
xqc_tls_ctx.h      -- TLS context (per-engine), certificate/ALPN config
xqc_crypto.h       -- QUIC packet protection (AEAD encrypt/decrypt, header protection)
xqc_hkdf.h         -- Key derivation (Initial/Handshake/1-RTT secrets)
xqc_ssl_if.h       -- SSL backend abstraction (implemented per-backend)
xqc_null_crypto.c  -- No-op crypto for testing (no encryption)
```

## Backend Directories

| Directory | SSL Library | When Used |
|-----------|------------|-----------|
| `boringssl/` | BoringSSL (Google) | Default on macOS, recommended |
| `babassl/` | BabaSSL/Tongsuo (Alibaba) | Chinese crypto algorithm support |

Both backends implement the same 3 files: `xqc_hkdf_impl.c`, `xqc_crypto_impl.c`, `xqc_ssl_if_impl.c`.

## Common Pitfalls

- **Windows compatibility**: `xqc_tls.h` has `#ifdef XQC_SYS_WINDOWS` guards to handle wincrypt.h macro conflicts with OpenSSL types (`X509_NAME`, `X509_EXTENSIONS`, etc.). Don't remove these.
- **Key derivation ordering**: Initial secrets derive from the original DCID. After Retry or Version Negotiation, keys must be re-derived via `xqc_tls_reset_initial()`.
- **ALPN registration**: ALPNs must be registered before connection creation via `xqc_tls_ctx_register_alpn()`. Unregistered ALPNs cause handshake failure.
- **0-RTT**: Early data support requires session tickets. Check `xqc_ssl_session_is_early_data_enabled()` and `xqc_ssl_is_early_data_accepted()` for state.

## Impact & Testing

TLS changes affect all connections. Run `run_tests` (tls + crypto tests). Backend-specific changes only affect that backend's build configuration. See `docs_ai/architecture/module_dependency.md`.
