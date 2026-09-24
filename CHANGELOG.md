# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This package follows
semver, but is pre-1.0 — expect breaking changes between minor versions until 1.0.0.

## [Unreleased]

### Added

- `crypto.ts` — HD1 **v3**, the same authenticated envelope over an opaque byte payload instead of
  UTF-8 JSON, for sealing payloads that are already files. `encryptBytes(data, dek)` /
  `decryptBytes(blob, dek)`, plus `isHD1(blob)` for a store that must read plaintext and sealed
  objects side by side while migrating between them. Header, key handling and GCM tag are
  identical to v2; only the version byte and the payload codec differ, so `MIN_BYTES = 32` and
  magic checks stay valid across all three versions.

- `blob-store.ts` — `BlobStore`, a generic conditional-write interface for storing an opaque
  encrypted blob by key. Server-side counterpart to `vault-sink.ts`'s browser-side `VaultSink`.
- `adapters/d1/` — `D1AccountStore`/`D1CredentialStore`/`D1EnvelopeStore`/`D1ProviderLinkStore`/
  `D1AuditStore`, a Cloudflare D1 implementation of all five `stores.ts` contracts.
- `adapters/r2.ts` — `R2BlobStore`, a Cloudflare R2 implementation of `BlobStore`.
- `adapters/memory.ts` — full in-memory implementations of all five `stores.ts` contracts, proven
  against the D1 adapter via a shared contract suite — the actual evidence "storage-agnostic"
  holds, not an assertion made by interface shape alone.
- `adapters/pages-http.ts` — `pagesHandler()`, wrapping a portable
  `(request, deps) => Promise<Response>` handler into Cloudflare Pages Functions' `onRequestX`
  shape.
- `adapters/conformance.ts` — shared vitest contract suites, one per `stores.ts` interface, run
  against `adapters/memory` here (`tests/adapters-memory.test.ts`) and against `adapters/d1` in an
  adopter's own Miniflare-backed suite.
- `tests/blob-store.test.ts` — pins `R2BlobStore`'s conditional-mapping logic against a
  hand-written fake R2 bucket.
- `auth-client.ts`, `auth-recovery.ts`, `auth-support.ts`, `auth-grants.ts`, `org-recovery.ts` —
  browser-side reference client wiring `crypto.ts` to a specific signup/login/recovery/
  support-access/grant API shape. Not a portable primitive — see `ARCHITECTURE.md`'s "Reference
  auth client" section and `THREAT_MODEL.md`'s "Not a portable client SDK".
- `vault-session.ts` — `VaultEntry`/`VaultSession` types and `openVault()`, the decrypt-and-open
  step every unlock path (owner, provider, support) shares.
- `base64.ts` — byte/base64 codec used by the client layer above.

See `ARCHITECTURE.md`'s "Adapters" section for what each one is for and what it doesn't cover.

## [0.1.0] — Initial public release

Extracted from a health-records application's internal `packages/security`. First public
version; no prior published releases.

### Added

- `kdf.ts` — shared PBKDF2-HMAC-SHA256 key derivation (200,000 iterations), runtime-agnostic.
- `bytes.ts` — `toArrayBuffer`, a `byteOffset`-safe conversion from a `Uint8Array` view to the
  `ArrayBuffer` WebCrypto calls want.
- `crypto.ts` — HD1 envelope format: v1 (passphrase-only) and v2 (DEK-based, multi-principal
  access via ECDH-ES-wrapped keys); account keypair generation; KEK wrapping of private keys from
  either a password or a WebAuthn PRF secret; one-time recovery-code grants.
- `key-store.ts` — browser IndexedDB persistence of an account's private key as a
  non-extractable `CryptoKey`.
- `vault-sink.ts` — `VaultSink` interface plus a conflict-safe (ETag/`If-Match`) HTTP `PUT`
  implementation, with per-vault write serialization and a typed `VaultConflictError`.
- `stores.ts` — five storage-agnostic contracts: `AccountStore`, `CredentialStore`,
  `EnvelopeStore`, `ProviderLinkStore`, `AuditStore`.
- `envelope-access.ts` — `resolveEnvelopeAccess`, the composed access-policy function over
  `EnvelopeStore` + `ProviderLinkStore`.
- `break-glass.ts` — `grantBreakGlass`/`checkBreakGlass`/`revokeBreakGlass`: time-boxed access
  grants over `ProviderLinkStore`/`AuditStore`/`EnvelopeStore` — TTL clamp to a policy max,
  expiry that self-revokes and audits, idempotent revoke.
- `LICENSE` (MIT), `THREAT_MODEL.md`, `SECURITY.md`, `ARCHITECTURE.md`, `CONTRIBUTING.md`.
- `tests/` — a vitest suite (57 tests across 7 files) covering every module above: KDF
  determinism and parameters, both envelope format versions and their cross-rejection, KEK
  wrapping from a password and from a passkey PRF secret, the key-store non-extractability
  guarantee, `vault-sink`'s conflict/serialization behavior, `bytes.ts`'s `byteOffset` handling,
  `resolveEnvelopeAccess`'s owner/org-recovery/provider-link decision paths, and
  `break-glass.ts`'s TTL-clamp/expiry/idempotent-revoke logic.

### Known gaps (tracked, not blocking this release)

- No forward secrecy on revoke — see `THREAT_MODEL.md`.

### Known gaps, not silently dropped

- The D1/R2 adapters' real conditional-write/transaction semantics are verified against real
  `workerd` only in a Cloudflare-hosted adopter's own test suite, not in this package's `npm
  test` — `tests/blob-store.test.ts` here pins the mapping logic against a fake bucket, not real
  R2 behavior.
- No client-side, presigned-URL direct-to-storage sink (a browser-side sibling to `vault-sink.ts`'s
  `VaultSink`, writing straight to S3/R2 instead of through an HTTP `PUT` endpoint) — left as
  future work; see `ARCHITECTURE.md`'s "Adapters" section.
