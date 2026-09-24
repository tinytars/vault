# Architecture

This is the contract, not a tour — see `README.md`'s **What it does** for the featureset summary
an architect scans first. What follows is what a reader needs in order to adopt the package,
write a new storage adapter, or judge whether a change to an existing one is safe.

`@tinytars/vault` has three layers. Lower layers know nothing about higher ones — `kdf.ts`
never imports from `crypto.ts`, and neither imports from `stores.ts` or `envelope-access.ts`.

```
kdf.ts                     shared key-derivation primitive (PBKDF2)
   |
   v
crypto.ts   +   key-store.ts     HD1 envelope + keypair/DEK logic
                (browser-only: persists the unwrapped private key)
   |
   v
stores.ts                  five storage-agnostic contracts -- no crypto, no policy
   |
   v
envelope-access.ts   +   break-glass.ts     composed access policy -- standing / time-boxed
```

## Key derivation (`kdf.ts`)

One derivation function, shared by every envelope format that needs a password-derived key:

- **PBKDF2-HMAC-SHA256**, `200_000` iterations.
- 16-byte random salt (`SALT_LEN`), 12-byte random IV (`IV_LEN`) for the AES-GCM layer that
  consumes the derived key.
- Runtime-agnostic: `SubtleCrypto` is passed in as a parameter, not read off a global. This is
  what lets the same module run in a browser, a Cloudflare Worker, and Node's `crypto.webcrypto`
  without a shim.

200,000 iterations is an OWASP-floor PBKDF2 parameter, not an Argon2id-class one — this package
does not implement Argon2id. If you need memory-hard derivation, derive your own key upstream and
hand this module raw key bytes, or don't use this module for that path. See `THREAT_MODEL.md` for
why this tradeoff was made and what upgrading it would require (a version byte, since existing
ciphertext blobs don't carry an iteration count).

**`kdf.ts` is intentionally the only shared surface between envelope formats.** Two independent
envelope formats exist in this codebase's history (`EB1`, `HD1`); they share this derivation and
nothing else. Do not merge their framing code — that has been proposed before and is wrong: the
formats evolve on different schedules and a shared frame couples them for no benefit.

## Envelope format (`crypto.ts`)

### HD1 v1 — passphrase-only

```
MAGIC(3, "HD1") | VERSION(1)=1 | salt(16) | iv(12) | ciphertext
```

Passphrase → PBKDF2 (`kdf.ts`) → AES-GCM-256 key → encrypts the payload directly. One
passphrase, one key, no access control beyond "do you know the passphrase."

### HD1 v2 — DEK-based, multi-principal

```
MAGIC(3) | VERSION(1)=2 | vaultKeyId(16) | iv(12) | ciphertext
```

Same 32-byte header length as v1, deliberately — code that only checks magic + total length
without branching on version stays correct.

v2 separates *encrypting the data* from *granting access to it*:

1. A random per-vault **DEK** (data encryption key) encrypts the payload with AES-GCM.
2. The DEK itself is wrapped, once per principal who should be able to read the vault, via
   ECDH-ES: an ephemeral P-256 keypair does ECDH against the principal's long-term public key,
   and the resulting shared secret wraps the DEK with AES-GCM. This is functionally equivalent
   to JWE's `ECDH-ES+A256GCM`.
3. "Grant access to principal X" = wrap the same DEK again for X's public key. No secret is
   shared between principals, and revoking one principal's *future* access means deleting their
   wrapped-DEK row — it does not touch anyone else's.

### HD1 v3 — the same envelope over opaque bytes

```
MAGIC(3) | VERSION(1)=3 | vaultKeyId(16) | iv(12) | ciphertext
```

Identical to v2 in every respect except the payload: v2 carries UTF-8 JSON, v3 carries raw bytes.
It exists for payloads that are **already files** — a PDF, an image — which would otherwise have
to be base64'd into v2's JSON at a 33% cost.

`encryptBytes`/`decryptBytes` are the v3 pair. `isHD1(blob)` reads the magic alone and says whether
an object is sealed at all, which is what a store migrating from plaintext to sealed objects needs
while both formats are live.

The natural shape for per-file encryption is one random content key per file, kept inside a v2
vault blob that the file's owner already controls. The file is then sealed under a key that only a
principal who can open that vault can recover, and re-keying the vault does not mean re-uploading
the files.

`vaultKeyId` is an opaque reference into the caller's own storage (a row ID, not key material)
— resolving it to an actual wrapped DEK is the storage layer's job, not this module's.

### Account keypairs and the KEK

Each account holds a long-term ECDH P-256 keypair (`generateAccountKeypair`). The private key is
never stored raw — it's wrapped under a KEK (key-encryption key) with AES-GCM
(`wrapPrivateKey`/`unwrapPrivateKey`, operating on PKCS8 bytes). The KEK itself comes from one of
two sources, both producing an AES-GCM key of the same shape:

- **Password-derived** (`deriveKekFromPassword`) — same PBKDF2 parameters as `kdf.ts`.
- **WebAuthn PRF secret** (`kekFromPrfSecret`) — the authenticator's PRF extension output is
  imported directly as an AES-GCM key, no PBKDF2 step. This is what lets a passkey unlock the
  account without a password ever existing.

`deriveAuthHash()` produces a server-verifiable value from the same password, domain-separated
from the KEK derivation by appending `"|auth"` to the salt before the PBKDF2 call. A server can
verify a login (`SHA-256(authHash)` stored server-side) without ever learning the password or the
KEK it derives.

### Recovery-code grants (`wrapDEKWithKek`/`unwrapDEKWithKek`)

A one-time recovery mechanism: wrap a DEK under a KEK derived from a recovery code (same
AES-GCM shape as everything else here). **The wrapped blob must be deleted the moment the grant
is consumed.** AES-GCM's authentication tag lets a holder of the ciphertext verify whether a
*guessed* code was correct without needing to fully decrypt anything meaningful — leaving the
blob in place after use turns it into an online guessing oracle against the recovery code.

### Extractability is a deliberate choice, not an oversight

Keys and DEKs unwrapped by this module are `extractable`. That is intentional: an authorized
holder needs to be able to re-wrap a DEK for a newly added principal, or re-wrap a private key
under a new KEK when a login method is added. This is the same trust boundary as holding a
session DEK in memory at all — see `THREAT_MODEL.md`.

## Byte handling (`bytes.ts`)

One function, `toArrayBuffer(view: Uint8Array): ArrayBuffer`. `SubtleCrypto` takes a
`BufferSource`, and a `Uint8Array` is only safely interchangeable with its own `.buffer` when it
spans the whole thing — a view produced by `.slice()` or `.subarray()` on a larger buffer carries
a non-zero `byteOffset`, and passing `view.buffer` there silently operates on the wrong bytes
instead of failing. Every WebCrypto call in `kdf.ts` and `crypto.ts` goes through this function
rather than a per-call-site cast.

## Browser key persistence (`key-store.ts`)

The only browser-specific module in this package (everything else is runtime-agnostic). Persists
an account's unwrapped ECDH private key in IndexedDB as a **non-extractable**, structured-cloned
`CryptoKey`. The point: code running on the page (including an XSS payload) can ask the browser
to *use* the key — sign, derive, unwrap — but cannot ask the browser to hand back the raw key
bytes. This narrows what an XSS foothold can do with the persisted key without eliminating it;
see `THREAT_MODEL.md` for the boundary this actually draws.

## Conflict-safe blob persistence (`vault-sink.ts`)

`VaultSink` is a one-method interface — `put(id, blob): Promise<void>` — for persisting an
already-encrypted blob. The encryption boundary stays with the caller: a sink stores opaque
ciphertext and never sees plaintext or a key.

The reusable part of this module is optimistic-concurrency bookkeeping around that interface:

- `rememberVaultEtag`/`knownVaultEtag` track, per vault ID, the last version this context saw.
- The exported `r2Sink` implementation sends `If-Match: <known-etag>` when a version is known, or
  `If-None-Match: *` when it isn't — "replace exactly this version" or "create, and refuse if one
  already exists," never neither, so a server-side precondition check can't be silently skipped.
- A `409`/`412`-class rejection throws a typed `VaultConflictError` carrying the server's current
  ETag, distinguishable from an ordinary failure (a network error, a `5xx`) so a caller can react
  to "someone else edited this" differently from "the request failed." `setVaultConflictHandler`
  gives one hook that sees every conflict across every call site, rather than requiring each
  caller to wire its own handling.
- Writes to the same vault ID are serialized through an internal promise chain, so two saves to
  the same vault from the same browser context never race each other and report a spurious
  conflict against themselves.

`localSink` and the concrete `r2Sink` request (`/api/vault/{id}`, `/__save-vault`) are wired to
this package's originating application's own Pages Functions routes — they're included as a
working reference implementation, not something a new adopter imports and uses verbatim unless
their own routes happen to match. Implement `VaultSink` against your own endpoint and reuse the
etag-tracking/conflict-typing/serialization logic above it.

## Storage contracts (`stores.ts`)

Five interfaces, each a plain data-access contract with no crypto and no policy baked in. An
adapter (D1, Postgres, an in-memory map for tests) implements these against whatever it stores
rows in:

- **`AccountStore`** — accounts, identities, session lifecycle, profile/tombstone state.
- **`CredentialStore`** — login credentials, kept separate from `AccountStore` rather than folded
  into it, because a store implementation may back credentials with a different table or a
  different backend (e.g. a WebAuthn authenticator registry) than the account row itself.
- **`EnvelopeStore`** — vault rows and their envelopes, pure storage: get/put an envelope by
  vault ID, nothing about who's allowed to.
- **`ProviderLinkStore`** — grants between a "provider" (grantee) and a vault owner. See
  `README.md`'s **Why** section for the healthcare and beyond-health use cases this vocabulary
  covers, and § Principal model below for how this fits owner and org-recovery access.
- **`AuditStore`** — append-only access-event logging, read back by subject.

None of these five types know about each other. Composing them into a policy is a separate,
explicit step — see below.

## Principal model

Three kinds of principal exist, and only three — this is the actual list, not a subset:

1. **Owner.** Always has access to their own vault. No row, no grant, no expiry to check.
2. **Org-recovery principal.** One designated system-level fallback per vault, itself revocable
   (`orgRecoveryRevokedAt`) — for the "the owner is unreachable and something still needs to read
   this" case. Adopters without that case pass an `orgAccountId` that never matches and the branch
   never fires.
3. **Grantee.** Anyone else, via an active `ProviderLink` (`stores.ts`). A grantee comes in exactly
   two forms, both stored as the same `ProviderLink` row and resolved by the same `getActive()`
   check:
   - **Standing** — no `expiresAt`, revoked only explicitly.
   - **Time-boxed** — granted, checked, and revoked through `break-glass.ts`'s lifecycle below:
     TTL-clamped, self-expiring, always audited.

This is one model, not three unrelated mechanisms bolted together: one grant primitive
(`ProviderLink`), one resolution function (`resolveEnvelopeAccess`, next section), one audit
trail. A standing grant and a time-boxed grant differ in exactly one field — whether `expiresAt`
is set — never in how they're checked or who checks them. That single fact is why `break-glass.ts`
doesn't duplicate `envelope-access.ts`'s resolution logic; it composes the same `ProviderLinkStore`
instead.

```
resolveEnvelopeAccess(vault, principal):

  1. principal is vault.owner?                        -> allow, no row needed
  2. principal is vault.orgRecoveryAccountId
       and orgRecoveryRevokedAt is unset?              -> allow, revocable
  3. ProviderLink.getActive(vault.owner, principal)?   -> allow
       expiresAt == null   -> standing grant, revoked only explicitly
       expiresAt is set    -> time-boxed grant, see break-glass.ts below
  4. none of the above                                 -> deny
```

## Access policy (`envelope-access.ts`)

`resolveEnvelopeAccess(envelopes, providers, vaultId, principalAccountId, orgAccountId)` is the
one place this package makes an access decision, and it does so by composing `EnvelopeStore` and
`ProviderLinkStore` rather than embedding policy inside either contract:

1. The vault's owner may always access it.
2. A designated "org recovery" principal may access it, unless that vault's
   `orgRecoveryRevokedAt` is set.
3. Anyone else needs an active `ProviderLink` (`getActive`) to that vault.

This function exists specifically to fix a bug class: **expiry checked lazily, per-route, is a
bug.** A grant that a route only re-validates when it's used lets a grantee who never triggers
the self-revoking endpoint keep reading past the grant's real expiry. Composing the check once,
here, means every caller gets the same answer regardless of which route asks. Adopters without an
"org recovery" concept can ignore that branch or pass an `orgAccountId` that never matches.

**Known limitation, stated plainly:** revoking a `ProviderLink` stops the *next* read — it does
not invalidate a DEK a grantee already unwrapped and is holding in memory or in their own storage
(see the extractability note above; the same "authorized holder can re-wrap" property that makes
key rotation *possible* also means old access isn't retroactively erased just by deleting the
grant row). Forward secrecy on revoke requires DEK rotation, which this package does not yet
implement. See `THREAT_MODEL.md`.

## Time-boxed access grants (`break-glass.ts`)

The time-boxed half of the principal model above — a break-glass grant is a `ProviderLink`, not a
fourth, separate mechanism. Three functions — `grantBreakGlass`, `checkBreakGlass`,
`revokeBreakGlass` — implement the "temporary access, then it lapses or is pulled" pattern on top
of `ProviderLinkStore` and `AuditStore` (and `EnvelopeStore`, when the grant carries an envelope):

1. **Grant.** Validates the caller owns the pending link being approved, clamps the requested TTL
   to a caller-supplied `BreakGlassPolicy` (`defaultTtlHours`/`maxTtlHours`), stamps a
   caller-prefixed consent ref, optionally writes an envelope (only when the grant is
   vault-backed — a metadata-only grant carries none), flips the link active, and audits.
2. **Check.** Same non-lazy-expiry principle as `resolveEnvelopeAccess` above: a route calls this
   on every use rather than trusting the link's `status` alone. Past `expiresAt`, it runs the
   caller's `onExpire` cleanup (typically: delete the envelope, flag DEK-rotation-pending), then
   self-revokes the link and audits the expiry — so a grantee who never triggers a "check" route
   can't outlive their TTL by simply not hitting that route.
3. **Revoke.** Ends a link early from either side, idempotently: deletes the envelope (if any) and
   marks the link revoked, both safe to repeat. Auditing is conditional on `auditAction` being
   supplied — some link kinds (e.g. a primary link) carry no disclosure-audit obligation.

All three are storage-agnostic — they take `Pick<...>` slices of `ProviderLinkStore`/
`AuditStore`/`EnvelopeStore`, never a concrete adapter — and carry the same envelope-revocation
caveat as `envelope-access.ts`'s "Known limitation" above: revoking or expiring a grant stops the
*next* read, not a DEK the grantee already unwrapped. See `THREAT_MODEL.md`'s "No forward secrecy
on revoke" section, which applies here without modification.

## Adapters

Five adapters ship, each as its own subpath export, none of them imported by the core package
files above — `crypto.ts`, `kdf.ts`, `bytes.ts`, `key-store.ts`, `vault-sink.ts`, `stores.ts`,
`envelope-access.ts`, and `break-glass.ts` have zero Cloudflare (or any other platform) imports.
An adopter that never touches `@tinytars/vault/adapters/*` never links against Cloudflare's types
at all — that's the actual mechanism behind "platform-independent," not just a claim about intent.

- **`adapters/d1`** — `D1AccountStore`/`D1CredentialStore`/`D1EnvelopeStore`/`D1ProviderLinkStore`/
  `D1AuditStore`, a Cloudflare D1 (SQLite) implementation of all five `stores.ts` contracts. One
  file per interface, plus `types.ts` for the structural `D1Database` type this package declares
  itself rather than depending on `@cloudflare/workers-types` for.
- **`adapters/r2`** — `R2BlobStore`, a Cloudflare R2 implementation of `blob-store.ts`'s `BlobStore`
  interface. Maps `BlobStore`'s `{ifMatch, ifNoneMatch}` conditional onto R2's own
  `onlyIf.{etagMatches,etagDoesNotMatch}` shape; null-on-failed-precondition, not a throw, matching
  R2's observed contract (see `tests/blob-store.test.ts`'s fake bucket, and an adopter's own
  workerd-level conditional-write tests for the real thing).
- **`adapters/memory`** — full in-memory implementations of all five `stores.ts` contracts. This
  is the portability proof, not a toy: `adapters/conformance.ts`'s contract suites run against
  both this adapter and `adapters/d1` (in an adopter's own test suite, since Miniflare/`workerd`
  isn't a dependency of this package) and pass identically. A Cloudflare-free adopter can depend on
  this adapter directly, or write their own against the same `stores.ts` interfaces and reuse the
  same conformance suite to prove it.
- **`adapters/pages-http`** — `pagesHandler()`, a five-line wrapper turning a portable
  `(request, deps) => Promise<Response>` handler into Cloudflare Pages Functions'
  `onRequestX({request, env, params})` shape. The handler itself — the actual route logic — takes
  no Cloudflare types; only the thin wrapper does. This is the HTTP-layer half of platform
  independence: business logic stays portable, only the last mile adapts to the host's routing
  convention.
- **`adapters/conformance`** — shared vitest contract suites, one exported function per `stores.ts`
  interface (create/read/update roundtrip plus the documented null/not-found cases). Each takes a
  factory and can be pointed at any adapter; see `tests/adapters-memory.test.ts` in this repo for
  the pattern.

**Trust boundary per adapter**: each adapter is only as trustworthy as its backing platform's own
guarantees — `THREAT_MODEL.md` covers what this package's crypto and access-policy layers do and
don't protect against, but a D1/R2 adapter's data durability and conditional-write atomicity are
Cloudflare's guarantees, not this package's. Swapping to the memory adapter (or your own) swaps
that trust boundary too; read `THREAT_MODEL.md`'s own framing before assuming any adapter is a
drop-in security equivalent of another.

**Known gaps, not silently dropped**: a client-side, presigned-URL direct-to-storage sink (a
sibling to `vault-sink.ts`'s HTTP-`PUT` `VaultSink`, but writing straight to S3/R2 from the
browser) is not built — see `CHANGELOG.md`. And these adapters' conditional-write/transaction
semantics are verified against real D1/`workerd`/R2 only in an adopter's own test suite, not in
this package's `npm test`, which deliberately carries no Miniflare dependency.

## Reference auth client (`auth-client.ts` and friends)

Everything above this section is a primitive: composable, storage-agnostic, wired to nothing
external. `auth-client.ts`, `auth-recovery.ts`, `auth-support.ts`, `auth-grants.ts`, and
`org-recovery.ts` are the opposite kind of thing on purpose — browser-side orchestration that
composes those primitives against one specific server API shape, included because "how do these
compose into an actual signup/login/recovery flow" is exactly the part hardest to get right from
the primitives alone, and worth showing worked rather than left as an exercise.

**Dependency graph**: all five import from `crypto.ts` and `base64.ts` directly; `auth-recovery.ts`,
`auth-support.ts`, and `auth-grants.ts` additionally import `auth-client.ts`'s `bytesToBase64`/
`base64ToBytes`/`failed`/`currentAuthHashFor` helpers rather than duplicating them. `vault-session.ts`
depends on none of these five — only `crypto.ts` — and `org-recovery.ts` is the one file here that
depends on `vault-session.ts`, for the `VaultSession` type its `ensureOrgRecoveryEnvelope` takes.

### What each file orchestrates

- **`auth-client.ts`** — signup and login for both password and passkey (WebAuthn + PRF)
  credentials, a Google-SSO session bootstrap, plain-session resume, and account-settings method
  management (add/remove passkey, add Google). The shared `KDF_ITERATIONS`/`rand`/`bytesToHex`/
  `hexToBytes`/`failed`/`currentAuthHashFor` helpers the other four files import live here, not
  duplicated.
- **`auth-recovery.ts`** — the recovery-code ladder: a passphrase-style recovery code the owner
  mints in advance (`regenerateRecoveryCode`, redeemed by `recoverAccount`), and a provider-issued,
  read-down-the-phone grant code (`issueRecoveryCode`/`redeemRecoveryCode`) for the case where the
  owner has lost every credential and a provider is re-establishing access on their behalf. Also
  DEK rotation (`getVaultPrincipals`/`stageVaultRotation`/`rotateVault`) and the account's
  access-event log fetch.
- **`auth-support.ts`** — audited support-agent access: an owner approves a pending support
  request by wrapping their in-memory DEK to the agent's public key (time-boxed); a separate,
  metadata-only path lets a support agent request roster access to a *provider's* linked-owner
  list through the same request/approve shape, without ever seeing a DEK.
- **`auth-grants.ts`** — the owner-side half of provider access: look up a provider by email,
  grant them the vault by wrapping the DEK to their public key, revoke.
- **`org-recovery.ts`** — one function, `ensureOrgRecoveryEnvelope`, that backfills the
  org-recovery envelope (see `THREAT_MODEL.md`'s "org recovery principal") for a session that
  predates it or missed it at signup. Deliberately best-effort: a failure here must never block or
  fail an unlock, which is why it swallows its own errors rather than propagating them.
- **`vault-session.ts`** — the `VaultEntry`/`VaultSession` types both the provider-roster and
  support-console flows above hand to their host, plus `openVault()`, the decrypt-and-open-session
  step every unlock path (owner, provider, support) shares. The concrete `VaultSession`
  implementation — the reactive session object that actually holds these fields — is intentionally
  not here: it's UI-framework-coupled and lives in the adopting app's own frame layer. This package
  ships only the interface and the one pure function that operates on it.

### Two design choices worth reading before you adapt this

**The enumeration oracle stays closed on purpose.** Every call that authenticates an unidentified
caller — `signupPassword`, both login paths, the Google bootstrap, `recoverAccount`,
`redeemRecoveryCode` — deliberately does *not* surface the server's own error message the way
everything else here does via `failed()`. A salt/grant-salt lookup for an unregistered address
returns a decoy rather than a 404, and a client-visible "no such account" message would reopen
exactly the oracle the decoy exists to close. Once a caller has an established session, every other
function does use `failed()` and does surface the server's message — there's nobody left to
enumerate to at that point.

**Recovery has two independently-shaped codes, not one.** A 32-character alphabet excluding
ambiguous characters (`0/O`, `1/I`) produces the owner's own 20-character recovery code; a
Crockford-style alphabet produces a shorter, hyphen-grouped code meant to be read aloud down a
phone line by a provider who already holds the owner's DEK. `detectRecoveryKind()` routes a
pasted/typed string between the two ladders by stripped length alone — no shared length makes the
two ambiguous by construction. The shorter code is safe to read aloud specifically because the
server (not this package) caps attempts and expires the grant within an hour; a client-side length
choice is not itself a rate limit, and reusing that length for an unattempt-limited flow would be
a mistake.

This layer calls a specific set of routes (`/api/auth/*`, `/api/account/*`, `/api/support/*`,
`/api/providers/*`, `/api/vault/*`) that this package does not implement or specify as a contract —
the same caveat `vault-sink.ts` already carries for `r2Sink`/`localSink` above. Treat it as a
worked reference for composing the primitives into real flows, not a client SDK for an arbitrary
backend.
