# Design review request: auth helper surface of an RPC library

I maintain an open-source RPC library (TypeScript, runs in browser / Node /
workers over any byte transport, application-layer encryption). I need a
critique of the **authentication helper API**: its developer experience, and
specifically whether two of the five server-side helpers should exist at all.
One of them has a design gap around principal binding (described below); before
deciding how to address it I want an independent judgement on whether to keep or
remove it.

No code access needed — everything relevant is inlined.

## Core auth model

The handshake is one round-trip: X25519 ECDH → HKDF-SHA-256 → XSalsa20-Poly1305.
Authentication plugs in through a single options object, symmetric on both
sides:

```typescript
interface AuthOptions {
  /** Pre-shared secret mixed into session-key derivation (min 32 bytes). */
  secret?: () => Uint8Array | Promise<Uint8Array>;
  /** Produce a proof over the canonical handshake transcript.
      Embedded in hello (client) or reply (server). */
  sign?: (transcript: Uint8Array) => Uint8Array | Promise<Uint8Array>;
  /** Verify the counterparty's proof. Throw to reject.
      Server-side: the returned `auth` object becomes the session principal,
      exposed to every RPC handler via context. */
  verify?: (proof: Uint8Array, transcript: Uint8Array) => VerifyResult | Promise<VerifyResult>;
}
```

The transcript binds the per-handshake epoch, both ephemeral public keys
(reply direction) and the client nonce, so a signature over it ties the proof
to this specific handshake and prevents reuse of a captured proof in a
different handshake.

Applications can implement `sign`/`verify` directly — the helpers below are
convenience wrappers.

## Current helper surface

Client-side (each returns `{ sign }` to spread into the auth block):

| Helper | Payload it produces |
| --- | --- |
| `createJWTClientAuth({ getToken })` | `{ jwt, ts, th: SHA-256(transcript) }` |
| `createEd25519ClientAuth({ privateKey, deviceId })` | `{ deviceId, sig: Ed25519(transcript) }` |
| `createECDSAClientAuth({ privateKey, identifier })` | `{ identifier, sig: P-256(transcript) }` (WebCrypto, non-extractable keys) |
| `generateEd25519Keypair()` / `generateECDSAKeypair()` | key generation utilities |

Server-side (each returns `{ verify }`):

| Helper | Verifies |
| --- | --- |
| `createJWTServerAuth({ verifyToken, maxAge? })` | JWT via app callback + timestamp skew + transcript digest (const-time) |
| `createEd25519ServerAuth({ getPublicKey, validateDevice? })` | Ed25519 signature over transcript |
| `createECDSAServerAuth({ getPublicKey, validateEntity? })` | P-256 signature over transcript |
| `createCertificateServerAuth({ verifyCertificate, validateSubject? })` | app-supplied chain verification → P-256 signature over transcript with the cert's key |
| `createMultifactorServerAuth({ primary, secondary, combineAuth? })` | composes two verifiers, both must pass |

Usage:

```typescript
// client
client(channel, { auth: { ...createEd25519ClientAuth({ privateKey, deviceId }) } });
// server
server(router, channel, { auth: { ...createEd25519ServerAuth({ getPublicKey }) } });
```

## The two helpers in question

### 1. `createCertificateServerAuth`

- **No client counterpart exists.** The application must hand-assemble the
  `{ cert, sig }` payload: serialize with the library's exported msgpack
  codec, sign the transcript with WebCrypto itself. Even our own unit tests
  build the payload by hand.
- The helper delegates the security-critical part — certificate chain
  verification — entirely to an app callback
  `verifyCertificate(certBytes) → { subject, publicKey }`. What remains inside
  the helper is ~30 lines: decode payload, null-checks, one
  `crypto.subtle.verify` call over the transcript.
- That remaining signature-over-transcript step is byte-for-byte identical to
  what `createECDSAServerAuth` already does.
- We have no known downstream users (the library is young; internal consumers
  use Ed25519 and JWT modes).

### 2. `createMultifactorServerAuth` — a principal-binding design gap

- **No client counterpart either.** The application calls two sign helpers
  itself and wraps them: `mpEncode({ primary: p1, secondary: p2 })`.
- **The gap:** the two factors are verified independently against the same
  transcript, then their returned principals are combined with a default
  shallow merge `{ ...primaryAuth, ...secondaryAuth, multifactor: true }`.
  Nothing in the helper verifies that the two factors resolve to the **same**
  principal — because the generic helper does not know the schema of the auth
  objects each verifier returns (one returns `{ sub }`, another `{ deviceId }`,
  etc.). So a composition where the two factors describe *different* subjects
  still yields a single merged principal marked `multifactor: true`. For
  bearer-style factors (JWT), whose binding fields are assembled on the client
  side rather than signed by the token issuer, the helper cannot itself
  guarantee the two factors belong to one identity — that guarantee has to come
  from application code that understands the principal schema.
- Because the helper cannot know the schema, "are these two factors the same
  principal?" is logic only the application can supply.
- Options if kept:
  - (a) drop the default merge, make `combineAuth(primary, secondary)`
    **required**, and document that it must assert the two principals match;
  - (b) sequential verification: feed the first factor's verified principal
    into the second verifier so the second factor can bind to the first
    (requires changing the `verify(proof, transcript)` signature across all
    helpers);
  - (c) both.

## Questions

1. **Existence:** for each of the two helpers — keep or delete? Criteria I care
   about: does the helper carry real security weight, or does it mostly wrap
   trivial plumbing while delegating the hard part to the app; is a server-only
   half-helper worse DX than no helper (since the app already has to own the
   client side); in a security-focused library, what does a helper whose name
   implies it handles X — while the hard part of X lives in an app callback —
   signal to an integrating developer. Removing is cheap now (0.x, no known
   users); shipping a helper that invites misuse is not.
2. **If multifactor stays:** which option — required `combineAuth`, sequential
   verification, or both? Is there a composition design that is safe by default
   for a helper that structurally cannot know the principal schema, or is a
   documented "write your own `verify` that composes two sub-verifiers and
   asserts the binding explicitly" pattern the safer answer than any helper?
3. **DX of the overall auth surface:** is `{ secret?, sign?, verify? }` +
   spreadable helpers the right shape? Any rough edges in the helper ergonomics
   (naming, config fields, error behavior) from the perspective of a developer
   wiring up auth in under an hour?
4. **Cross-language angle:** the wire protocol is being specified for
   reimplementation in other languages. Helper payload schemas
   (`{ jwt, ts, th }`, `{ deviceId, sig }`, …) become de-facto wire format.
   Should helper payloads be part of the normative spec, or explicitly marked
   implementation-defined?

Constraints: pre-1.0, breaking API changes acceptable. Bias toward a minimal
surface — every helper we ship we also have to specify, test thoroughly, and
keep working in browser + Node + workers.
