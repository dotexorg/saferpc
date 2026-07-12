# Design review request: session-continuity property in a lazy handshake

I'm the author of an open-source end-to-end-encrypted RPC library. I'd like a
design critique of one lifecycle property in my handshake state machine. No code
needed — this is a protocol-design question about which state transition should
carry an authentication guarantee.

## System under review

A peer-to-peer RPC library. Two endpoints share a byte channel. Payloads are
encrypted at the application layer (X25519 ECDH → HKDF-SHA-256 → XSalsa20-Poly1305
AEAD), independent of whatever transport sits underneath.

The handshake is **one round-trip and lazy** — nothing goes on the wire until the
first RPC call:

1. The initiator sends a `hello`:
   `{ epoch, pub_i, nonce_i, signature? }`
   where `epoch` is a per-attempt counter, `pub_i` is a fresh ephemeral X25519
   public key, `nonce_i` is random, and `signature` (optional) covers the
   **hello transcript**:
   `transcript = DOMAIN_TAG || epoch || pub_i || nonce_i`.

2. The responder derives the session key:
   `key = HKDF(ikm = ECDH(priv_r, pub_i), salt = PSK, info = ...)`,
   computes an HMAC proof over `(pub_r, pub_i, nonce_i)`, and replies with
   `{ pub_r, proof, epoch, signature? }`.

3. The initiator recomputes the same key, checks the proof, and is ready.

4. The responder does **not** consider the session live yet. It becomes live only
   when the **first encrypted frame decrypts and authenticates** under the new
   key. Producing a valid AEAD frame is the implicit proof that the sender
   actually holds the key material.

Two authentication modes, independently or together:

- **Shared-secret mode:** a pre-shared key (PSK) is folded into HKDF. Nothing in
  the `hello` itself is signed; possession of the PSK is proven only in step 4.
- **Signature mode:** the initiator signs the hello transcript. The verifier is
  **stateless** (e.g. Ed25519 / ECDSA over the transcript bytes) — it has no
  server-contributed value in the transcript, so it depends only on
  initiator-chosen fields (`epoch`, `pub_i`, `nonce_i`).

## The property I want to hold

> An established, live session must only be **superseded** by a counterparty that
> proves possession of the private key material (`priv_i` or the PSK). A
> **duplicate or stale `hello`** — the same bytes the library already processed
> once — must not be able to retire the live session.

Rationale: a duplicate `hello` carries no new proof of key possession. Whoever
re-sends it does not thereby demonstrate they can participate in the session, so
it should not be allowed to end the working one. This is a **liveness /
continuity** property, not confidentiality.

## Current design and where I think it's wrong

Today the responder treats every incoming `hello` as a fresh handshake *attempt*
on attempt-local state, and — importantly — the live session keeps serving while
the attempt runs. The old session is retired and replaced at the **publish step**,
which happens **right after the signature verifies and the key is derived** (i.e.
after step 2), **before** the new session is confirmed by step 4.

My concern: in signature mode the verifier is stateless over initiator-only
fields, so a **byte-for-byte duplicate `hello` verifies again**. That reaches the
publish step and retires the live session — yet the new session can never reach
step 4, because the party re-sending the duplicate does not hold `priv_i` and so
cannot derive the key or produce a valid encrypted frame. Net effect: a repeated
`hello` ends the working session and replaces it with one that is never
confirmed. That's a continuity regression, and I reproduced it: after a duplicate
`hello`, the next legitimate call on the original session fails with a timeout.

The same reasoning applies in shared-secret mode: nothing in the `hello` proves
PSK possession, so a well-formed `hello` reaches publish and supersedes the live
session there too.

## Proposed fix: promote on first authenticated frame ("make-before-break")

Keep **both** session keys alive concurrently:

- The current (old) key stays live and keeps decrypting ongoing traffic.
- A new `hello` derives a **candidate** key but does **not** retire the old one.
- Incoming encrypted frames are tried against the current key first.
- The candidate is promoted — and the old key retired — **only when the first
  frame decrypts and authenticates under the candidate key** (step 4 applied to
  the candidate).
- Unconfirmed candidates expire on a timer, leaving the live session untouched.

The claim is that step 4 is the real authentication of the counterparty:
producing a valid AEAD frame under the candidate key requires either `priv_i`
(for the ECDH) or the PSK, neither of which a party re-sending a captured/stale
`hello` possesses. So a duplicate `hello` can create a candidate that never
confirms, but can never retire the live session.

## Questions

1. Does "promote only on the first authenticated frame under the candidate key"
   fully establish the continuity property in **both** modes (shared-secret and
   stateless-signature)? Where is the reasoning load-bearing, and where could it
   leak?

2. What does make-before-break **not** cover? (e.g. resource cost of holding
   candidate state; concurrent candidates; interaction with the per-session
   nonce-dedup window that is cleared on key change.)

3. Is adding a **responder-contributed freshness value** to the hello transcript
   (so signatures aren't replayable at all) strictly better than, or complementary
   to, make-before-break? What round-trip cost does that impose on a design whose
   whole point is a single lazy round-trip, and is there a way to get freshness
   without a second round-trip?

4. Is there a cleaner framing of the underlying rule — something like "a session
   transition that ends a live session must be gated on proof-of-key-possession,
   never on a signature over counterparty-chosen fields alone"? Does that
   generalize, or are there transitions where it's too strong?
