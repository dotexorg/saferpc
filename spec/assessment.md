# Security assessment

An internal line-by-line review of the implementation against the [Protocol](protocol.md) and [Security](security.md) specs, published as-is. We would rather ship an honest list of residual risks than a clean-looking page. Threat model and configuration guidance live in [Security](security.md); this page is about how well the code holds up against them.

**Reviewed version:** 0.7.0 · **Date:** 2026-07 · **Reviewer:** internal (Dotex), independent of the original author

## Method

- Full read of `src/` (client, server, common, auth helpers) against every normative statement in `spec/protocol.md` and `spec/security.md`.
- Full test suite run (265 tests at the review date — the suite has grown since; including `test/security/`: handshake attacks, replay, tampering, type confusion, prototype pollution, DoS limits, deferred reset, replay window, session continuity, and the 2026-07 follow-up fixes below).
- Instrumented probes for behavioral claims that the suite does not pin (execution counts, handshake counts under fault injection).

An internal review is not a third-party audit. It catches spec/code drift and design-level issues; it does not replace external cryptographic review. If you need the latter for a deployment, treat this page as the starting inventory.

## What was verified and holds

Checked line-by-line against the spec, no findings:

- **Handshake ordering.** `verify` runs before any session key material is derived on both sides; a failed verification never leaks ECDH artifacts. Every `await` in the handshake path is followed by an epoch + destroyed guard; module-level state is published only inside a synchronous block under a final guard.
- **Transcripts.** Domain-separated magic prefixes, big-endian uint32 epoch, field order — byte-for-byte per spec. An active MITM cannot substitute either ephemeral key without invalidating the corresponding signature.
- **Key derivation and proof.** `HKDF(ikm=raw ECDH, salt=secret, info="saferpc-v1")`; `HMAC(session_key, s_pub‖c_pub‖c_nonce)`; proof compared in constant time. `deriveSessionSecret` matches its spec formula.
- **Low-order X25519 points.** Rejected by `@noble/curves`, with a regression test (`test/security/f002-low-order-x25519-pubkey.test.ts`) pinning both halves of the contract: the library throws, and a forged hello carrying a low-order `pub` aborts the handshake before any session state exists.
- **Memory hygiene.** Ephemeral keys and shared secrets zeroed in try/finally; in-flight handshake attempts own copies of key material, so a concurrent reset cannot corrupt a derivation. An application `secret()` returning 32 zero bytes is refused at runtime.
- **Sanitization.** msgpack extension types rejected (including the hard-coded Timestamp), prototype-pollution keys stripped, non-plain objects rejected, recursion capped, inbound `bin` fields normalized to plain `Uint8Array` at the channel boundary.
- **Silent-drop policy.** Bad tags, oversized frames, Poly1305 failures, and malformed RPC shapes are dropped without feedback, as specified.
- **Constant-time comparisons** everywhere the spec requires them, including the JWT helper's transcript digest check.

## Residual risks

Ordered by how much they should influence a deployment decision. "By design" means the trade-off is deliberate and documented; "fixed in 0.7.0" means the 0.7.0 release closed it (see the per-risk status).

### 1. Replay within a session — narrowed in 0.7.0, residual by design

Per-message nonces are random, not counter-derived. An attacker who can inject into a live channel can replay a captured ciphertext; without a dedup window the receiver executes it again. Full discussion in [Security § Replay within a session](security.md#replay-within-a-session).

Status: **fixed (narrowed) in 0.7.0.** The server keeps a bounded seen-nonce set (`replayWindow`, default 4096) and silently drops any frame whose nonce it has already accepted in the current session — the nonce is recorded only after Poly1305 verifies, and the set is cleared on re-handshake, with no wire change. Residual by design: a replay older than the last `replayWindow` accepted messages still executes (the window is narrowed to N, not closed), so non-idempotent handlers on very long sessions should still carry idempotency keys. Counter-based nonces (which would close it fully) require directional keys and are deferred to a future protocol version.

### 2. Auto-retry double-execution — fixed in 0.7.0

Before 0.7.0 the client's transparent retry fired on **any** local error, including the `CLIENT` backpressure error, and — more fundamentally — resent a call after a `TIMEOUT` whose outcome is unknown. An instrumented probe reproduced a single backpressure error on a healthy session tearing the session down and re-executing every in-flight call, callers observing clean success while handlers ran twice.

Status: **fixed in 0.7.0.** The auto-retry is removed entirely. Exactly one trigger resets the session (without resending): a reply-timeout on a **sent** request (`RPCAbortedError` code `TIMEOUT`) — "it went out and the server never answered" is the one signal the session may be desynced. The request may have executed, so it is never blind-resent; the caller decides whether to retry. A `CHANNEL` send error is a transport event, **not** a session event — the keys stay good and nothing resets. Guardrail (`CLIENT`), `SESSION`, and `RemoteRPCError` never reset. See [Protocol § Failure handling](protocol.md#failure-handling-no-auto-retry).

### 3. Unauthenticated session teardown — fixed in 0.7.0 (both modes, make-before-break)

Before 0.7.0 a server in any state that received a `TAG_HELLO` reset its session **before** validating the hello, so a single injected garbage hello (≤ 64 KiB, no authentication needed) tore down an established session — even when `auth.verify` was configured and would reject the attacker. An interim fix (deferred reset, D1) closed the _garbage_-hello case by validating before publishing, but a **byte-for-byte replayed valid hello** still reached publish and displaced the live session with one that could never come alive — reproduced empirically: injecting a captured hello into an established session made the next call time out. In PSK-only mode a well-formed forged hello did the same.

Status: **fixed in 0.7.0 (make-before-break).** A validated hello is now installed as a _candidate_ that runs alongside the live session; the live key is retired only when a `TAG_MSG` decrypts under the candidate — proof the counterparty holds the key material. Because the server's ephemeral key is fresh per attempt, a duplicate or forged hello derives a different candidate key than the live session, so its replayed traffic can never decrypt under the candidate. A replayed or forged hello can therefore at most create a candidate that expires unconfirmed; it can no longer displace a live session in **either** mode. Regression tests: `test/security/session-continuity.test.ts` (duplicate PSK hello, duplicate signed hello, genuine-rekey first-call reply, candidate expiry). The general rule this enforces — *a transition that destroys authenticated state must be authenticated no weaker than the state it destroys* — is stated in [Protocol § Re-handshake](protocol.md#re-handshake).

Residual by design (denial of service, out of threat model): each hello still costs the server an ECDH plus an optional `verify`, and because the latest hello wins the candidate slot, a **flood** of hellos can keep overwriting the candidate and starve a legitimate peer's reconnect before its confirming frame lands. This does not touch an already-live session (make-before-break protects it), but it can delay a genuine _re_-handshake. Rate-limit hellos in your channel adapter on exposed transports (on `BroadcastChannel` / `postMessage`, any same-origin code can still force handshake work). A cheap partial mitigation — dropping byte-identical duplicate hellos via a small recent-transcript-hash cache before signature verification — is possible but not shipped. Do not put Safe RPC on a shared-origin bus you do not fully control.

### 3b. Weak-secret proof oracle — documented, pre-existing

On any well-formed hello the server returns `proof = HMAC(HKDF(raw, salt=secret), …)` before the client authenticates. An attacker who completes an ECDH with their own ephemeral knows `raw` and receives the proof, leaving the `secret` as the only unknown — which they can then brute-force **offline**. Infeasible against a random 32-byte key (2²⁵⁶); a fast dictionary attack against a password-derived secret. This is a property of the scheme (PSK as HKDF salt, server-first proof), not a code defect, and is unchanged by make-before-break. Mitigation is documentation: the `secret` must be a CSPRNG key, not a passphrase — see [Security § The secret is a key, not a password](security.md#the-secret-is-a-key-not-a-password).

### 3c. Core outbound queue — head-of-line blocking bounded by `sendTimeout`

The client core now owns the outbound queue; adapters have no internal queues. A frame that fails to send (the adapter threw) enters the core queue and is retried every 250 ms. The queue is head-of-line: if the channel is down, no later frame can pass a stuck earlier one. The bound is `sendTimeout` (default 3 s) — every queued frame fails with a definite `RPCError("CHANNEL")` if a live channel does not appear within that window. The stale-queued-hello residual (a timed-out hello flushing after handshake timeout) is gone: the core revokes queued hellos when the handshake attempt expires.

### 4. No server-side concurrency cap — documented, application concern

The server has no per-request timeout and no cap on concurrent handler executions (consistent with tRPC/oRPC). An authenticated client can accumulate hanging closures by calling a slow procedure repeatedly. Bound concurrency in your handlers or in front of the server if your peers are not fully trusted.

### 5. One session key for both directions — design note

Traffic in both directions is encrypted under the same session key; there are no directional keys (`k_c2s` / `k_s2c`). A reflected frame therefore decrypts successfully and is rejected one layer up, by the message-type field (`t: 1` requests vs `t: 2` responses). This holds, and the shape check is covered by tests — but it is a weaker line of defense than directional keys, and a port that forgets the `t` check loses reflection protection entirely. Flagged for a future protocol version.

### 6. JWT mode is bearer-token auth — by design, documented

The transcript digest binds a captured auth payload to its handshake, so it cannot be replayed into a new one. It does not protect against theft of the JWT itself: anyone holding the token can open fresh handshakes until it expires. Documented in [Security § JWT](security.md#jwt-bearer-token-transcript-bound); combine with a PSK or a signature mode when this matters.

### 7. The curve dependency pin is load-bearing — documented, pinned by test

Low-order point rejection is delegated to `@noble/curves`. A future dependency release that relaxed the check would re-open the MITM attack against asymmetric-only deployments described in [Security § Ephemeral key validity](security.md#ephemeral-key-validity). The regression test exists precisely so this cannot happen silently — do not remove it, and re-run the suite on every dependency bump.

## 2026-07 follow-up review — fixed

A second internal read (independent context) after the 0.7.0 fixes above found a
further set of defects, all fixed and pinned by `test/security/review-fixes-2026-07.test.ts` unless noted.

- **AEAD verification vs. inner-payload decode were conflated.** The server's inbound path decrypted, msgpack-decoded, and sanitized in one step, so a decode error on an otherwise-authenticated candidate frame was handled as a Poly1305 failure — the candidate never promoted and expired, contradicting the spec (a frame that passes AEAD promotes regardless of inner shape). Split into `createAeadOpener` (Poly1305 → plaintext, promotes + records the nonce) and a separate `decodePlaintext` step that runs after promotion.
- **A synchronous auth callback could overrun `handshakeTimeout`.** Expiry was tracked only by a boolean the timer sets; a `verify`/`secret`/`sign` that blocked the event loop past the budget resumed as a microtask before the timer macrotask, so its continuation still installed a candidate and sent a reply. Both sides now also check an absolute wall-clock deadline after every await (`attemptDead()` server-side, `hsDeadline` client-side).
- **Defensive limits accepted `NaN`/`Infinity`.** `maxPending`, `maxMessageBytes` (client + server), and JWT `maxAge` were not validated — `length > NaN` is always false, silently disabling the limit. All now require a finite positive integer (`maxAge`: finite ≥ 0) at construction.
- **A failed handshake-reply send left the candidate lingering.** The candidate was installed before `channel.send(reply)`; a send failure reported the error but left the candidate to expire, producing a second spurious `Handshake timeout`. The send is now guarded — on failure the candidate is dropped (if still current) and a single `HANDSHAKE` error carries the transport cause.
- **Middleware could complete without calling `next()`.** Only a double `next()` was caught; a middleware that returned a value without calling `next()` skipped the handler while the client still saw success. Completion without `next()` now yields `RPCError("MIDDLEWARE", …)`.

Separately, the `createCertificateServerAuth` and `createMultifactorServerAuth` helpers were **removed** (not fixed). Both delegated the security-critical work to an application callback (certificate chain / principal binding) while shipping a name that implied the library handled it, and neither had a client counterpart. The multifactor composer additionally merged two independently-verified principals without checking they described the same subject. The documented pattern in [Security § Custom schemes](security.md#custom-schemes-certificates-multiple-factors) replaces them: compose your own `verify` and assert the binding explicitly, where the check is visible to its author rather than hidden in a helper.

## Reporting a vulnerability

Found something not on this list? Report it privately via [GitHub Security Advisories](https://github.com/dotexorg/saferpc/security/advisories/new) rather than a public issue. We will credit reporters in the release notes unless asked otherwise.
