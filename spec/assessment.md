# Security assessment

An internal line-by-line review of the implementation against the [Protocol](protocol.md) and [Security](security.md) specs, published as-is. We would rather ship an honest list of residual risks than a clean-looking page. Threat model and configuration guidance live in [Security](security.md); this page is about how well the code holds up against them.

**Reviewed version:** 0.7.0 · **Date:** 2026-07 · **Reviewer:** internal (Dotex), independent of the original author

## Method

- Full read of `src/` (client, server, common, auth helpers) against every normative statement in `spec/protocol.md` and `spec/security.md`.
- Full test suite run (262 tests, including `test/security/`: handshake attacks, replay, tampering, type confusion, prototype pollution, DoS limits, deferred reset, replay window).
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

Status: **fixed in 0.7.0.** The auto-retry is removed entirely. A `TIMEOUT` or `CHANNEL` send error resets the session but is **not** resent — the error surfaces with its typed code and the caller decides whether to retry (a `TIMEOUT` is never blind-resent because the request may have executed). Guardrail (`CLIENT`) and `RemoteRPCError` never reset the session. See [Protocol § Failure handling](protocol.md#failure-handling-no-auto-retry).

### 3. Unauthenticated session teardown — fixed in 0.7.0 (with `verify`), residual in PSK-only

Before 0.7.0 a server in any state that received a `TAG_HELLO` reset its session **before** validating the hello, so a single injected garbage hello (≤ 64 KiB, no authentication needed) tore down an established session — even when `auth.verify` was configured and would reject the attacker.

Status: **fixed in 0.7.0 (deferred reset, D1).** A hello now opens a handshake attempt on attempt-local state; the live session keeps serving and is replaced only when the attempt fully validates and publishes. With `verify` configured, an attacker without a valid signature can no longer displace an established session. Residual by design: in PSK-only mode a well-formed hello still displaces (there is nothing to authenticate at hello time), and each hello still costs the server an ECDH plus an optional `verify` — denial of service stays outside the threat model, so rate-limit hellos in your channel adapter on exposed transports (on `BroadcastChannel` / `postMessage`, any same-origin code can still force handshake work). Do not put Safe RPC on a shared-origin bus you do not fully control.

### 4. No server-side concurrency cap — documented, application concern

The server has no per-request timeout and no cap on concurrent handler executions (consistent with tRPC/oRPC). An authenticated client can accumulate hanging closures by calling a slow procedure repeatedly. Bound concurrency in your handlers or in front of the server if your peers are not fully trusted.

### 5. One session key for both directions — design note

Traffic in both directions is encrypted under the same session key; there are no directional keys (`k_c2s` / `k_s2c`). A reflected frame therefore decrypts successfully and is rejected one layer up, by the message-type field (`t: 1` requests vs `t: 2` responses). This holds, and the shape check is covered by tests — but it is a weaker line of defense than directional keys, and a port that forgets the `t` check loses reflection protection entirely. Flagged for a future protocol version.

### 6. JWT mode is bearer-token auth — by design, documented

The transcript digest binds a captured auth payload to its handshake, so it cannot be replayed into a new one. It does not protect against theft of the JWT itself: anyone holding the token can open fresh handshakes until it expires. Documented in [Security § JWT](security.md#jwt-bearer-token-transcript-bound); combine with a PSK or a signature mode when this matters.

### 7. The curve dependency pin is load-bearing — documented, pinned by test

Low-order point rejection is delegated to `@noble/curves`. A future dependency release that relaxed the check would re-open the MITM attack against asymmetric-only deployments described in [Security § Ephemeral key validity](security.md#ephemeral-key-validity). The regression test exists precisely so this cannot happen silently — do not remove it, and re-run the suite on every dependency bump.

## Reporting a vulnerability

Found something not on this list? Report it privately via [GitHub Security Advisories](https://github.com/dotexorg/saferpc/security/advisories/new) rather than a public issue. We will credit reporters in the release notes unless asked otherwise.
