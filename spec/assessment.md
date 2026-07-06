# Security assessment

An internal line-by-line review of the implementation against the [Protocol](protocol.md) and [Security](security.md) specs, published as-is. We would rather ship an honest list of residual risks than a clean-looking page. Threat model and configuration guidance live in [Security](security.md); this page is about how well the code holds up against them.

**Reviewed version:** 0.6.1 · **Date:** 2026-07 · **Reviewer:** internal (Dotex), independent of the original author

## Method

- Full read of `src/` (client, server, common, auth helpers) against every normative statement in `spec/protocol.md` and `spec/security.md`.
- Full test suite run (245 tests, including `test/security/`: handshake attacks, replay, tampering, type confusion, prototype pollution, DoS limits).
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

Ordered by how much they should influence a deployment decision. "By design" means the trade-off is deliberate and documented; "open" means a fix is planned.

### 1. Replay within a session — by design, documented

Per-message nonces are random, not counter-derived. An attacker who can inject into a live channel can replay a captured ciphertext and the receiver will execute it again. This is the protocol's one known replay window; the mitigation (idempotency keys, a server-side request-ID set) is the application's job. Full discussion in [Security § Replay within a session](security.md#replay-within-a-session).

Status: a bounded seen-nonce set on the server is planned — replays within the last N messages of a session will be dropped, narrowing the window to N without any wire change. Replays older than the window remain the application's problem; counter-based nonces (which would close it fully) require directional keys and are deferred to a future protocol version.

### 2. Auto-retry can double-execute — open bug

The client's transparent retry is specified to fire only on `TIMEOUT` or a send error. The implementation retries on **any** local error, including the `CLIENT` backpressure error (`maxPending` exceeded). Consequence, reproduced with an instrumented probe: a single backpressure error on a healthy session tears the session down, forces a re-handshake, and re-executes every in-flight call — callers observe clean success while handlers ran twice. No attacker or network fault is required.

Until the fix lands: treat non-idempotent procedures exactly as you would for risk #1 (idempotency keys), and size `maxPending` so backpressure is not hit in normal operation. Status: fix planned; the retry predicate will match the spec.

### 3. Unauthenticated session teardown — fix planned, know your transport

Per spec, a server in any state that receives a `TAG_HELLO` resets its session — this is what makes crash recovery coordination-free. The flip side: a single injected garbage hello (≤ 64 KiB, no authentication needed) tears down an established session — today the reset happens **before** the hello is validated, so this holds even when `auth.verify` is configured and rejects the attacker. Each hello also costs the server an ECDH plus an optional `verify` call. Denial of service is explicitly outside the threat model, but the practical exposure depends on the transport: on TLS-protected WebSocket an injector already owns the channel; on `BroadcastChannel` or `postMessage`, **any code in the same origin** can reset sessions in a loop. Do not put Safe RPC on a shared-origin bus you do not fully control.

Status: fix planned — the destructive reset will be deferred until the incoming hello fully validates. With `verify` configured, an attacker without a valid signature will no longer be able to displace an established session. In PSK-only mode a well-formed hello still displaces (there is nothing to authenticate at hello time); that residual stays, as does the unauthenticated-compute cost — rate-limit hellos in your channel adapter if your transport is exposed.

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
