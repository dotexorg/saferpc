# SafeRPC design review — transport lifecycle, retry, error taxonomy

Scope: `src/client.ts` / `src/server.ts` / `src/common.ts` @ `a6ffecb` (0.6.1),
`spec/protocol.md`, `spec/security.md`, `spec/integrations.md`.
Trigger: the Enclave WS-reconnect work. Empirical base: an in-memory
channel with fault injection run against the published 0.6.0 build
(same lifecycle code as 0.6.1); results quoted inline as [B]/[C]/[D].

The stated goal (per CTO): *create the client api once; keep using it no
matter how often the handshake re-runs or the channel dies.*

## Verdict on the goal

The design is ~90% there already, and the remaining 10% is not "add
machinery" — it is "delete the retry and give the channel a failure
vocabulary". Specifically:

- Lazy handshake, epoch discipline, zeroization, the client state machine,
  and the server's any-hello-resets resilience are sound. Nothing below
  touches the crypto or the handshake.
- The only paths that force recreating a client today are `destroy()` and
  the (cosmetic) id-counter exhaustion. Channel death does NOT require
  recreation — it requires a way to *tell* the client about it, which is
  what `abortPending` adds.

## F1 — Remove the auto-retry; keep the auto-reset

The retry in the api-proxy `catch` conflates two failure classes with
opposite safety properties:

| class | meaning | retry safety | empirical |
|---|---|---|---|
| send error | request **never left** the client | safe | [B] send threw → transparent retry → success in 1ms, handler ran once |
| RPC timeout | request **may have executed**; reply lost | **unsafe** | [C] reply dropped → auto-retry → handler ran **twice** for one logical call, caller saw one clean SUCCESS |

[C] is silent at-least-once. For fund-moving handlers (the exact Enclave
use case: `sign`) it is a first-party double-execution mechanism layered
on top of the *documented* attacker-replay window (security.md §"only
known replay window"). The library currently duplicates requests more
reliably than an attacker could.

**Recommendation (agreed with CTO 06.07: "better to drop"):**

1. Delete the retry block in the api proxy (`catch` → `reset()` →
   `ensureHandshake()` → `sendRequest` re-send). Every failure surfaces to
   the caller with a typed code (see F2). The caller decides — it is the
   only party that knows whether the procedure is idempotent.
2. **Keep `reset()` on timeout** (reset ≠ retry). Without it a desynced
   session wedges permanently: over a sync transport (worker, iframe),
   a restarted server has no session, silently drops every TAG_MSG, and
   the client — with no channel signal available — would time out on every
   call forever. Reset-on-timeout keeps the healing lazy: the failed call
   still fails, the *next* call re-handshakes.
3. Document the surviving trade-off of (2): `reset()` nulls `decrypt`, so
   replies to *other* concurrent in-flight calls on the same session are
   dropped — one slow handler (> `timeout`) can cascade-fail its
   neighbours. Mitigations, in order of preference: per-call timeout
   override (`api.slowThing(input, { timeout })` or a per-procedure option)
   so slow procedures don't share the 10s default; accept and document.
   Do NOT fix this by delaying reset — that reopens the wedge in (2).

This also deletes the `(state as any) === "closed"` cast and the
`// @TODO: Invistigae error` artifact — both live inside the retry block.

## F2 — Give the channel a failure vocabulary (the "special error")

Today `sendRequest` propagates the raw `channel.send` rejection to the
caller (`rej(err)` in `onSendError`). Consequences: callers cannot
distinguish "transport down, request never sent, safe to retry" from
arbitrary garbage; and the client core cannot react to transport death
either.

**Recommendation — three small pieces:**

1. Export a channel error, one code, minimal:
   ```ts
   // common.ts
   export class ChannelDownError extends RPCError {
     constructor(message = "Transport down") { super("CHANNEL_DOWN", message); }
   }
   ```
   Adapters throw it from `send()` when they *know* the transport is dead
   (see F4). The client wraps any other send rejection as
   `RPCError("CHANNEL", msg, { cause })` so the caller-facing taxonomy is
   closed: `CHANNEL_DOWN` / `CHANNEL` = never sent, retryable;
   `TIMEOUT` = **outcome unknown** (may have executed — never blind-retry
   a non-idempotent call); `RemoteRPCError` = server answered;
   `HANDSHAKE` / `SESSION` as today.

2. On `ChannelDownError` from send, the client should also `reset()` —
   in every real deployment (WS + per-socket server bridge, as in the
   Enclave SessionDO) transport death implies the peer's session is gone;
   the keys are dead weight. The failed call rejects; the next call
   re-handshakes over whatever transport the adapter provides.

3. **"Fail fast vs wait for the channel to come back" is adapter policy,
   not core policy** — and the `Channel` interface already supports both
   without any core change, because `send` may return a `Promise`:
   - *fail-fast adapter*: `readyState !== OPEN → throw ChannelDownError`;
   - *self-healing adapter*: recreate the socket inside `send` and resolve
     when flushed — the pending RPC timer keeps running, so the wait
     budget is naturally capped by the call timeout;
   - *queueing adapter*: hold the promise until reconnect. Same cap.
   Keep the core dumb; document the three patterns in `integrations.md`.
   (While there: fix integrations.md §"transport is allowed to drop,
   duplicate, or reorder — Safe RPC will time out and retry" — after F1
   it times out and *reports*.)

## F3 — `abortPending` semantics (already being added)

The missing half of F2: the adapter learns about death from an event
(`ws.onclose`) at a moment when no `send` is in progress — today it has
no way to hand that knowledge to the client, and `rejectPending` is only
reachable via `destroy()`, which is terminal. Required semantics:

```ts
abortPending(err?: RPCError): void
// 1. no-op when state === "closed"
// 2. reject ALL pending with err ?? new ChannelDownError()  (clear timers)
// 3. fail an in-progress handshake with the same error
//    (otherwise hello-waiters hang until handshakeTimeout)
// 4. zeroKeys(); state = "idle"   — NOT "closed"; client stays usable
```

Return `{ api, abortPending, destroy }`. With F1+F2+F3 the full lifecycle
story becomes: *adapter throws/aborts on death → in-flight calls reject
instantly with a retryable code → next call lazily re-handshakes over the
revived transport → caller-visible client object never changes identity.*
That is exactly the stated goal.

## F4 — Browser-WS trap (documentation, but load-bearing)

`WebSocket.send()` on a CLOSED socket **silently drops** (it only throws
on CONNECTING). So over the single most common transport, the send-error
path never fires at all: without an adapter-side `readyState` check every
failure degrades into the timeout path — empirically [D]: dead socket →
RPC-timeout + handshake-timeout stacked, ≈15s with defaults, surfacing as
a misleading `HANDSHAKE "Handshake timeout"`. The WS adapter guidance in
`integrations.md` must say: check `readyState` in `send` and throw
`ChannelDownError`; wire `onclose` → `abortPending()`.

## F5 — Optional: close the documented replay window for ordered-enough transports

`security.md` accepts request replay ("only known replay window") on the
grounds that a counter scheme needs strict transport ordering. Half-true:
*dedup* does not need ordering. Request ids are already client-monotonic
integers-as-strings; a per-session bounded seen-set on the server
(e.g. LRU of the last 1024 ids, reset per epoch) rejects attacker replays
of captured ciphertexts without constraining reordering or requiring
counters on the wire. One `Set<string>` per session, ~30 lines, no
protocol change (server-side only). Worth doing since the client no
longer duplicates requests itself after F1 — the seen-set then guards a
genuinely attacker-only path. Optional; if declined, keep the current
doc language and rely on application idempotency (Enclave: `device_proof.jti`).

## F6 — Minor

- `sendRequest` starts the timeout timer before `send` resolves — an
  adapter that waits for reconnect inside `send` (F2.3) spends the call's
  own budget. Correct behaviour; document it.
- Counter-exhaustion message says "destroy and recreate client" — at one
  call per ms that is ~285k years; harmless, but the message contradicts
  the create-once philosophy. Cosmetic.
- After F1, `RemoteRPCError` handling in the proxy simplifies to a plain
  passthrough (no retry-exemption needed).

## Regression fixture

`/tmp/saferpc-transport-test/test.mjs` (in-memory channel + fault
injection, cases A–D) currently demonstrates [B]/[C]/[D] against 0.6.x.
After F1–F3 land, expected deltas: [C] → caller gets `TIMEOUT`, handler
executes exactly once; [B] → caller gets `CHANNEL`/`CHANNEL_DOWN`
immediately (no hidden retry — app-level retry of an idempotent call is
one line); [D] with a compliant WS adapter → instant `CHANNEL_DOWN` via
`abortPending` instead of 15s of stacked timeouts. Happy to port it into
`test/e2e/` as `transport-lifecycle.test.ts`.
