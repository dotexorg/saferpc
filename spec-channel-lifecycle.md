# Spec: channel lifecycle — session survives transport death (saferpc client + channels module)

Status: ready to implement. Target: `src/client.ts`, new `src/channels/`,
`package.json` exports, four spec docs, two test files. Ships within the
unreleased 0.7.0 (no published version ever carried the old `abortPending`
semantics, so no consumer-facing break).

Decisions locked with CTO 2026-07-09:

1. **Reconnect policy: lazy on the client core.** The client does not react to
   channel recovery at all. Pending calls keep waiting for their reply under
   their own timers; if the server kept the session the replies arrive over the
   revived socket, if not the call times out and the existing
   `timeout → reset → lazy re-handshake` path heals. No eager re-handshake on
   reconnect — while `handshaking` the client drops TAG_MSG, which would kill
   the very pending calls the kept session exists to serve.
2. **`abortPending` stays, in simple form** (rejects pending, no longer zeros
   the session), **plus** a per-call `AbortSignal`, fetch-style, as an optional
   argument on every generated method.
3. **The `Channel` interface does not change.** `{ send, receive }` as today.
   The lifecycle policy is an *adapter contract*, stated in docs and shipped as
   code in a new channels module: reopen your transport immediately when it
   closes, hold it open as long as possible; while down, `send` must not throw —
   queue frames that provably never left and drop any transport error inside
   the adapter.

This document is self-contained.

---

## 1. The problem in one paragraph

Today channel death is handled by tearing the session down. The documented WS
wiring is `ws.onclose → abortPending()`, and `abortPending` rejects every
in-flight call **and zeros the session keys** (`src/client.ts`, `abortPending`
→ `zeroKeys(); state = "idle"`). That is wrong twice. First, it burns a session
that may still be perfectly valid on the server (the Enclave SessionDO case:
the DO and its session outlive any single socket) — a transient socket blip
costs a full re-handshake and rejects calls that could have completed. Second,
it makes the adapter responsible for calling into the client at the right
moment, which is exactly the API awkwardness the CTO flagged ("abortPending
неприятно юзать"). Meanwhile a `send` into a dead channel is adapter roulette:
browser `WebSocket.send()` on CLOSED silently drops (review F4), so the call
burns its whole timeout for a frame that never left, even if the socket comes
back 50 ms later. The fix: the channel owns its own liveness (reconnect
eagerly, queue never-left frames, swallow errors while down), and the client
core stops treating transport death as session death.

## 2. The property we want

> A Safe RPC session is bound to key material, not to a transport instance. The
> death of a socket must not, by itself, destroy the session or reject calls.
> A call's outcome is decided by exactly two events: a reply that decrypts, or
> the call's own timeout.

Corollary for the send path: a frame that **provably never left** the client
(submitted while the transport was down) may be flushed after reconnect — this
is the `CHANNEL`-class "never left, safe to retry" case from the 0.7.0
taxonomy, executed inside the adapter. A frame that was written to a live
socket that then died has UNKNOWN outcome and is **never** resent by anyone.
This keeps the no-auto-retry invariant (F1) intact: nothing above the adapter
retries, and the adapter only ever "retries" frames that never hit the wire.

Payoff condition, stated honestly: keeping the session across a reconnect pays
off only when the server-side session outlives the socket (long-lived server
binding, e.g. Enclave's SessionDO, or any wiring where `server()` is not
per-connection). With the common `wss.on("connection", ws => server(...))`
wiring the kept client session is dead weight after a reconnect — the first
call times out, resets, and heals. That is the same cost as today's behavior,
minus the instant rejection. The design is strictly better or equal in every
wiring.

## 3. Design part I — channels module (`src/channels/`)

New source directory, exported as a subpath so the core stays dependency-free
and tree-shakeable:

```jsonc
// package.json exports (add)
"./channels": {
  "types": "./esm/channels/index.d.ts",
  "import": "./esm/channels/index.js",
  "require": "./cjs/channels/index.js"
}
```

Files: `src/channels/index.ts` (re-exports), `src/channels/ws.ts`. The adapters
currently living as copy-paste snippets in `spec/integrations.md` migrate here
over time; WebSocket ships first because it is the one with the lifecycle trap.

### 3.1 `wsChannel(source, opts?)` — reconnecting client adapter

```ts
export interface WsChannelOptions {
  /** Max frames buffered while the socket is down. Default 256
   *  (matches the client's default maxPending). Overflow: drop-oldest. */
  maxQueue?: number;
  /** Reconnect backoff. First retry is immediate; then exponential
   *  from `backoffMin` (default 250) to `backoffMax` (default 5000) ms,
   *  full jitter. Retries forever until close(). */
  backoffMin?: number;
  backoffMax?: number;
  /** Observability only. Never affects behavior. */
  onDown?: (err?: unknown) => void;
  onUp?: () => void;
}

export function wsChannel(
  source: string | (() => WebSocket),
  opts?: WsChannelOptions,
): Channel & { close: () => void };
```

- `source` as a string uses `globalThis.WebSocket` (browser, Node ≥ 22); a
  factory covers the `ws` package and custom construction. The adapter sets
  `binaryType = "arraybuffer"` on every socket it creates.
- **Owns the socket lifecycle.** On `close` or `error` of the current socket:
  notify `onDown`, immediately create a new socket via the factory, and keep
  doing so with backoff until it opens or `close()` is called. Eager, not lazy —
  the channel does not wait for the next `send` to notice death ("сразу
  поднимать и держать открытым как можно дольше").
- **`send` never throws while down.** If `readyState !== OPEN` (covers the F4
  browser silent-drop trap: CONNECTING throws, CLOSED drops — we do neither),
  the frame goes into the queue. On `open`, the queue flushes in order, then
  `onUp` fires. Queue overflow drops the **oldest** frame silently — the
  affected call times out and heals; dropping oldest keeps the most recent
  frames (a fresh hello beats a stale encrypted request). Only frames that were
  queued (never left) are ever flushed; a frame passed to `ws.send` on an OPEN
  socket is spent regardless of what happens to that socket afterwards.
- **Errors while down are dropped inside the adapter** (per CTO: "когда канал
  закрыт любую ошибку дропать на канал"), surfaced only via `onDown` for
  logging. A synchronous `ws.send` throw on an OPEN socket still propagates —
  that is a real send failure, the client wraps it as `CHANNEL` and the
  existing reset path applies.
- `receive(cb)` registers into a callback set that survives socket
  replacement; the adapter re-attaches its single message handler to each new
  socket. The returned unsubscribe removes only `cb`.
- `close()`: stop the reconnect loop, close the current socket, drop the
  queue. After `close()`, `send` throws synchronously (client wraps as
  `CHANNEL`). This is the hook for app shutdown, wired next to `destroy()`.

### 3.2 `socketChannel(ws)` — plain single-socket adapter

The old `wsChannel(ws)` from integrations.md, renamed. No lifecycle ownership:
one socket, no reconnect, no queue. This is what the **server** side uses in
`wss.on("connection", ...)` — a server cannot reconnect a client's socket, so
its channel is one-shot by nature and `ws.on("close", destroy)` stays correct.
No server-core changes anywhere in this spec.

### 3.3 Interaction with the handshake

A hello sent while the socket is down is queued like any frame. If the socket
opens within `handshakeTimeout` (default 5000 ms) the handshake proceeds
normally. If not, the client's hs timer fails the attempt (state → `idle`) and
the stale hello may still flush later — that is safe end to end: the server
processes it as a normal hello, and under make-before-break
(`spec-make-before-break.md`) it installs a *candidate* that expires without
touching any live session; the server's reply finds the client not in
`handshaking` and is dropped by the existing gate (`client.ts`,
`tag === TAG_HELLO && state === "handshaking"`). No new residual. (Queued-frame
TTL considered and rejected — adds a clock to the adapter for a case both state
machines already absorb.)

## 4. Design part II — `abortPending` keeps the session

New semantics (`src/client.ts`):

```ts
function abortPending(err?: RPCError): void {
  if (state === "closed") return;
  const e = err ?? new RPCError("ABORTED", "Pending calls aborted");
  rejectPending(e);                 // reject all in-flight calls, clear timers
  if (state === "handshaking") {
    failHandshake(e);               // hello-waiters reject; attempt ephemerals
                                    // zeroed; state → idle. Unchanged.
  }
  // state === "ready": session keys, encrypt/decrypt, state — ALL untouched.
}
```

Diff against 0.7.0: the `else { zeroKeys(); state = "idle"; }` branch is
deleted, and the default error code changes `CHANNEL → ABORTED` (the method's
role changed from "adapter reports transport death" to "application declares
waiting pointless" — e.g. user logged out, tab hiding). Failing an in-progress
handshake still zeros that attempt's ephemerals via `failHandshake` — those are
attempt state, not a live session.

The adapter-driven use disappears from the docs: a `wsChannel` user wires
nothing on `onclose`. The method remains for the app itself.

## 5. Design part III — per-call `AbortSignal`

Fetch-style optional argument on every generated method:

```ts
export interface CallOptions {
  signal?: AbortSignal;
}

// ClientMethod gains a second optional parameter in all three branches:
type ClientMethod<TInput, TOutput> = unknown extends TInput
  ? (input?: TInput, opts?: CallOptions) => Promise<TOutput>
  : undefined extends TInput
    ? (input?: TInput, opts?: CallOptions) => Promise<TOutput>
    : (input: TInput, opts?: CallOptions) => Promise<TOutput>;
```

Semantics (all rejections use
`new RPCError("ABORTED", "Call aborted: " + prop, undefined, { cause: signal.reason })`):

- **Already aborted** at call time → reject immediately; nothing is sent, no
  handshake is triggered.
- **Abort while awaiting the shared handshake** → reject *this call*; the
  handshake itself continues (it is shared with other callers and with the next
  call). Implementation: race the `ensureHandshake()` promise against an
  abort promise; on abort, detach and reject.
- **Abort while pending** → delete the pending entry, `clearTimeout`, reject.
  A reply arriving later finds no entry and is silently dropped (existing
  behavior for unknown ids).
- **Session is never touched.** `ABORTED` must not trigger the auto-reset — the
  proxy's reset predicate already whitelists only `TIMEOUT`/`CHANNEL`, so no
  change needed there, but add the regression test (§9).
- **Outcome is UNKNOWN**, same as `TIMEOUT`: abort is client-local; the request
  may have executed on the server. Document next to the timeout caveat in
  api.md — abort does not cancel server-side execution.
- Listener hygiene: `signal.addEventListener("abort", h, { once: true })` and
  remove it on every settle path (resolve, reject, timeout), or the pending map
  leaks closures on long-lived signals reused across calls.

Taxonomy addition: `ABORTED` = client-local, "caller gave up on purpose";
retry-safety identical to `TIMEOUT` (unknown outcome). It joins `TIMEOUT`,
`SESSION`, `CLIENT`, `HANDSHAKE` as a genuinely client-local code.

## 6. What deliberately does NOT change

- **`Channel` interface** — `{ send, receive }`, untouched. The lifecycle
  contract is prose in `common.ts` jsdoc + integrations.md, and code in
  `src/channels/`.
- **Server core** — nothing. It gains `socketChannel` for convenience only.
- **Auto-reset on `TIMEOUT`/`CHANNEL` while ready** — stays exactly as in
  0.7.0. It is the heal path for the server-lost-session case and for dumb
  adapters; with a reconnecting adapter `CHANNEL` simply fires rarely.
- **No auto-retry (F1)** — stays. The only "retry" anywhere is the adapter
  flushing frames that provably never left.
- **Handshake/crypto/wire format** — untouched.

## 7. Spec/doc changes

- **integrations.md**
  - Top contract section: add the adapter lifecycle contract (reopen
    immediately on close, hold open as long as possible; while down `send`
    must not throw — queue never-left frames, drop transport errors inside the
    adapter; never resend a frame written to a live socket).
  - §WebSocket: replace the inline adapter + `onclose → abortPending` guidance
    with `import { wsChannel, socketChannel } from "@dotex/saferpc/channels"`;
    keep one inline snippet as "what the adapter does for you".
  - Fix any remaining "Safe RPC will time out and retry" phrasing (F2.3
    leftover check).
- **api.md**
  - `abortPending`: new semantics (§4) — rejects pending, session survives,
    default code `ABORTED`.
  - `CallOptions` + `signal` on every method; UNKNOWN-outcome caveat shared
    with `TIMEOUT`.
  - Error table: add `ABORTED`; update the `CHANNEL` row (no longer "also the
    default abortPending code").
  - Note under lifecycle: channel death no longer resets the session; what
    decides a call is reply-or-timeout.
- **protocol.md** §Failure handling: transport death is not a session event;
  describe the two-event outcome rule (§2) and the never-left flush exception.
- **assessment.md**: note the new residual — a stale queued hello flushing
  after handshake timeout — and why it is absorbed (§3.3); note drop-oldest
  overflow as an availability (not integrity) trade.
- **common.ts** `Channel` jsdoc: state the adapter contract in two sentences.

## 8. Migration / breaking notes (vs pre-release 0.7.0 tree)

- `abortPending` no longer returns the client to `idle` from `ready` and no
  longer zeros keys; default error code `CHANNEL → ABORTED`. Anyone who used it
  as "reset the session" should call nothing (channel death heals lazily) or
  `destroy()` (terminal).
- `test/e2e/transport-lifecycle.test.ts` (F3 block) asserts the old semantics
  — "rejects in-flight calls with CHANNEL and keeps the client usable" must be
  updated: default code becomes `ABORTED`, and add the assertion that the next
  call does **not** re-handshake (count TAG_HELLO frames — the session
  survived). The F1 retry-semantics block stays green untouched.

## 9. Tests

`test/e2e/channel-lifecycle.test.ts` — in-memory channel with down/up fault
injection (extend `test/helpers/channels.ts` with a `faultChannel` that can
`goDown()`/`goUp()` and implements the §3 contract):

1. **Call issued while channel is down completes after recovery, no
   re-handshake.** Establish session, `goDown()`, issue call (frame queues),
   `goUp()` within the call timeout. Assert: call resolves; total TAG_HELLO
   count == 1.
2. **Channel death with server session intact: pending call survives.** Issue
   call, `goDown()` *after* send, deliver the reply after `goUp()`. Assert
   resolution. (Reply-or-timeout rule, reply branch.)
3. **Channel death with server session lost: lazy heal.** `goDown()`, replace
   server with a fresh instance, `goUp()`. First call times out (`TIMEOUT`),
   second call re-handshakes and succeeds; TAG_HELLO count == 2 total.
4. **abortPending keeps the session.** Establish, issue two calls,
   `abortPending()`. Both reject with `ABORTED`; a third call succeeds with
   TAG_HELLO count still == 1.
5. **AbortSignal**: (a) pre-aborted signal rejects immediately, nothing sent,
   no handshake triggered on an idle client; (b) abort mid-flight rejects with
   `ABORTED` + `cause`, the late reply is silently dropped, a subsequent call
   succeeds without re-handshake (no reset on ABORTED — the regression for
   §5's reset-predicate claim); (c) abort of one call during a shared handshake
   rejects that call while a concurrent unaborted call completes the handshake
   and resolves; (d) listener is removed after settle (assert via a stub
   signal counting listeners, or `getEventListeners` under Node).

`test/e2e/ws-channel.test.ts` — real `ws` server:

6. **Reconnect + flush.** Kill the client socket server-side; adapter
   reconnects; a call issued during the gap resolves after reconnect (server
   session survives because the same `server()` is re-bound — use a helper
   that re-attaches the server to the new connection, mirroring the SessionDO
   wiring). Assert `onDown`/`onUp` fired once each.
7. **Queue overflow drops oldest.** `maxQueue: 2`, three sends while down;
   after reconnect the receiving side saw the last two frames.
8. **close() is terminal.** After `close()`, `send` throws; client surfaces
   `CHANNEL`.

Keep neutral naming/comments (no attack vocabulary), as with
`session-continuity.test.ts`.

## 10. Open questions for the implementer

1. **Per-call `timeout` in the same `CallOptions` bag.** ~~Review F1.3 already
   recommended a per-call timeout override as the mitigation for slow handlers
   cascading resets; the options bag now exists, so the marginal cost is ~10
   lines. Recommended: include.~~ **Resolved 2026-07-10: REJECTED by CTO.**
   The two-lever model covers all cases: a *global* timeout
   (`ClientOptions.timeout`, already configurable — the safety net that heals
   a dead session; default raised 10 s → 30 s as part of this decision) plus
   a *local* abort (`AbortSignal.timeout(ms)` via the existing `signal` —
   shorter single-call budget, `ABORTED`, no reset). A per-call field could
   only add "extend past the global timer", and the answer to that case is
   "raise the global".
2. Queue overflow policy is specced as drop-oldest (§3.1); if the CTO prefers
   loud failure, the alternative is rejecting the *new* send with `CHANNEL`
   ("never left" stays true). Drop-oldest is the current spec choice.
3. `wsChannel` factory typing across browser `WebSocket` and the `ws` package:
   type `source` against a minimal structural interface (readyState, send,
   close, addEventListener, binaryType) rather than the DOM type, so `ws`
   users don't need casts.
4. Does anything else in the codebase or Enclave call `abortPending` expecting
   the old zero-keys behavior? Grep consumers before release; the Enclave
   WS-reconnect branch is the known caller and is the direct beneficiary —
   coordinate the adapter swap there.
