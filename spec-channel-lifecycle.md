# Spec: channel lifecycle v2 — session survives transport death, core owns the send queue

Status: ready to implement. Supersedes v1 (2026-07-09) after CTO review of
PR #2 (2026-07-10). Target: `src/client.ts`, `src/common.ts`,
`src/channels/`, spec docs, tests. Ships within the unreleased 0.7.0.

Decisions locked with CTO 2026-07-10:

1. **`abortPending` is removed entirely** (v1 kept it in simple form). The
   per-call `AbortSignal` covers the use case: an app that wants "reject all
   in-flight calls" holds one `AbortController` and passes its signal to every
   call — `ctl.abort()` is `abortPending()` with none of the API surface. The
   method was historically the transport hook (`ws.onclose → abortPending`),
   which is exactly the antipattern this work kills; removing it removes the
   footgun physically.
2. **New error class `RPCAbortedError extends RPCError`** — the caller must
   know deterministically whether the request reached the wire.
   `RPCAbortedError` = "the request was handed to a live transport; outcome
   UNKNOWN — it may have executed, check before retrying". Plain `RPCError`
   (local) = "the request provably never left this process; retry freely".
   `RemoteRPCError` (unchanged) = "the handler ran and returned an error".
   Details and the DX rationale in §5.
3. **Channels own no queue — queueing inside a transport adapter is an
   antipattern.** The `Channel` contract flips: `send` MUST throw (or reject,
   for async adapters) when it cannot hand the frame to a live transport
   right now. The client core owns the outbound queue and retries unsent
   frames until a new **`sendTimeout`** (default 10 000 ms) expires. The
   channel's only jobs: move frames, and try to stay available
   (auto-reconnect stays in `wsChannel`).
4. **Unchanged from v1:** lazy reconnect policy (the client core does not
   react to channel recovery; pending calls wait under their own timers, a
   lost server session heals via `timeout → reset → lazy re-handshake`);
   the `Channel` interface shape `{ send, receive }`; the two-lever timeout
   model (global `timeout` 30 s + per-call `AbortSignal.timeout(ms)`); no
   auto-retry of frames that reached the wire (F1).

This document is self-contained; v1 content still valid is restated.

---

## 1. The problem in one paragraph

Two gaps remain after the v1 implementation (543d4f9). First, a caller
catching an error today cannot tell whether the request reached the server:
`TIMEOUT` is documented as unknown-outcome, `CHANNEL` as never-left, but the
send/queue split lived inside the adapter — a frame sitting in `wsChannel`'s
private queue when the call timed out was reported `TIMEOUT` (unknown) even
though it provably never left. The retry decision — the single most important
thing an RPC error must support — required reading docs and trusting adapter
internals. Second, the adapter-owned queue duplicates state the core already
has (the pending map bounds it, the call timers race it) and puts the
"never-left" bookkeeping in the one place the core cannot see. Moving the
queue into the core makes the sent/unsent boundary a fact the core *knows*
rather than infers, and shrinks the adapter contract to one line: send or
throw.

## 2. The property we want

> A Safe RPC session is bound to key material, not to a transport instance.
> A call's outcome is decided by exactly two events: a reply that decrypts,
> or a terminal local event (timeout, abort, destroy). Every rejection states
> on which side of the wire the request died: `RPCAbortedError` = it left,
> outcome unknown; plain local `RPCError` = it never left, retry freely.

The **sent boundary** is defined as: `channel.send(frame)` returned without
throwing (sync adapters) or its promise resolved (async adapters). Before
that point the core holds the only copy of the frame and can discard it with
certainty; after that point the frame's fate is unknowable and it is never
resent by any layer.

## 3. Design part I — the channel contract (revised) and `src/channels/`

### 3.1 Contract (goes into `common.ts` `Channel` jsdoc + integrations.md)

- `send(frame)` MUST throw synchronously (or reject, if it returns a
  promise) when it cannot hand the frame to a live transport **now**. No
  internal queues, no buffering, no retry — a channel that accepts a frame it
  cannot deliver lies to the core about the sent boundary.
- A channel SHOULD try to stay available: reopen its transport eagerly when
  it dies, hold it open as long as possible. Availability is the channel's
  job; delivery bookkeeping is the core's.
- `receive(cb)` unchanged: register a frame callback, return unsubscribe.

### 3.2 `wsChannel(source, opts?)` — reconnecting client adapter (revised)

```ts
export interface WsChannelOptions {
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

Diff against the v1 implementation:

- **The queue is deleted** (`maxQueue` option gone, drop-oldest policy gone,
  flush-on-open gone). `send` while `readyState !== OPEN` — or after
  `close()` — **throws synchronously**. This also covers the F4 browser trap
  (CLOSED silently drops, CONNECTING throws): the adapter checks readyState
  itself and throws one typed error for every not-OPEN state.
- Everything else stays: owns the socket lifecycle, eager reconnect with
  backoff until `close()`, `binaryType = "arraybuffer"`, `receive` callbacks
  survive socket replacement, `onDown`/`onUp` observability, `close()` stops
  the loop and closes the socket.

### 3.3 `socketChannel(ws)` — plain single-socket adapter (revised)

One socket, no reconnect (server side / caller-managed sockets). Change:
`send` must check `readyState` and throw when not OPEN instead of delegating
to `ws.send`'s platform-dependent behavior. `ws.on("close", ...)` server
wiring stays as is — the server core is untouched.

### 3.4 Handshake frames

The hello goes through the same core outbound queue (§4). If the channel is
down, the hello is retried like any frame; the attempt is bounded by
`handshakeTimeout` (5 s), which fires first and **removes the queued hello**.
This deletes v1's accepted residual (a stale hello flushing after handshake
timeout) — the core owns the queue, so it can revoke frames; an adapter
queue couldn't.

## 4. Design part II — core outbound queue + `sendTimeout`

New `ClientOptions` field:

```ts
/** How long a frame may wait for a live channel before the call fails
 *  with a definite "never sent" error. Default 10_000 ms. */
sendTimeout?: number;
```

Send path in `sendRequest` (and the hello path in `ensureHandshake`):

1. Try `channel.send(encrypted)` immediately. Success (no throw / resolved
   promise) → the call is **sent**: it waits for reply-or-timeout exactly as
   today.
2. On sync throw or async rejection → the frame enters the **outbound
   queue** with its call context. The call's global timer keeps running.
3. A retry tick (fixed 250 ms interval, running only while the queue is
   non-empty) attempts queued frames **in order**; first throw stops the
   tick's pass (head-of-line: if the channel is down for one frame it is
   down for all). A frame that sends transitions its call to *sent*.
4. Terminal events on a **still-queued** frame remove it from the queue and
   reject the call with a **plain** `RPCError` — the frame provably never
   left:
   - `sendTimeout` expiry (per-frame, counted from enqueue) → code
     `CHANNEL`, message "not sent within sendTimeout".
   - global `timeout` fires first (only possible when `timeout` is
     configured below `sendTimeout`) → code `CHANNEL`, plain class —
     same definite never-left code as sendTimeout expiry.
   - per-call signal abort → code `ABORTED`, plain class.
   - `destroy()` → code `SESSION`, plain class.
   - session reset (epoch bump, §6) → code `CHANNEL`, plain class — the
     frame is encrypted under zeroed keys and can never succeed.
5. Terminal events on a **sent** call reject with `RPCAbortedError` (§5).

Bounding: the queue needs no own limit — `maxPending` (256) already bounds
in-flight calls, and at most one hello can be queued per handshake attempt.

Defaults sanity: `sendTimeout` (10 s) < `timeout` (30 s), so with default
config an unsent frame normally fails via the sendTimeout expiry. But the
`CHANNEL` code does not depend on which timer fires first: if the global
`timeout` beats `sendTimeout` (custom config), the still-queued frame is
removed and rejected with the same plain `RPCError("CHANNEL")`. Plain
`TIMEOUT` therefore never occurs — the `TIMEOUT` code always means "sent,
no reply" and always rides the aborted class.

The queue holds encrypted frames (encryption happens at call time, as
today); the epoch captured at call time (`sentEpoch`) identifies frames
staled by a reset.

## 5. Design part III — error taxonomy: `RPCAbortedError`

### 5.1 Shape

```ts
// common.ts
export class RPCAbortedError extends RPCError {}
```

No new fields. The class carries the one bit that decides retry safety; the
existing `code` string keeps naming the trigger. Constructor signature
identical to `RPCError` (code, message, data?, options?).

### 5.2 The full local-error table

| class | code | trigger | wire status |
|---|---|---|---|
| `RPCAbortedError` | `TIMEOUT` | global timeout, frame was sent | UNKNOWN — check, then retry |
| `RPCAbortedError` | `ABORTED` | signal fired, frame was sent | UNKNOWN — check, then retry |
| `RPCAbortedError` | `SESSION` | `destroy()`, frame was sent | UNKNOWN — check, then retry |
| `RPCError` | `CHANNEL` | sendTimeout or global timeout expired while still queued / channel closed / reset staled a queued frame | never left — retry freely |
| `RPCError` | `ABORTED` | signal fired before send (incl. during handshake wait, pre-aborted signal) | never left — retry freely |
| `RPCError` | `SESSION` | `destroy()` before send / call on closed client | never left |
| `RPCError` | `CLIENT` / `HANDSHAKE` | guardrails / handshake failure | never left |
| `RemoteRPCError` | server-defined | handler ran and threw | executed |

Invariant, stated once in api.md and enforced by tests: **class = which side
of the wire the request died on; code = what killed it.** The same code can
appear in both classes (`ABORTED`, `SESSION`) — that is by design, the
trigger and the retry-safety are orthogonal axes. `TIMEOUT` appears only
on the aborted class: a still-queued frame that runs out of time fails
with the definite `CHANNEL` code, whichever timer fired.

Caller-facing catch block, the whole point of the feature:

```ts
try {
  await api.transfer(input, { signal });
} catch (e) {
  if (e instanceof RemoteRPCError) {
    // executed, server said no
  } else if (e instanceof RPCAbortedError) {
    // may have executed — reconcile state before retrying
  } else {
    // never reached the server — safe to resend as-is
  }
}
```

### 5.3 DX rationale (variants considered, per review ask)

- **Code-only (`code === "ABORTED"`), no subclass** — rejected: no
  `instanceof` narrowing, and it conflates trigger with retry-safety
  (timeout-after-send and timeout-before-send would need distinct invented
  codes; stringly-typed checks spread through consumer code).
- **Boolean field on `RPCError` (`err.sent`)** — rejected: carries the bit
  but is invisible at the catch site, not discoverable from types, easy to
  ignore; a flag does not force the three-way decision the way the class
  hierarchy does.
- **Subclass with a dedicated `reason` field and a single fixed code** —
  rejected: `reason` duplicates the existing `code` machinery; two parallel
  trigger vocabularies is worse than one.
- **Chosen: bare subclass, codes preserved across the boundary.** One
  `instanceof` = the retry decision with type narrowing; `code`/`message`/
  `cause` = diagnostics, unchanged semantics; zero new fields; symmetric
  codes make logs readable ("ABORTED before send" vs "ABORTED after send" is
  the class name in the stack trace).

`RemoteRPCError extends RPCError` already exists; `RPCAbortedError` is a
parallel branch. `instanceof RPCError` still catches everything — existing
consumer code keeps working.

## 6. Auto-reset predicate (revised)

Today: reset on `code === "TIMEOUT" || code === "CHANNEL"` while `ready`.
New predicate: **reset only on `RPCAbortedError` with code `TIMEOUT`** —
"the request went out and the server never answered" is the one signal that
the session may be desynced (server restarted, session dropped: the reply
can't come). Everything else must NOT reset:

- plain `CHANNEL` (never left) — the transport was down; that is not a
  session event, the keys are fine. Note this loses nothing: the old
  CHANNEL-reset could only heal if a re-handshake could send, and if send
  throws for 10 s the hello can't leave either; the first *sent* call that
  times out still resets. The wedge case in the current comment (restarted
  server silently dropping TAG_MSG over a sync transport) sends fine and
  fails by reply-timeout → still resets.
- `ABORTED` (either class) — caller-local decision, existing rule.
- `SESSION`/`CLIENT`/`HANDSHAKE`/`RemoteRPCError` — existing rule.

`reset()` itself gains one duty: reject **queued unsent** frames plain
`CHANNEL` (§4.4) — they are ciphertext under zeroed keys. Sent-pending calls
stay untouched, exactly as today (their replies can't decrypt post-reset;
they fail by reply-timeout → `RPCAbortedError("TIMEOUT")`, which is the
correct classification — they did leave).

`destroy()` splits the pending map by the sent flag: sent →
`RPCAbortedError("SESSION", ...)`, queued → plain `RPCError("SESSION", ...)`.
Hello-waiters were never sent as calls → plain.

## 7. What deliberately does NOT change

- **`Channel` interface shape** — `{ send, receive }`. Only the prose
  contract flips (§3.1). Async `send` stays supported (the core already
  handles a returned promise).
- **Server core** — nothing.
- **No auto-retry of anything past the sent boundary (F1)** — the core
  retries only frames it still exclusively owns; a frame written to a live
  transport is spent.
- **Per-call `AbortSignal` semantics** (v1 §5) — all of it: reject-not-
  cancel-handshake, listener hygiene, no reset on abort. Only the rejection
  class now depends on the sent flag.
- **Handshake/crypto/wire format** — untouched.
- **Two-lever timeout model** — global `timeout` + `AbortSignal.timeout()`.
  `sendTimeout` is not a third caller lever; it is the definite/unknown
  boundary inside the machine.

## 8. Spec/doc changes

- **api.md**: delete `abortPending` (§ returns, § failure handling); add
  `RPCAbortedError` + the §5.2 table + the catch-block idiom; add
  `sendTimeout` to `ClientOptions`; error-code table gets a "class" column;
  migration note "abortPending → shared AbortController".
- **protocol.md**: delete the `### abortPending` section (it still describes
  pre-0.7.0 zero-keys semantics — stale either way); §Failure handling:
  state the sent-boundary rule (§2), the queue-in-core design, the revised
  reset predicate; update the checklist line that still says abortPending
  returns the client to `idle`.
- **integrations.md**: adapter contract section replaced by §3.1 (send or
  throw, no queues, stay available); `wsChannel`/`socketChannel` docs lose
  the queue paragraphs.
- **assessment.md**: remove the stale-hello residual (fixed by §3.4) and the
  drop-oldest availability trade (queue no longer exists); add: head-of-line
  blocking on the core retry tick is bounded by `sendTimeout`.
- **common.ts**: `Channel` jsdoc = §3.1 contract in three sentences;
  `RPCAbortedError` jsdoc = the invariant sentence from §5.2.

## 9. Migration / breaking notes (vs 543d4f9, all pre-release)

- `abortPending` removed from the client return type. Replacement: shared
  `AbortController` passed per call.
- `wsChannel` `maxQueue` option removed; `send` now throws while down.
- New `ClientOptions.sendTimeout` (default 10 000 ms).
- `ClientOptions.timeout` default raised from 10 000 to 30 000 ms. The old
  short default doubled as a UX budget when a timeout auto-healed via
  reset+retry; without auto-retry the per-call UX cap belongs to
  `AbortSignal.timeout(ms)`. Pin `timeout: 10_000` to keep the old cadence.
- `CHANNEL` no longer triggers auto-reset; reply-timeout now surfaces as
  `RPCAbortedError` (still `code === "TIMEOUT"`, so code-based consumer
  checks keep working).
- Tests asserting `abortPending` (transport-lifecycle F3 block,
  channel-lifecycle §4 case, session-continuity usage) are rewritten against
  the shared-controller idiom or dropped.

## 10. Tests

`test/e2e/channel-lifecycle.test.ts` (rework; `faultChannel` helper now
implements the §3.1 contract — `send` throws while down):

1. **Call issued while channel is down completes after recovery, no
   re-handshake.** Establish, `goDown()`, call (frame queues in core),
   `goUp()` within `sendTimeout`. Resolves; TAG_HELLO count == 1.
2. **Pending call survives a gap after send.** Send, `goDown()`, `goUp()`,
   deliver reply. Resolves. (Reply-or-timeout, reply branch.)
3. **Lazy heal on lost server session.** First call fails
   `RPCAbortedError("TIMEOUT")`; second call re-handshakes and succeeds;
   TAG_HELLO == 2.
4. **sendTimeout: definite failure.** `goDown()`, call, stay down past
   `sendTimeout` → plain `RPCError("CHANNEL")`, NOT RPCAbortedError; session
   not reset (next call after `goUp()` succeeds, TAG_HELLO still 1).
5. **Class split on abort.** (a) abort while frame queued → plain
   `ABORTED`; (b) abort after send → `RPCAbortedError("ABORTED")` + cause;
   late reply dropped; no reset either way.
6. **Class split on destroy.** One call sent, one queued (channel down);
   `destroy()` → sent rejects `RPCAbortedError("SESSION")`, queued rejects
   plain `RPCError("SESSION")`.
7. **Reset predicate regression.** Reply-timeout (sent) → next call
   re-handshakes (reset happened). Plain CHANNEL (never sent) → next call
   does NOT re-handshake.
8. **Stale hello is revoked.** Channel down, first call queues a hello,
   `handshakeTimeout` fires → attempt fails; `goUp()` → queue does not flush
   the dead hello (assert no TAG_HELLO frame from the failed attempt reaches
   the server); next call sends a fresh hello.
9. **Shared-controller idiom replaces abortPending.** Two calls with one
   controller's signal; `ctl.abort()` rejects both (`ABORTED`, class per
   sent status); a third call succeeds without re-handshake.

`test/e2e/ws-channel.test.ts` (rework):

10. **Contract: send throws while down and after close().** Kill socket
    server-side; `send` throws until reconnect completes; after `close()`
    throws forever.
11. **Reconnect + core retry end-to-end.** Kill socket; call during the gap
    resolves after the adapter reconnects (core tick re-sends); `onDown`/
    `onUp` fired once each; TAG_HELLO == 1.

Keep neutral naming/comments, as with `session-continuity.test.ts`.

## 11. Open questions for the implementer

1. Retry tick granularity: fixed 250 ms is specced (not configurable — avoid
   knob creep; `sendTimeout` is the caller-visible contract). Revisit only
   if a sync-transport test shows the 250 ms floor hurting.
2. `RPCAbortedError` export surface: export from the package root alongside
   `RPCError`/`RemoteRPCError` (it is part of the public catch idiom).
3. Grep Enclave for `abortPending` consumers before merging the removal —
   the WS-reconnect branch there was the known caller; it migrates to
   `wsChannel` + shared controller.
4. Async-send adapters: a rejection arriving *after* the sent boundary was
   already counted (promise resolved) is impossible by contract; a rejection
   is always pre-boundary and re-enqueues the frame at the head of the
   queue. State this in the `Channel` jsdoc so adapter authors reject
   rather than resolve-then-error.
