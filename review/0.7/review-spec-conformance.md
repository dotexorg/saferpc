# Review: spec ↔ implementation conformance (0.6.1)

Scope: does the library do what README + `spec/*.md` claim. Companion to
`review-transport-lifecycle.md` (F1–F6, transport/lifecycle design). Findings
here are numbered C1–C10. Method: full read of `src/`, all five specs, README;
suite run (245/245 green); one instrumented probe for the main behavioral claim.

**Overall verdict:** the crypto core, handshake, sanitization, and auth helpers
match the spec closely — ordering of auth-before-key-material, epoch guards
after every await, transcript layout, HKDF/HMAC parameters, zeroing discipline
all check out line-by-line. The gaps are concentrated in one behavioral bug in
the client retry path (C1), one dangerous stale instruction in the normative
protocol doc (C2), and a handful of doc overclaims.

---

## C1 — Auto-retry fires on ANY local error, not just TIMEOUT / send error. Empirically causes silent double execution. 🔴

**Spec:** protocol.md §Auto-retry semantics and api.md §Auto-retry both say:
"A call that fails on a `ready` session with a local **`TIMEOUT` or send
error** triggers a single retry." `RemoteRPCError` excluded.

**Code:** `client.ts` `call()` catch block excludes only `RemoteRPCError` and
`closed`. Everything else — including `RPCError("CLIENT", "Too many pending
requests")` and the counter-exhaustion `CLIENT` error — goes through
`reset()` + re-handshake + resend:

```ts
if (err instanceof RemoteRPCError) throw err;
if (epoch === sentEpoch) reset();   // ← also reached by CLIENT errors
```

**Empirical probe** (in-memory channel, `maxPending: 4`, 4 in-flight slow
calls + 1 overflow call):

```
{ helloCount: 2, execCount: 8, results: ["done","done","done","done"] }
```

One `CLIENT` backpressure error on a **healthy** session produced:

1. A second handshake (`helloCount: 2`) — the good session key was zeroed and
   the server reset, for no wire-level reason.
2. The server's in-flight responses were dropped by the epoch guard, so all
   4 pending calls timed out and retried: **8 executions for 4 calls**, with
   every caller seeing clean success. This is the F1 double-execution hazard
   from the transport review, but triggered *locally* by backpressure — no
   attacker, no network fault needed.
3. The overflow call itself still failed with `CLIENT` (pending was still
   full at retry time), so the reset bought nothing.

The existing `test/security/dos-attacks.test.ts` backpressure test passes
while masking this: it asserts final values only, and the doubled executions
still eventually resolve `"done"`.

**Fix:** make the retry predicate match the spec. Retry only when
`err instanceof RPCError && err.code === "TIMEOUT"` or when the rejection came
from `channel.send` (tag send-path rejections with a distinct code, e.g.
`CHANNEL`, instead of re-throwing raw). Never reset on `CLIENT`. Add an
exec-count assertion to the backpressure test. Note: if F1 from the transport
review is adopted (drop retry-on-timeout entirely), this collapses into the
same change.

## C2 — protocol.md instructs ports to zero the application's PSK buffer. Code and security.md say the opposite. 🔴 (doc, but normative)

protocol.md §Handshake step 7: **"Zero `raw` and PSK bytes."**

Code (both `client.ts` and `server.ts`):

```ts
// The caller owns the secret buffer's lifecycle — do NOT mutate it.
// A `() => sharedSecret` pattern would break on the next handshake.
```

security.md agrees with the code: "Safe RPC reads it during HKDF and never
mutates it."

protocol.md declares itself normative ("this document is the contract — the
code follows it"). A conformant port following step 7 literally would zero the
app's secret buffer after the first handshake and break every subsequent
handshake for the common `secret: () => staticBuffer` pattern — and it would
do so silently on the peer's side (proof mismatch / handshake failures).
Fix protocol.md: "Zero `raw`. Do NOT zero the secret bytes — the application
owns that buffer."

## C3 — Epoch: spec says "wrap modulo 2³²", code throws instead 🟡

protocol.md step 1: "increment on every handshake attempt; **wrap modulo
2³²**." Code: `epoch++` unbounded. At `epoch > 0xffffffff`:

- sign-mode client: `encodeEpoch` throws `INVALID_DATA` inside
  `buildHelloTranscript` → handshake fails forever (no wrap, no recovery).
- secret-only client: epoch goes on the wire unvalidated; the **server**
  rejects it (`Invalid epoch`) → silent reset loop until client timeout.

4 billion handshake attempts is theoretical for a browser tab, less so for a
long-lived server-to-server client auto-retrying against a dead peer for
months. Cheapest fix is code-side wrap (`epoch = (epoch + 1) >>> 0` with a
skip of 0 if you want to preserve "starts at 1"), or change the spec to
"error out" and document the ceiling.

## C4 — Send errors surface raw, spec promises RPCError 🟡

api.md §Errors: "`RPCError` is thrown for local failures: timeout, session
destroyed, handshake failure, validation failure, **channel error**."

Code: `sendRequest`'s `channel.send` rejection is re-thrown as-is. On the
first attempt it's swallowed by the retry; but the *second* attempt's send
failure surfaces the adapter's raw error (a bare `Error`, a DOMException,
whatever the transport throws) to the caller. Callers following the documented
`instanceof RPCError` pattern will hit their `else { throw err }` branch on
what is by the spec's own taxonomy a local failure. Wrap send-path rejections
in `RPCError("CHANNEL", ..., { cause })` — which also gives C1 its clean
retry predicate.

## C5 — Client-side error-handling docs list `INPUT_VALIDATION` as a local failure 🟡

README quick-start catch comment: `// Local failure: TIMEOUT, SESSION,
HANDSHAKE, INPUT_VALIDATION, ...`. Same framing in api.md's "Standard local
error codes" table without noting the side.

Input validation runs on the **server**. The client never validates locally,
so `INPUT_VALIDATION` always arrives wrapped as `RemoteRPCError` — the *other*
branch of the documented pattern. Anyone writing
`if (err instanceof RPCError && err.code === "INPUT_VALIDATION")` after
`instanceof RemoteRPCError` handled the first branch will have dead code.
One-line fix in README; api.md table could gain a "side" column
(`INPUT_VALIDATION` / `OUTPUT_VALIDATION` / `MIDDLEWARE` / `NOT_FOUND` are
server-local, surface remotely).

## C6 — protocol.md "Test vectors" section overclaims 🟡

"The reference implementation's `test/security` and `test/unit` directories
contain canonical fixtures: known `(c_priv, c_pub, c_nonce, s_priv, s_pub,
secret)` inputs and the resulting `session_key` and `proof`."

They don't. `derive-proof.test.ts` and friends are property-based over
`randomBytes` (determinism, divergence, length). There is not a single fixed
known-answer vector in the repo. A porter reading this section will go looking
for fixtures that don't exist. Either add one KAT file (a real deliverable —
one fixed input set, expected `session_key`, `proof`, and a canonical
encrypted frame) or soften the section to "derive vectors from the reference
implementation".

## C7 — `getting-started.md`: "The only peer dependency is zod" — zod is a hard dependency 🟡

package.json puts `zod` in `dependencies` (along with `@msgpack/msgpack`,
`@noble/*`). There are no `peerDependencies` at all. So (a) "peer dependency"
is the wrong term, and (b) "or any library exposing `.safeParse()`" is only
true for the schema *objects* you pass in — you cannot swap the dependency
out; zod ships regardless. README's phrasing ("`@noble/*` crypto,
`@msgpack/msgpack`, `zod`, and nothing else") is the accurate one. Align
getting-started with it. (If duck-typed schemas are a real design goal, zod
could genuinely become an optional peer — `common.ts` only uses `ZodType` as a
type and calls `.safeParse()`.)

## C8 — Leftover in published source: `@TODO: Invistigae error` 🟢

`client.ts` retry path:

```ts
if ((state as any) === "closed") throw err; // @TODO: Invistigae error
```

The `as any` is masking a real question — TypeScript narrowed `state` to a
type that "can't" be `closed`, but the await points in the try block mean it
can. The cast is correct at runtime; the TODO (and typo) shipped in `files:
["src"]` to npm. Investigate, replace with a comment explaining *why* the
narrow is wrong, drop the `any`.

## C9 — `Channel.receive` return type: docs stricter than code 🟢

README, api.md, integrations.md all show `receive(cb): () => void` ("returns
unsubscribe"). `common.ts` accepts `(() => void) | void` and both sides handle
the void case (`unsubscribe?.()`). Harmless leniency, but the spec is the
contract for adapter authors — either document that void is tolerated (leak
warning: without an unsubscribe, `destroy()` can't detach the listener) or
tighten the type.

## C10 — Frame-size boundary off-by-one vs constant table 🟢

protocol.md's constant table: `MAX_HELLO_BYTES` = "Max size of a handshake
frame **(post-tag)**". Code compares the *whole* frame including the tag byte
(`data.length > MAX_HELLO_BYTES`), so the effective post-tag maximum is
65,535. Same pattern for `MAX_MSG_BYTES` (there the spec text "len(frame) ≤
MAX_MSG_BYTES" matches the code — it's the hello table annotation that's off).
Cosmetic for the reference implementation; matters for byte-exact port
conformance tests. Fix the table annotation.

---

## What was checked and found conformant (no findings)

- **Handshake ordering:** verify-before-key-material on both sides; epoch +
  destroyed guard after every await; final publish under a synchronous block.
  Matches the implementation checklist item-for-item.
- **Transcripts:** magic prefixes, big-endian uint32 epoch, field order —
  byte-for-byte per spec. Domain separation hello/reply present.
- **KDF/proof:** `HKDF(ikm=raw, salt=psk, info="saferpc-v1")`,
  `HMAC(session_key, s_pub‖c_pub‖c_nonce)`, constant-time compare. Matches.
- **`deriveSessionSecret`:** ikm=secret, salt=sessionId,
  info="saferpc-session-v1". Matches spec formula.
- **Sanitization:** depth 32, ext types rejected incl. Timestamp -1, poison
  keys stripped, non-plain objects rejected, null-proto rebuild, `bin`
  normalization at the channel boundary (`toPlainBytes`) on both sides.
- **State machines:** server waiting→pending→ready with ready-on-first-valid-
  decrypt (junk-that-decrypts confirms, matches spec); hello-in-any-state
  resets with epoch bump before any await. Client idle→handshaking→ready with
  shared handshake promise.
- **Zeroing:** ephemeral keys/shared secrets zeroed in try/finally; in-flight
  copies owned (`.slice()`) so concurrent resets can't corrupt derivations;
  all-zero secret refused; low-order X25519 pubkeys covered by noble + f002
  regression test.
- **Silent-drop policy:** bad tag, oversized frames, poly1305 failure,
  malformed RPC shape — all dropped without feedback, per spec.
- **Packaging:** package.json `exports` matches every import path claimed in
  README/api.md; jsr.json version synced at 0.6.1; ESM+CJS dual build wiring
  present (`rewriteRelativeImportExtensions` handles the `.ts` specifiers).
- **Auth helpers:** JWT symmetric skew + constant-time transcript digest,
  Ed25519/ECDSA/cert/multifactor decode through hardened codec with strict
  field validation — as documented. (JWT payload also carries `v: 1`, not
  mentioned in the docs; server ignores it. Not worth a finding.)

## Suggested priority

1. **C1** — behavioral bug, silent double execution from a local guardrail;
   fold into the F1 retry-semantics decision.
2. **C2** — one-line spec fix, but it's a port-breaking instruction in the
   normative doc.
3. **C4** — small code change that also gives C1 its clean predicate.
4. C5, C6, C7 — doc honesty fixes, 15 minutes total.
5. C3, C8, C9, C10 — housekeeping.

---

# Design sketches (agreed 2026-07-06)

Two fixes agreed against the residual-risk list in `spec/assessment.md`.
Sketches are implementation-ready; both are wire-compatible (no protocol
version bump).

## D1 — Deferred reset (assessment risk #3, unauthenticated teardown)

**Decision:** option 1 — do not tear down the established session until the
incoming hello has fully validated. Make-before-break (dual-session) was
considered and rejected for now: bigger state-machine change, and deferred
reset already covers the deployments that have `verify` configured.

**Current order** (`server.ts`, `onMessage`, TAG_HELLO branch):

```
length check → resetHandshake() → [async] shape check → verify → ECDH → …
```

A garbage hello kills the live session before any validation — even when
`auth.verify` is configured and would reject it.

**Target order:**

1. Length check as today.
2. **Do not call `resetHandshake()`.** Generate a *local* fresh ephemeral
   pair for this attempt (`hsPriv`, `hsPub`) — do not touch the module-level
   keys. Bump a separate `attemptEpoch` (or reuse `epoch` but without the
   destructive zeroing) so stale in-flight attempts still self-detect.
3. Run the whole existing coroutine on local state: shape check, epoch
   validation, `verify`, ECDH, `secret()`, key derivation, proof, `sign`.
   Any failure: discard locals, call `onError` — **the active session is
   untouched and keeps serving**.
4. Only in the final synchronous publish block (which already exists for the
   epoch-guard pattern): zero the old session key, swap in the new
   `sessionKey`/`encrypt`/`decrypt`/`authData`, regenerate module-level
   ephemerals, state → `pending`, send the reply.

**What this buys:** with `verify` configured, an attacker without a valid
signature can no longer displace an established session at all. In PSK-only
mode a well-formed hello still displaces (nothing to authenticate at hello
time) — accepted as residual; noted in assessment #3.

**Details to not miss:**

- The handshake timer must now be armed for the *attempt*, not by resetting
  the session; on attempt timeout, discard attempt-locals only.
- Two hellos racing: second attempt bumps `attemptEpoch`, first one bails at
  its guards — same pattern as today, just against attempt-locals.
- `resetHandshake()` remains for its other callers (post-publish failures,
  timeout of a `pending` session).
- Spec: protocol.md "Re-handshake" section and the state-machine diagram
  need one edit each ("a hello opens a handshake attempt; the active session
  is replaced only when the attempt succeeds"). The implementation-checklist
  bullet about bumping the epoch for every incoming hello changes meaning:
  the *attempt* epoch bumps; the session is not torn down.
- Tests: inject a garbage hello and a bad-signature hello into a `ready`
  session with `verify` configured → assert in-flight and subsequent calls
  still succeed with **zero** re-handshakes (count TAG_HELLO frames).

## D2 — Bounded seen-nonce set (assessment risk #1, in-session replay)

**Decision:** close the replay window with a per-session bounded set of
already-seen AEAD nonces, keeping random nonces (no wire change, no ordering
requirement, transport duplication still tolerated). Counter nonces were
considered and parked: with a single bidirectional session key they require
direction separation (keystream reuse otherwise) plus an anti-replay window,
i.e. a protocol v2 — batch with directional keys if ever done.

"Set of nonces already seen this session" is the right mental model, plus
three load-bearing details:

1. **Record only after successful Poly1305 verification.** Membership check
   *before* decrypt (cheap reject of exact replays); insert *after* the AEAD
   tag verifies. Never insert nonces from frames that fail to decrypt —
   otherwise an attacker who cannot forge ciphertexts can still pump
   arbitrary nonces into the set, forcing eviction churn and re-opening the
   window for the entries evicted early.
2. **Bound it with FIFO eviction.** Unbounded Set on a long-lived session is
   a slow memory leak (1M messages × 24 B ≈ 24 MB per session, plus Set
   overhead). Structure: ring buffer of the last `N` nonces + a `Set` keyed
   by the nonce bytes (latin1/hex string) for O(1) lookup; when full, evict
   oldest from both. Default `N` = 4096 (≈ a few hundred KB worst case),
   configurable via option (e.g. `replayWindow: number`, `0` = off).
   Honest semantics, must be documented: a replay older than the last `N`
   messages still executes — the window is *narrowed to N*, not closed.
3. **Clear on reset/re-handshake.** New session key makes old nonces
   irrelevant; keeping them only wastes the budget. Tie the set's lifetime
   to the session key's.

**Where:** server side is the one that matters — a replayed *request*
re-executes a handler. The client is already replay-immune at the RPC layer
(response ids are matched against `pending` and ids are never reused), so a
client-side set is optional symmetry, not security.

**Ordering with D1/session confirmation:** the pending→ready promotion on
first valid decrypt happens *after* the seen-check — a replayed frame from a
previous session cannot confirm anything (different key, fails AEAD), so no
interaction.

**Spec/docs:** protocol.md "Encryption" + "Non-goals" (replay caches are
currently declared an application concern — now partially in-protocol),
security.md "Replay within a session", assessment.md risk #1 status.
Re-run the double-execution probe from C1 as a regression: with the set
enabled, an injected duplicate of a captured request frame must produce
exactly one execution.

**Tests:** capture a valid encrypted request frame, re-inject it — assert
exec count 1 and silent drop; re-inject after `N+1` newer messages — assert
it executes (documents the honest boundary); assert memory bound (set size
never exceeds `N`).

---

# Work plan — 0.7.0 (consolidated 2026-07-06)

Everything open, in implementation order. Sources: this review (C*),
`review-transport-lifecycle.md` (F*), design sketches above (D*),
`spec/protocol.md` implementation checklist (now normative).

## ⚠ Decision needed first: retry-on-TIMEOUT — F1 vs current spec

Two positions are on record and they conflict:

- **F1 / transport review + prior discussion:** on `TIMEOUT`, drop without
  retry ("better to drop") — a timeout does not prove non-execution, so
  auto-retry risks double execution; keep only the session reset so the next
  call gets a fresh handshake.
- **spec/protocol.md as of today:** auto-retry once on `TIMEOUT` or send
  error stays (with an explicit note about the double-execution trade-off);
  guardrail errors excluded.

Pick one before touching client.ts — it changes both the code and the
"Auto-retry semantics" section + checklist bullet in protocol.md:

- Option A (F1): retry only on **send error** (request provably never left);
  `TIMEOUT` → reset session, surface the error, no resend.
- Option B (spec as written): retry on `TIMEOUT` + send error, never on
  guardrails. Keeps current UX, keeps the documented double-exec window.

Either way the C1 guardrail exclusion applies.

## Code (src/)

1. **C4** — wrap `channel.send` rejections in `RPCError("CHANNEL", …,
   { cause })`. Do this first: it gives the retry predicate a typed trigger.
2. **C1 (+F1 decision)** — rewrite the retry predicate in `client.ts` per
   the decision above. Remove the `(state as any)` cast + `@TODO: Invistigae`
   while in there (**C8**).
3. **D1** — deferred reset in `server.ts` (sketch above).
4. **D2** — seen-nonce set in `server.ts` + `replayWindow` option (sketch
   above). New `ServerOptions` field → api.md table row.
5. **F3** (if still planned) — `abortPending` on the client: reject pending
   + abort in-progress handshake + zeroKeys + state=idle (not closed);
   return `{ api, abortPending, destroy }`. Exists locally at Sergiy's,
   unpublished — reconcile with this branch before it drifts.

## Tests (test/)

6. **C1 regression** — maxPending overflow on a healthy session: assert
   exec count stays 4, hello count stays 1, blocked call rejects `CLIENT`.
   Extend `dos-attacks.test.ts` with exec/hello counters (current version
   masks the bug by asserting final values only).
7. **D1 tests** — garbage hello and bad-signature hello (with `verify`
   configured) injected into a `ready` session: in-flight + subsequent calls
   succeed, zero re-handshakes.
8. **D2 tests** — replayed frame: exec count 1, silent drop; replay older
   than window: executes (honest boundary); set size bounded; cleared on
   re-handshake.
9. **Retry-semantics test** matching the F1 decision (whichever option).

## Docs (spec/, README)

10. **protocol.md** — only if F1 Option A: rewrite Auto-retry section +
    failure-modes row + checklist bullet. Otherwise no changes (already
    normative for D1/D2/C1).
11. **api.md** — `replayWindow` option row; auto-retry paragraph sync with
    F1 decision; fix `Channel.receive` return type or document void
    tolerance (**C9**); error-code table: mark INPUT_VALIDATION /
    OUTPUT_VALIDATION / MIDDLEWARE / NOT_FOUND as server-side, surfacing
    remotely (**C5**).
12. **README** — quick-start catch comment: drop INPUT_VALIDATION from the
    "local failure" list (**C5**).
13. **getting-started.md** — "only peer dependency is zod" → zod is a
    regular dependency (**C7**).
14. **integrations.md** — wsChannel: add readyState guard / note that
    browser `ws.send` on a CLOSED socket drops silently (**F4**).
15. **security.md** — "Replay within a session" → describe the seen-nonce
    window; **assessment.md** — flip risk #1/#2/#3 statuses to "fixed in
    0.7.0" where applicable.

## Release

16. Bump 0.7.0, publish npm + jsr (`sync:jsr` hook handles jsr.json).
    Commit spec + code together — protocol.md currently leads the code on
    D1/D2/retry; the gap closes with this release.
17. Post-release regression from the consumer side: re-run the transport
    probe (`/tmp/saferpc-transport-test/test.mjs`) against the published
    version — reply-lost case must show 1 execution per call under the new
    retry semantics; then bump the Enclave repos.

Not in scope for 0.7.0 (parked): directional keys + counter nonces +
anti-replay window = protocol v2 (closes reflection at the crypto layer and
replay fully); make-before-break dual-session (D1's bigger sibling);
bounded `seen`-set on the client (adds nothing, see D2).
