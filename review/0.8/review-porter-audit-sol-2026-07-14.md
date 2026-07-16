# Porter audit — gpt-5.6-sol:high, 2026-07-14

**Method:** adversarial clean-context read of `spec/protocol.md` + `spec/security.md` ONLY (no src/, no test/), in the role of a Rust/Go porter. Agent: `porter-audit-sol`. Every finding = a question the porter cannot answer from the text.

**Verdict (agent's):** ~70% of the implementation determined; crypto/framing portable tomorrow, but parser acceptance, handshake concurrency, replay promotion ordering, async sending, envelope validation, middleware semantics, and several error paths require guessing.

**Triage status:** #39 FIXED (spec error, same day). **Batches 1–4 triaged + patched 2026-07-14/15** — see per-item resolutions below. Remaining ambiguity closures are recorded after Batch 4; no audit item is currently blocked.

### Batch 1 resolutions (all patched into protocol.md unless noted)

- **#2 numeric domain — spec was already correct; empirically confirmed + extended.** `mpEncode` uses `useBigInt64:true`; tested: `Date.now()`→0xcb float64 (decodes as number, NOT BigInt — the earlier probe-note that suggested BigInt used a different codec config). Existing lines 48/569 (ts=float64, uint64→rejected) hold. Added bullets covering negatives/non-integers/NaN/±Inf/−0, the "only big-integer selects 64-bit int family" rule, decoder framing (single top-level value, trailing→throw, dup-keys→last-wins no-throw, invalid-UTF-8→decoder-defined), and universal unknown-field tolerance.
- **#3 parser differentials — empirically pinned.** trailing bytes → THROW ("Extra N byte(s)"); duplicate keys → last-wins, no reject; invalid UTF-8 → no throw, substitutes. All three now normative in the msgpack profile.
- **#4 unknown hello/reply fields — RESOLVED (code correct).** Server/client read known keys by name; unknown fields ignored exactly like request/response. Added universal unknown-field-tolerance bullet.
- **#5 empty auth — RESOLVED (code correct).** No verifier configured ⇒ `auth` never read (ignored); verifier configured ⇒ `auth` required `1..MAX_AUTH_BYTES`, `bin(0)`/absent/oversized fail the attempt. Clarified in the TAG_HELLO frame section.
- **#20 MAX_ID_LEN unit — legalized.** Reference counts UTF-16 code units (JS `String.length`); documented as a resource guard, not a wire invariant; ids are opaque/ASCII-recommended so counts coincide; peers must not depend on the non-ASCII threshold.
- **#37 Ed25519 strictness — pinned.** Reference uses `@noble/curves` default = **ZIP-215** (confirmed `ed25519.ts:150` sets `zip215:true`). Documented as a normative vector-agreement parameter; ports may choose RFC 8032 strict but must document it; not replay-exploitable (transcript binds epoch+nonces).
- **#38 ECDSA high-S — pinned.** Reference uses WebCrypto `crypto.subtle.verify` which accepts high-S; ports MUST NOT add a low-S gate. Not replay-exploitable (transcript binding).

### Batch 2 resolutions (handshake/state #6–19 — patched 2026-07-14; NO code changes, all code correct)

- **#6 auth predicate — pinned.** `validateAuthConfig`: valid iff ≥1 of `secret`/`sign`/`verify`; every non-empty subset legal (secret-only, sign-only, verify-only, combos); none ⇒ construction error. Per-direction authentication decided at handshake time, not construction. New "Auth configuration predicate" note.
- **#7 epoch advancement — pinned.** Two deliberate `epoch++`: `startHandshake` (549) AND `reset` (1193). Reference counter doubles as staleness generation → advances on reset too → wire epochs may skip; server must not assume contiguity. Documented at step 1.
- **#8 exhaustion — legalized.** No client-side terminal guard exists; reference never wraps/reuses, and past 2³² the server rejects out-of-range epoch → permanent HANDSHAKE. Ports MAY add explicit terminal error; MUST NOT wrap/reuse. Spec softened from "terminal error" to describe actual behavior.
- **#9 client hello-send failure — RESOLVED (code correct).** Not a failure: hello queued + retried by flush tick, bounded by handshakeTimeout, revoked if attempt dies; error not surfaced. (Contradicts audit's "fails immediately" guess.) New note.
- **#10 server reply-send failure — RESOLVED (code correct).** Candidate dropped immediately (guarded on candidateEpoch), HANDSHAKE via onError with transport error as cause. New note.
- **#11 deadline origins — pinned.** Client: start of attempt (after keygen), `hsDeadline = Date.now()+hsTimeout`. Server: hello arrival (attemptStart); one budget spans validation + confirmation (confirmation timer inherits remaining). New note.
- **#12 verify return shape — pinned + spec corrected.** Server extracts `.auth` MEMBER, sanitizes THAT (not wrapper); absent `.auth` ⇒ success but no principal; non-object `.auth` ⇒ HANDSHAKE. Old wording ("sanitizes the `{auth:...}` object") tightened.
- **#13 no-verify auth — pinned.** context factory gets `{}` (no `auth` key, not `{auth:undefined}`); no factory + auth → principal fields on null-proto ctx; no factory + no auth → empty null-proto ctx.
- **#14 candidate concurrency — pinned (JS single-thread) + porter note.** Three generation counters (attempt/candidate/live-epoch) re-checked after every await; threaded ports must serialize trial-decrypt-and-promote vs candidate swap. New "Concurrency and generation guards" paragraph.
- **#15/#17 replay clearing — pinned.** `seenClear()` called ONLY in `promoteCandidate` (confirmed) → cleared on PROMOTION not install; make-before-break window intact; confirming nonce recorded AFTER clear (`promoteCandidate` then `seenAdd`) so its replay is caught. Rule 4 rewritten.
- **#16 atomic nonce — pinned.** `seenAdd` synchronous before first `await` → back-to-back dupes can't both pass; threaded ports MUST lock check+insert. Added to replay rules.
- **#18 response guard — already covered + reinforced.** `epoch !== reqEpoch || destroyed` drops ordinary responses too; reqEpoch captured at arrival (after this frame's own promotion). Cross-ref to execution pipeline.
- **#19 stray hello — RESOLVED (code correct).** `tag === TAG_HELLO && state === "handshaking"` — hello processed ONLY while handshaking; ignored in idle/ready/closed. Covered by generation-guards note + state machine.

### Batch 3 resolutions (RPC/pipeline #21–30 — patched 2026-07-15)

- **#21 ID lifetime — spec corrected.** Runtime counter is never reset by session reset/re-handshake; ids are unique for the entire client instance lifetime. Spec request schema and nuance now say this explicitly.
- **#22 response required shape — code tightened + spec pinned.** Client now requires `d` and `e` outer keys before consuming a pending entry: success requires `e:null`; failure requires `d:null` and a map `e`. Invalid envelopes are silently dropped. Error-map members remain defensively coerced (`c`/`m`), so malformed inner members do not invalidate an otherwise well-formed failure envelope. Added regression cases to `test/security/malformed-response.test.ts`.
- **#23 absent success/error data — pinned.** The reference includes the keys and msgpack encodes JS `undefined` as wire `nil`: no-output success is `{ok:true,d:nil,e:nil}`; an RPCError with absent data carries `e.d:nil`; ordinary failure always has outer `d:nil`. Added to response shape text.
- **#24 protocol error messages — intentionally non-normative.** Wire conformance requires the error code and envelope, not human-readable `m`; exact wording is implementation text. Reference common strings are listed for diagnostics, while schema issue details remain non-normative.
- **#25 typed RPC recognition — pinned.** Server recognizes its typed `RPCError` (including subclasses) and preserves its own `code/message/data`; any other thrown value maps to generic `INTERNAL` with no detail leak. Sanitizing error data can itself abort response production. Added to response/pipeline text.
- **#26 middleware continuation — pinned.** `next(extra?)` exactly once; non-null object extra is shallow-merged into a fresh null-prototype context; `next` returns downstream promise, but middleware's own return value is propagated to the preceding step rather than automatically replaced by downstream result. Added explicit semantics.
- **#27 async middleware races — pinned to reference contract.** `next` must be called before middleware completion; no-call ⇒ `MIDDLEWARE`, second call ⇒ `MIDDLEWARE`. A call made without awaiting/returning its promise is accepted after the call itself occurs; downstream can run concurrently and its result/error is only observed if the continuation promise is observed. Late calls after completion are invalid behavior. Added timing/precedence note.
- **#28 declaration-order composition — pinned.** Steps are nested continuations in declaration order; first declared is outermost, handler innermost. An output schema validates the value returned by the remainder, which may be middleware's replacement return value. Added to pipeline section.
- **#29 oversized outbound RPC — code fixed + spec pinned.** Client checks full encrypted frame length against its local `maxMessageBytes` before creating a pending entry/handing off; rejects `RPCError("CLIENT", "Message exceeds maxMessageBytes")`, does not send or reset. Added DoS regression test.
- **#30 client input sanitize — code fixed + spec pinned.** Client sanitizes supplied input before msgpack encoding, matching the server's plain-data gate; invalid host/ext/deep values fail locally as `INVALID_DATA` and never reach the adapter. Added Date regression test.

### Batch 3 review follow-up (gpt-5.6-luna:high — patched 2026-07-15)

- **Late middleware continuation — fixed.** `runMiddleware` now marks completion in `finally`; `next()` invoked after the middleware promise settles returns without launching downstream. Added regression test proving a delayed `next()` cannot invoke the handler after a `MIDDLEWARE` response.
- **Sanitizer primitive gap — fixed.** `sanitize()` now rejects `function` and `symbol` with `RPCError("INVALID_DATA")` before `mpEncode`; added function/symbol regression coverage.
- **Handshake-before-validation — fixed.** The client sanitizes input in the API proxy before `ensureHandshake()`, so an invalid first call emits no hello or RPC frame. `sendRequest()` retains the gate as defense-in-depth.
- **Luna suggestions applied.** Protocol now explicitly states the reference's late-`next()` ignore behavior and function/symbol rejection; `e.d` absence is pinned to `null`, and protocol error-code emission is mandatory rather than merely recommended. `spec/api.md` middleware wording is synchronized. Boundary `== maxMessageBytes` coverage remains an optional follow-up.

### Batch 4 resolutions (#31–35 — patched 2026-07-15)

- **#31 queued calls invalidated by reset — pinned.** A reset immediately removes every queued message encrypted under the retired epoch and rejects it with plain `RPCError("CHANNEL")`; the ciphertext is never re-encrypted or carried into the replacement session. Queued stale hellos are silently revoked.
- **#32 async-send terminal race — pinned.** The first event that settles a pending call wins. If timeout/abort/destroy/response already removed the pending entry, a later async-send rejection is ignored: it cannot requeue or settle the call a second time. An unresolved send is rolled back only while the call remains pending and the session/epoch is unchanged.
- **#33 response vs async-send rejection — pinned.** A valid response consumes the pending entry and wins even if the adapter's send promise is unresolved; a later send rejection is a no-op. Conversely, an earlier send rejection rolls back while the call remains pending.
- **#34 simultaneous terminal events — pinned.** Ports serialize event handling; the first observed settling event wins. The error class is selected from the sent boundary at that event. Only a sent-call `RPCAbortedError("TIMEOUT")` triggers reset, subject to the epoch guard; late replies and transport completions are ignored after settlement.
- **#35 reset and shared handshake — pinned.** `reset()` only retires keys and returns to `idle`; it does not start a handshake itself. The next call, or another pending call reaching `ensureHandshake()`, starts or joins one shared lazy handshake.

### Remaining ambiguity closures (patched 2026-07-15)

- **CSPRNG, malformed replies, deadlines, response ids — pinned.** Ephemeral keys/nonces require a CSPRNG; a failed RNG aborts the attempt without installing state. A malformed current-attempt reply fails that attempt, a valid stale-epoch reply is silently ignored, and unknown/settled response ids are silently ignored. Handshake deadlines use absolute wall-clock checks with `now >= deadline`; timers are only wakeups.
- **`maxPending` accounting — pinned.** Calls waiting for the shared handshake do not consume slots. A slot is reserved at encrypted-request admission and held across queued/async/sent states until settlement.
- **Sanitization graph semantics — fixed + pinned.** The sanitizer now rejects cyclic outbound graphs as `INVALID_DATA` instead of recursing until a host stack failure. Root depth is 0, map keys do not add depth, and non-cyclic repeated references are allowed. Added regression coverage.
- **JWT timestamp semantics — pinned.** The verifier samples `now` once at the timestamp check; finite fractional millisecond timestamps are accepted, matching the reference's non-integrality check.
- **`secret()` type-failure taxonomy — pinned.** A non-byte-string, too-short, or all-zero `secret()` return fails the handshake with the generic `HANDSHAKE` class on both peers; there is no distinct code for a mistyped application secret.
- **`t`-check vs sanitization ordering — pinned.** Plaintext sanitization runs during decode, before the `t` reflection check; it is side-effect-free, so its position is not security-relevant. What must precede handler dispatch/reply is the `t` check, and on the server AEAD verification (plus the promotion/nonce-record it authorizes) precedes plaintext decode.
- **Numeric option integrality — already normative (confirmed).** `timeout`/`sendTimeout`/`handshakeTimeout` accept finite fractional milliseconds; `maxPending`/`maxMessageBytes`/`replayWindow` require integers. Documented in `api.md`.
- **Typed-error precedence & error-`d` handling — already normative (confirmed).** A stage that throws the typed RPC error keeps its own code over the surrounding stage; a malformed/absent `e.d` is coerced defensively (absent ⇒ nil). No spec change needed.

---

## Blockers

1. **Document map — normative dependency on `api.md`.** What exact error classes, codes, causes, timeout behavior, constructor validation, and typed-error recognition must a port reproduce? protocol.md says ports mirror those semantics from api.md, while also saying only protocol.md is fully normative.
2. **msgpack profile — incomplete numeric encoding domain.** Negative integers, non-integral values, NaN, infinities, negative zero, integers outside exact IEEE-754 range; "outside the 32-bit range" doesn't define signed/unsigned bounds; float32 vs float64 unstated except JWT `ts`.
3. **msgpack profile / Sanitization — parser differentials.** Duplicate map keys, invalid UTF-8 in `str`, trailing bytes after the first msgpack value — reject, replace, keep-first, keep-last, ignore? Affects envelopes and signed auth profiles.
4. **TAG_HELLO — unknown hello fields.** Ignored, or does "check shape" require an exact field set? Unknown-field tolerance is explicitly normative only for request/response maps.
5. **Empty `auth`.** Is `auth: bin(0)` malformed when no verifier is configured? Frame schema, auth section (`1..MAX_AUTH_BYTES`), and compatibility section disagree.
6. **Valid auth callback combinations.** Which configurations pass construction validation: `sign` alone, `verify` alone, either + `secret`, only `sign+verify`? The predicate is undefined.
7. **Epoch advancement.** Does a timeout reset increment the wire epoch itself, and the next handshake again? Step 1 says once per attempt; checklist says per attempt AND per reset. Ports could send 1,2,… vs 1,3,…
8. **Epoch exhaustion.** What terminal state and typed error; do later calls return the same permanent error?
9. **Client hello send failure.** Queued under sendTimeout? Retried until handshake deadline? Shared handshake fails immediately? Outbound queue described for call frames only.
10. **Async server reply-send rejection.** Does it count as "reply send fails" and drop the candidate? What if confirmation/replacement happens before the rejection is observed?
11. **Handshake deadline origin.** Client: API-call entry / keygen / before sign / hello handoff? Server: transport delivery / before decode / after shape validation?
12. **Verifier return shape.** Principal directly, `{ auth: principal }`, or wrapper with `.auth` extracted? Text alternates.
13. **Session auth without `verify`.** Exact value given to context factory: absent, nil, empty map?
14. **Candidate concurrency linearization.** Candidate decrypt vs timeout vs newer-hello install vs promotion vs destroy in a threaded port; post-decrypt candidate-generation guard unspecified.
15. **Confirmation nonce ordering.** Inserted after promotion clears the old set, or before (and erased)? Checklist requires the malformed confirming frame to consume its nonce; promotion clears the set. Wrong order permits replay of the first request.
16. **Concurrent duplicate frames.** Must nonce acceptance be atomic post-AEAD? Two concurrent copies can both pass check-before-decrypt.
17. **"Cleared on re-handshake" meaning.** Cleared on promotion only, or at candidate install (which reopens replay of the still-serving live session)?
18. **Response-guard capture for ordinary requests.** When is the guard epoch captured? Does candidate installation count as "re-handshake" or only promotion?
19. **TAG_HELLO outside an active client attempt.** What must a client in idle/ready do with a valid/malformed/matching-epoch hello frame?
20. **MAX_ID_LEN unit.** UTF-8 bytes, scalar values, graphemes, or UTF-16 code units? A 64-char non-ASCII id accepted by one port, dropped by another.
21. **ID lifetime.** Unique within one session key or full client instance? Schema and nuance text disagree.
22. **Response required shape.** Must success contain `d` AND `e: nil`; failure `d: nil` + `e`? Are contradictory fields (`ok:true, e:{...}`) accepted?
23. **Absent success/error data.** No-output handler: `d:nil`, omitted, or INVALID_DATA? Typed-error `e.d` omitted or nil?
24. **Protocol error messages.** Exact `m` strings for NOT_FOUND/validation/middleware/etc. — wire-visible; only INTERNAL is fixed.
25. **Typed RPC error recognition.** What constitutes "the implementation's typed RPC error"; what validation before building the failure envelope?
26. **Middleware continuation semantics.** What `next` accepts/returns, context-extension merge, return-value propagation.
27. **Async middleware races.** `next()` unawaited / returns before completion / second call after completion / throw while downstream runs — error precedence, response-or-not.
28. **Declaration-order composition.** Execution topology when multiple schemas interleave with middleware; what an output schema validates when declared before the handler boundary.
29. **Oversized outbound RPC frames.** Local CLIENT/CHANNEL/INVALID_DATA, silent omission, onError, or attempted send? Sent-boundary consequences?
30. **Client input sanitize gate.** Must request input pass the plain-data sanitizer before encoding?
31. **Queued calls invalidated by reset.** Unsent frames under the retired key: immediate CHANNEL, continued retry, re-encrypt later, or wait for timers?
32. **Async-send terminal race.** Call already terminally rejected (timeout/abort) while send in flight; the send later rejects proving never-left — spec says requeue/CHANNEL, but caller already has a terminal result.
33. **Response vs async-send rejection.** Valid response arrives while send unresolved; send later rejects. Which event wins?
34. **Simultaneous terminal events.** Reply / call timeout / abort / destroy / send completion concurrently ready — required winner and reset-or-not.
35. **Reset and shared handshake wording.** Does the timeout-triggered reset itself begin a handshake? Texts disagree.
36. **Prototype-pollution keys across languages.** Language-neutral rules imply preservation outside JS; checklist says sanitization strips them. Observable divergence in handler inputs.
37. **Ed25519 verifier strictness.** Non-canonical scalars, small-order pubs, non-canonical encodings — mandatory rules unstated; libraries differ.
38. **ECDSA high-S.** Accept mathematically-valid high-S P-256 signatures or enforce low-S? Only the vector is identified as low-S.
39. ~~**Reply transcript "includes the proof".**~~ **FIXED 2026-07-14** — transcript = magic‖epoch‖clientPub‖clientNonce‖serverPub; spec text corrected in checklist + security.md.

## Ambiguities

1. CSPRNG requirement + failure error for keypairs/nonces.
2. Malformed-reply attribution during an attempt (which hellos fail it vs are ignored).
3. `onError` coverage matrix on the server.
4. Monotonic vs wall clock; deadline-boundary inclusive/exclusive.
5. `secret()` type-failure code taxonomy.
6. `t`-check ordering vs sanitization in decrypt pseudocode.
7. Unknown/consumed response ids — always silent? local diagnostic?
8. Error `d` absent/malformed — expose absent, nil, sanitized value, or discard?
9. Typed-error precedence when a schema/middleware throws a typed RPC error (its code vs the stage code).
10. `maxPending` accounting (waiting-on-handshake? queued? async-in-flight? sent?) + slot reserve/release points.
11. Numeric option validation: integrality of fractional values.
12. Sanitization depth accounting (root 0 or 1; keys counted?).
13. Cycles in outbound data — classification.
14. JWT `ts` integrality (1700000000000.5 rejected?).
15. JWT `now` sampling point.
16. Client error details for proof mismatch / malformed reply / sanitizer failure / invalid auth payload / hs timeout.
17. "Should emit the same codes" — mandatory or not; non-pipeline protocol failures.
18. Test vectors — conformance scope (primitives only vs protocol certification; no full hello/reply/response/malformed/timer/concurrency vectors).

## Nits

- Security "Why authentication is required": hello transcript cannot contain the not-yet-created server key.
- Server state-machine diagram vs prose on "attempt error" dropping the candidate.
- JWT `ts` labeled `uint` while wire representation is float64 (verify!).
- Compatibility "peers that do not understand auth ignore it" reads like unauthenticated-legacy support.
- XSalsa20-Poly1305 labeled AEAD though secretbox has no AD input; resolved later.

## Urge log (questions the agent wanted src/ for)

msgpack strictness (trailing/dup-keys/UTF-8); hello shape guards; epoch counter sharing between reset and wire; deadline creation points; hello send queueing + async handshake-send rejection; verifier output extraction; candidate promotion + replay insertion locking; promotion clear-vs-record order; response required fields before pending consumption; middleware runner edge cases; queued frames on foreign reset; race winners; maxPending accounting; sanitizer pollution-keys in non-JS + depth start; Ed25519 strict verification; ECDSA high-S; exact protocol error messages/classes.
