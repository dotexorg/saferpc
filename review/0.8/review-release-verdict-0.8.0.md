# 0.8.0 release verdict — branch `0.8.0-fixes` → `main`

**Audit date:** 2026-07-16
**HEAD audited:** `d0edc02` ("fix: implement maxPendingHandshakes …")
**Base:** `origin/main`
**Method:** independent re-verification of every prior finding against the code at HEAD (not against changelogs), empirical repro scripts re-run before/after, full gate, packaging smoke tests. Technical basis: `spec/assessment.md`; prior review rounds (`review-*.md`) are kept as historical records.

---

## 1. Branch scope vs `origin/main`

14 commits, **30 files changed, +2150 / −1308**.

| Theme | Commits | Content |
|---|---|---|
| Auth surface rework | `ee2f1de`, `73f9d3a`, `a8027d3` | `createCertificateServerAuth` / `createMultifactorServerAuth` **removed** (delegated security-critical binding to app callbacks under a name implying the library did it); JWT / Ed25519 / ECDSA transcript-bound profile helpers added with tests |
| Spec conformance batches | `b13d697`, `10cbf74`, `c07d36d`, `059320f`, `15e83d5`, `6e45c1d` | sent-boundary semantics, error-code map, middleware/validation ordering, cyclic outbound graph rejection, directionality clarifications |
| Round-2 findings (10) | `36ebeaa`, `48ae07e` | middleware completion guard; handshake deadline, sanitizer, replay, secret guards — itemized in §2 |
| Follow-up hardening | `9428901`, `d0edc02` | AEAD-verify/inner-decode split, nonce-slot rules for malformed/reflected frames, outbound response framing bound, `maxPendingHandshakes` (default 16), NaN/Infinity limit validation, client single-pending-handshake rule |
| Packaging | in `48ae07e` | `engines.node` raised `>=18` → `>=20.19.0`; README support matrix corrected |

No changes on `origin/main` are reverted or bypassed by the branch (`726e928` merges main in cleanly).

---

## 2. Findings, severity, fixes, regression coverage

All ten round-2 findings re-verified at HEAD by reading the shipped code and re-running the original repro inputs. "Repro re-run" = the exact input that demonstrated the defect now produces the fixed behavior.

### #6 — Expired handshake candidate could be promoted (main code bug)

- **Severity: High.** Security impact: a candidate whose `handshakeTimeout` budget had elapsed could still be promoted to the live session and its request executed, if the event loop was busy past the budget (spec `protocol.md` § deadline origins forbids this: timers are wakeups, every continuation must check the absolute deadline).
- **Fix:** `src/server.ts` — `candidateDeadline = attemptStart + hsTimeout` stored at candidate install (`:754`), checked in the TAG_MSG handler **before** `promoteCandidate()` (`:906`: `if (Date.now() >= candidateDeadline) return;`). Expired candidate is left to the overdue timer: no promotion, no nonce record, no handler run.
- **Sub-finding (Low): double `onError` per attempt.** Timer fired "Handshake timeout" without advancing the epoch; a late async rejection then passed the epoch-only guard and fired "Handshake failed" too. Fixed with an attempt-scoped `reported` flag checked at every report site (`:562`, `:567`, `:765`, `:825`).
- **Regression tests:** `test/security/review-round2-fixes-2026-07-15.test.ts` — "#6a a confirming frame that arrives after the budget (loop starved) does not promote an expired candidate"; "#6b a timeout followed by a late-rejecting auth callback reports exactly once". Both green.

### #8 — All-zero secret guard only covered length 32

- **Severity: Medium-High.** Security impact: a 33/64/65-byte all-zero secret passed the guard and silently degraded the session to no-secret authentication; `deriveSessionSecret(publicId, zeros)` produced a deterministic, publicly reproducible secret the handshake accepted — contradicting the documented "fails loudly" example (`security.md:203-207`).
- **Fix:** `src/common.ts` — `isEmptySecret` now treats an all-zero buffer of **any** length (including empty) as empty; `deriveSessionSecret` rejects all-zero secret material with `TypeError("secret must not be all-zero")`.
- **Repro re-run:** `isEmptySecret(new Uint8Array(64))` was `false` → now `true` (also 33, 0); `deriveSessionSecret('user-123', new Uint8Array(32))` returned a valid-looking key → now throws.
- **Regression tests:** `test/unit/psk-auth.test.ts` — "rejects all-zero secret material (#8)", "returns true for an all-zero buffer of any length", "derived secret is never the all-zero sentinel". Green.

### #4 — Out-of-range bigints silently altered

- **Severity: Medium.** Impact: silent data corruption — an echo of `18446744073709551616n` returned `0`; msgpack `useBigInt64` reduces to 64 bits without error.
- **Fix:** `src/common.ts:169-176` — sanitizer rejects `bigint` outside `[-2^63, 2^64−1]` with `RPCError("INVALID_DATA", "BigInt out of encodable range")`; `BIGINT_MIN`/`BIGINT_MAX` exported constants.
- **Repro re-run:** `2^64` → was `0n`, now throws `INVALID_DATA`; `−2^63−1` → was clamped to `2^63−1`, now throws. Boundary values `2^64−1` and `−2^63` pass unchanged.
- **Regression tests:** `test/unit/sanitize.test.ts` § "sanitize / bigint range (#4)" — above-max, below-min, in-range. Green.

### #5 — Nested `undefined` arrived as `null`

- **Severity: Medium.** Impact: a type-valid call with an optional field set to `undefined` failed server-side validation ("expected string, received null") while an empty object passed — same on the response path.
- **Fix:** `src/common.ts:210-214` — sanitizer drops `undefined`-valued object keys, matching top-level omission; top-level `undefined` still returned as-is.
- **Repro re-run:** `sanitize({a: undefined, b:"x"})` → `{b:"x"}`; encode/decode round-trip has no `a` key (was `{"a":null}`).
- **Regression tests:** `test/unit/sanitize.test.ts` § "sanitize / nested undefined (#5)". Green.

### #7 — Fire-and-forget `next()` could crash the process

- **Severity: Medium.** Impact: docs accept an unreturned `next()`; if the downstream chain later rejected, the promise was unobserved → `unhandledRejection` → process termination on default Node config. Remote-triggerable DoS given a middleware written in the documented style.
- **Fix:** `src/server.ts` (runMiddleware) — `void Promise.resolve(downstream).catch(() => {})` attached to the continuation promise at the `next()` call site; `spec/protocol.md:449` now documents the internal observer and that the unpropagated rejection is intentionally not delivered.
- **Regression test:** `test/security/middleware-attacks.test.ts` — "fire-and-forget next() with a rejecting downstream does not leak an unhandled rejection". Green.

### #9 — Reflected server responses consumed replay-window slots

- **Severity: Medium.** Impact: both directions share one key; a genuine server response fed back to the server passed Poly1305 and was recorded in the seen-nonce window **before** the message-type check, shrinking the effective replay window (~half with symmetric traffic).
- **Fix:** `src/server.ts:940-941` — direction guard (`t === 1`) runs before the nonce record for the reflected-response case: `t: 2` frames are dropped **without** consuming a slot. Deliberate nuance: authenticated **malformed** envelopes and non-1/non-2 `t` values DO consume their nonce (`:923`, `:928`, `:941`) so a captured authenticated junk frame cannot force unbounded decode work — rationale in-code and in `spec/assessment.md`.
- **Regression test:** `test/security/review-round2-fixes-2026-07-15.test.ts` — "#9 reflecting a genuine server response does not evict a recorded request nonce". Green.

### #3 — Declared Node range the build didn't support

- **Severity: Medium (packaging).** Impact: `engines.node >=18` while `@noble/* 2.2.0` is ESM-only with `engines >= 20.19.0`; the CJS build `require()`s it → `ERR_REQUIRE_ESM` on 18.x and 20.18 (require(esm) landed in 20.19). Install succeeded, first import crashed.
- **Fix:** `package.json` `engines.node: ">=20.19.0"`; `README.md:161` states the floor and the reason (noble ESM-only under CJS).
- **Verification:** `node_modules/@noble/hashes/package.json` confirms `"type":"module"`, `engines >= 20.19.0`. CJS `require('./cjs/index.js')` and ESM import both smoke-tested OK on Node 22.22.1. *Not re-tested on 18.x/20.18 in this audit — the floor now excludes them by declaration, which is the fix.*

### #1 — JWT wire-visibility undocumented (docs)

- **Severity: Medium (documentation, security-relevant).** Impact: the JWT rides the unencrypted hello frame; threat model includes a passive transport observer; docs never stated the consequence.
- **Fix:** `spec/security.md:328` — explicit paragraph: "The token is wire-visible … JWT-only mode therefore assumes a **confidential transport** (TLS/DTLS) or a second factor (PSK or a signature mode)", including the contrast with signature modes.
- **Coverage:** documentation fix; no test applicable. Code behavior (token in hello) is by design and unchanged.

### #2 — One-directional auth examples (docs)

- **Severity: Medium (documentation, security-relevant).** Impact: shipped examples (client `sign`, server `verify`) authenticate only the client; a reader could assume mutual authentication.
- **Fix:** `spec/getting-started.md:241` — "**Authentication is directional.**" callout: client `sign` + server `verify` proves only the client's identity; mutual auth needs both directions or a PSK; links to the security-doc section.
- **Coverage:** documentation fix. `test/unit/psk-auth.test.ts` § validateAuthConfig pins that one-directional configs remain legal (by design).

### #10 — Context-error contract self-contradiction (spec)

- **Severity: Low (spec quality / porter hazard).** Impact: `protocol.md:430` said a typed error from the context factory keeps its code; `:446` and `:595` required masking to `INTERNAL`. A second implementer could not choose unambiguously.
- **Fix:** all three passages aligned to the code's actual behavior — typed RPC error keeps its `c`/`m`/`d`, any other thrown value masks to `INTERNAL` (`protocol.md:447`, `:596`, conformance checklist `:727`). Verified against `src/server.ts:886` (context call inside the try whose catch preserves `RPCError` codes).
- **Coverage:** `test/security/middleware-attacks.test.ts` — "middleware-thrown RPCError is not masked as INTERNAL" pins the response-mapping rule.

### Follow-up round (post-round-2, same branch) — verified fixed

Documented in `spec/assessment.md` § "2026-07 follow-up review"; regression tests in `test/security/review-fixes-2026-07.test.ts`, `hung-auth-timeout.test.ts`, `replay-and-response-bounds.test.ts`, `dos-attacks.test.ts`:

| Finding | Severity | Fix |
|---|---|---|
| AEAD verify conflated with inner decode — authenticated-but-malformed candidate frame failed to promote | Medium | split `createAeadOpener` / `decodePlaintext`; promotion on Poly1305 proof alone |
| Sync auth callback overrunning `handshakeTimeout` still installed a candidate | Medium | absolute wall-clock deadline after every await, both sides (`attemptDead()` / `hsDeadline`) |
| Non-cancellable auth callbacks accumulated one closure per timed-out attempt | Medium (DoS) | `maxPendingHandshakes` (default 16, validated integer > 0); client holds max one unsettled attempt |
| `NaN`/`Infinity` accepted for `maxPending`/`maxMessageBytes`/JWT `maxAge` — silently disabled the limit | Medium | finite-positive-integer validation at construction |
| Failed handshake-reply send left candidate lingering → spurious second timeout error | Low | send guarded; candidate dropped, single `HANDSHAKE` error with transport cause |
| Middleware completing without calling `next()` skipped the handler silently | Medium | `RPCError("MIDDLEWARE", "Middleware completed without calling next()")` |
| Oversized encrypted **response** handed to the channel (peer must drop it → opaque client timeout) | Low-Medium | outbound frame checked against `maxMessageBytes`; reported via `onError`, never sent |

---

## 3. Full spec-conformance pass (protocol.md implementation checklist, 44 items)

`spec/protocol.md` § Implementation checklist is the normative conformance contract (44 items). Every item was checked against `src/` at HEAD with file:line evidence. Result: **43 PASS, 1 PARTIAL (C1, Low)**.

| # | Item (abbreviated) | Evidence | Result |
|---|---|---|---|
| 1 | Constants byte-exact | `common.ts:24-55,63-66,430`, `client.ts:61-64`, `server.ts:53-54` — every value matches the spec table; wire-normative set additionally pinned by KAT vectors | PASS |
| 2 | msgpack profile (smallest-width ints, bin/str, str keys) | msgpack-javascript defaults; byte-pinned by `vectors.test.ts` (encrypted frame + profile payload bytes), `msgpack.test.ts` | PASS |
| 3 | Whole-message framing, not self-delimiting | core consumes the full delivered buffer as one frame; stream framing delegated to adapters per spec | PASS |
| 4 | Constant-time comparisons | `constTimeEqual` (`common.ts`) used for proof (`client.ts:842`) and JWT digest (`auth/server.ts:112`); MAC verification inside `@noble/ciphers` | PASS |
| 5 | Low-order X25519 rejection | delegated to `@noble/curves`, pinned by `f002-low-order-x25519-pubkey.test.ts` | PASS |
| 6 | All msgpack ext types rejected | `SAFE_CODEC` throws on Timestamp (type −1); unknown ext → `ExtData` instance → rejected by `sanitize` (non-plain object); `type-confusion.test.ts` | PASS |
| 7 | Sanitization: host objects, proto keys, depth | `sanitize` (`common.ts`): POISON set, `MAX_DEPTH = 32`, non-plain rejection; `sanitize.test.ts`, `prototype-pollution.test.ts` | PASS |
| 8 | Auth payloads pass full sanitize gate → `UNAUTHORIZED` | `auth/server.ts:32-41` (`sanitize(mpDecode(...))`, catch → `UNAUTHORIZED`); server core also sanitizes hello (`server.ts:590`) | PASS |
| 9 | Handler output sanitized → `INVALID_DATA` | `server.ts:996` | PASS |
| 10 | Frame bounds, full length incl. tag, `>` compare | hello `server.ts:535` / `client.ts:719`; msg `server.ts:853` / `client.ts:894`; outbound `server.ts:1025` / `client.ts:1047` | PASS |
| 11 | Transcript byte sequences exact | `buildHelloTranscript` / `buildReplyTranscript` (`common.ts`); hex pinned in `vectors.test.ts` = spec §Test vectors, verified identical | PASS |
| 12 | verify before ECDH; sign late; failed sign → no candidate | order in `server.ts`: verify `:641` → ECDH `:662` → derive `:690` → proof `:691` → sign `:699`; sign failure throws into attempt catch, candidate never installed | PASS |
| 13 | Fresh ephemeral pair per hello attempt | `x25519.utils.randomSecretKey()` inside `handleHello`, attempt-local | PASS |
| 14 | Candidate install, live-first trial decrypt | `server.ts` TAG_MSG handler: live → candidate; `promoteCandidate()` on candidate decrypt | PASS |
| 15 | Response epoch captured after promotion | `server.ts:909` (`const reqEpoch = epoch` after `promoteCandidate()`) | PASS |
| 16 | Client epoch uint32, never wraps, exhaustion terminal; server three counters | wire validation both sides (`server.ts:608-616`, `client.ts:754-756`); three counters present (`attemptEpoch`/`candidateEpoch`/`epoch`); exhaustion guard in `startHandshake` (see C1, fixed) | PASS |
| 17 | Attempt counter bumped for every hello | `server.ts:539` (`attemptEpoch++` at handler top, before validation) | PASS |
| 18 | Guards after every await; `maxPendingHandshakes` cap | epoch+destroyed guards throughout; cap `d0edc02`, `hung-auth-timeout.test.ts` "caps server attempts whose auth callbacks never settle" | PASS |
| 19 | Absolute wall-clock deadline both sides | server `attemptDead()` `:564` + `candidateDeadline` `:906`; client `hsDeadline` checked `:636,:802,:816,:853` | PASS |
| 20 | Reply-send failure drops candidate, one error | `review-fixes-2026-07.test.ts` "#6 a failed handshake-reply send drops the candidate and reports exactly one error" | PASS |
| 21 | Promotion on AEAD only; nonce rules for malformed / reflected | `server.ts:895-941`; `replay-and-response-bounds.test.ts` | PASS |
| 22 | Numeric limits validated at construction | `server.ts:331`, `client.ts:225`, `maxPendingHandshakes` integer>0, JWT `maxAge`; `review-fixes-2026-07.test.ts` "#4 NaN / Infinity limits" | PASS |
| 23 | Profile version `v` stamped and required | `auth/server.ts:48` rejects absent/unknown `v`; three profiles byte-pinned in `vectors.test.ts` | PASS |
| 24 | Separate candidate-timer counter | `candidateEpoch` / `myCandEpoch` keying (`server.ts:709` area) | PASS |
| 25 | Attempt-local state; live session undisturbed by invalid/replayed/forged hello | `session-continuity.test.ts` (4 scenarios) | PASS |
| 26 | All-zero secret rejected at any length | `isEmptySecret` (`common.ts:136`), `server.ts:681`, `client.ts:830`; `psk-auth.test.ts` | PASS |
| 27 | Raw shared secret zeroed in try/finally | `server.ts` attempt `finally` zeroes `rawShared`/`localSessionKey`/`localProof`; same pattern client-side | PASS |
| 28 | Ephemeral keys copied, not aliased, for awaits | `client.ts:728-729` (`privateKey.slice()`, `publicKey.slice()`) | PASS |
| 29 | Server accepts hellos in any state | make-before-break design; `session-continuity` / `handshake-attacks` tests | PASS |
| 30 | No auto-retry; reset only on sent-call `TIMEOUT`; guardrails never reset | `client.ts:237,:1247`; `channel-lifecycle.test.ts` "reset predicate" | PASS |
| 31 | Application secret buffer never zeroed by protocol | `secretBytes` absent from all `zero()` sites (only derived material zeroed) | PASS |
| 32 | `id`/`p` validation, unknown proc → `NOT_FOUND` | `server.ts:950-966` | PASS |
| 33 | Confirmation timer gets remaining budget | `server.ts:735` (`hsTimeout − (Date.now() − attemptStart)`) | PASS |
| 34 | Absent input omits `i` | `client.ts:1045` (`if (input !== undefined) req["i"] = input`) | PASS |
| 35 | `t` check before any other processing | `server.ts:940` (before nonce record for `t: 2`, before id/proc parsing) | PASS |
| 36 | Remote error coercion (`c`→`UNKNOWN`, `m`→"") | `client.ts:945` area; `malformed-response.test.ts` | PASS |
| 37 | `ok` never coerced, strict boolean | `malformed-response.test.ts:84-92` (9 garbage variants dropped) | PASS |
| 38 | Pipeline stage order + error-code map | verified in round-2 #10; `middleware-attacks.test.ts`, `chain.test.ts` | PASS |
| 39 | Shared-handshake rejection, per-call abort, timeout starts post-handshake | `channel-lifecycle.test.ts` (abort classes, shared AbortController, queued-vs-sent) | PASS |
| 40 | Sent boundary = handoff, async error rolls back | `client.ts` sent-class comments + `channel-lifecycle.test.ts` (sent/unsent classes per scenario) | PASS |
| 41 | Seen-nonce set semantics | check-before-decrypt `server.ts:869`, insert-after-verify, FIFO `:431`, cleared on promotion (`seenClear()`); `replay-window.test.ts` | PASS |
| 42 | Keys zeroed on reset/destroy | `client.ts:1286` (`zeroKeys()` + epoch bump); `zero.test.ts` | PASS |
| 43 | Proof verified constant-time | `client.ts:842` | PASS |
| 44 | No feedback to malformed-frame sender | silent `return` on every drop path (bad tag, oversize, AEAD fail, malformed envelope) | PASS |

**KAT vectors:** spec §Test vectors hex values compared against `test/unit/vectors.test.ts` fixtures — identical (c_pub, s_pub, raw_shared, session_key, empty-secret key, proof, both transcripts, three auth-profile payloads). The suite (green) proves `src/` reproduces them.

### C1 — Client epoch exhaustion was not a terminal client error (Low) — **FIXED in this audit**

Checklist item 16 asserts "never wraps (**exhaustion is a terminal client error**)". The client incremented `epoch` per attempt and per reset with no guard at 0xffffffff. A JS number does not wrap (integer-safe to 2^53), so past 2^32−1 the server would reject every hello as `Invalid epoch` (`server.ts:614`) — an endless string of opaque handshake timeouts instead of the explicit terminal error the spec promises.

- **Security impact:** none (no wrap, no nonce/epoch reuse). Practical reachability: ~4.3 × 10⁹ handshake attempts on one client instance — pathological reconnect loops only.
- **Fix applied:** `src/client.ts` `startHandshake` — `epoch >= 0xffffffff` now rejects with `RPCError("CLIENT", "Handshake epoch exhausted; destroy and recreate client")`, mirroring the request-id counter guard (`:1028`) and placed before ephemeral key generation. `CLIENT` is the guardrail class: per checklist item 30 it never resets the session. The reset-path increment needs no guard of its own — an over-ceiling value is only compared locally for staleness and the next attempt hits the guard before anything reaches the wire.
- **Regression test:** none — deliberately. `epoch` is closure-private and reaches the ceiling only via 2^32 real handshakes; a test would require adding a test-only state-injection hook to the public surface of a security library, which is a worse trade than code-read evidence for an unreachable-in-practice guard. Conformance evidence: this section + the guard's in-code comment.
- **Gate re-run after fix:** 295 tests, lint, typecheck, ESM+CJS build — all green.

---

## 4. Verification performed (this audit)

1. **Full conformance pass** — all 44 normative checklist items of `spec/protocol.md` checked against `src/` with file:line evidence (§3); KAT vectors cross-checked spec ↔ test ↔ implementation.
2. **Per-finding code read at HEAD** — every fix located and read in `src/` / `spec/` (file:line citations above), not inferred from commit messages.
3. **Empirical repro re-runs** (tsx against `src/`): bigint over/under/boundary (#4), nested-undefined round-trip (#5), `isEmptySecret` at lengths 0/32/33/64 (#8), `deriveSessionSecret` with all-zero input (#8b). All produce the fixed behavior; all reproduced the defect on the pre-fix tree in round 2.
4. **Full gate:** `npm test` — **39 files, 295 tests, all green** (10.2 s). `npm run lint` — clean. `npm run build` — ESM + CJS + `cjs/package.json` marker, clean. `npm run test:typecheck` — clean.
5. **Targeted re-run** of the four fix-pinning suites (`review-round2-fixes-2026-07-15`, `middleware-attacks`, `replay-and-response-bounds`, `hung-auth-timeout`) — 17 tests green.
6. **Packaging smoke:** `require('./cjs/index.js')` and ESM `import './esm/index.js'` both load and export `client`/`server` (Node 22.22.1). `files` whitelist (`esm`, `cjs`, `src`) keeps review/spec working files out of the npm artifact.
7. **Dependency floor check:** `@noble/hashes` 2.2.0 `engines` read from the installed package.
8. **Branch hygiene:** commit list and diffstat vs `origin/main`; merge commit inspected; gitignore audit (see §5 — this found blocker B1).

---

## 5. New findings from this audit (blockers)

### B1 — Regression tests for the fixes are gitignored ⛔ merge blocker

`.gitignore:12` (`review-*`) matches **`test/security/review-fixes-2026-07.test.ts`** and **`test/security/review-round2-fixes-2026-07-15.test.ts`**. Both are untracked. These files carry the only regression coverage for #6a, #6b, #9 and five of the seven follow-up fixes (8 tests). Consequences on a fresh clone / CI: the suite runs 287, not 295; the highest-severity fix on the branch (#6) has **zero** committed regression coverage; `spec/assessment.md`'s "covered by the security test suite" claim is false for the repository as published.

**Fix:** rename the two files (e.g. `handshake-deadline.test.ts`, `hardening-2026-07.test.ts`) or narrow the ignore pattern to `/review-*` (root-anchored), then commit them. Mechanical, no code change.

*Note: this verdict file itself matches `review-*` and is untracked by the same rule — intentional if it stays historical; rename it if it must ship in the repo.*

### B2 — Version not bumped ⛔ publication blocker

`package.json` and `jsr.json` both say **0.7.1**. Publication requires `0.8.0` + `npm run sync:jsr` (release notes / tag per the usual flow). Already flagged in round 2 as a separate step; still pending.

### Hygiene (non-blocking)

Untracked worktree strays: `0.8-rev`, `auth-api-review-question.md`. Not part of the merge; delete or move out of the repo.

---

## 6. Residual risks (accepted, documented)

All by design and documented in `spec/assessment.md` / `spec/security.md`; none regressed on this branch:

1. **Replay window is narrowed, not closed** — a replay older than the last `replayWindow` (default 4096) accepted nonces still executes; non-idempotent handlers on long sessions need idempotency keys. Counter-based nonces deferred (require directional keys).
2. **One session key for both directions** — reflection protection rests solely on the `t` field check. This branch strengthened it (reflected `t: 2` frames no longer consume replay slots) but a port that omits the check loses the protection entirely. Flagged for a future protocol version. Residual micro-cost: each reflected frame still costs one AEAD decrypt, unbounded but cheap.
3. **Weak-secret offline oracle** — server-first proof lets an active attacker brute-force a low-entropy PSK offline. The secret must be a CSPRNG key, not a passphrase. Property of the scheme, unchanged.
4. **Hello-flood candidate starvation** — a flood of hellos can keep overwriting the candidate slot and delay a legitimate *re*-handshake (live session untouched). `maxPendingHandshakes` bounds callback accumulation, not ECDH cost. Rate-limit hellos in the channel adapter on exposed transports.
5. **JWT is a bearer credential** — theft of the token allows fresh handshakes until expiry; JWT-only additionally requires a confidential transport (now documented, #1).
6. **`@noble/curves` pin is load-bearing** for low-order point rejection — regression test `f002-low-order-x25519-pubkey.test.ts` pins it; re-run the suite on every dependency bump.
7. **No server-side concurrency cap / per-request timeout** — application concern, consistent with comparable RPC libraries; bound concurrency in handlers for untrusted peers.
8. **Node <20.19 excluded by declaration, not CI** — the floor is correct per the dependency's engines; no CI matrix run verifies the failure mode on 18.x/20.18 (acceptable: those are now outside the declared range).

---

## 7. Verdict

| Gate | Status |
|---|---|
| All 10 round-2 findings fixed and verified at HEAD | ✅ |
| Follow-up hardening fixed and verified | ✅ |
| Tests / lint / build / typecheck | ✅ 295 green, clean |
| Empirical repros reproduce fixed behavior | ✅ |
| Full spec conformance (44-item normative checklist) | ✅ 44 PASS (C1 fixed during audit) |
| KAT vectors: spec ↔ tests ↔ implementation | ✅ byte-identical |
| Regression tests committed to the repo | ⛔ B1 |
| Version / manifest ready for publish | ⛔ B2 |

**Merge to `main`: NOT READY — one mechanical blocker (B1).** The code and spec are ready as-is; merging without the two test files would land the highest-severity fix with no committed regression coverage and make the assessment's coverage claim false. Rename/commit the two test files and the branch is READY with no further review needed.

**Publication of 0.8.0: NOT READY — B1 + B2.** After B1: bump `package.json`/`jsr.json` to 0.8.0 (`npm version` runs the jsr sync), tag, publish. No code changes required for either blocker.
