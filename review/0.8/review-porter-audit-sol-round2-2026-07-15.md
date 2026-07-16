# Porter audit round 2 — gpt-5.6-sol:high, 2026-07-15

**Target:** HEAD `36ebeaa` (branch `0.8.0-fixes`), release candidate 0.8.0.
**Method:** adversarial re-read after the previous 9 findings were closed, plus runtime probes. All 9 prior items confirmed fixed.
**Verdict:** **0.8.0 not release-ready.** 10 new divergences below. Artifact verification added per item by opus (main agent) 2026-07-15 — every finding re-checked against `src/`, not inherited.

## Resolution status (2026-07-15, opus)

All 10 addressed. Gate after fixes: tsc (main+test) clean, project-lint clean, **291/291** tests (+12 regressions, each verified red-before-green), build (ESM+CJS) + `npm pack` clean.

| # | Kind | Fix | Regression |
|---|------|-----|------------|
| 1 | doc | security.md: JWT wire-visible → needs confidential transport | — |
| 2 | doc | security.md "Authentication is directional" + getting-started caveat | — |
| 3 | config | `engines.node` → `>=20.19.0`, README | — |
| 4 | code | `sanitize()` rejects bigint outside `[-2^63, 2^64-1]` | sanitize.test.ts |
| 5 | code | sanitizer drops `undefined`-valued object keys | sanitize.test.ts |
| 6 | code | candidate-promotion absolute-deadline check + single onError | review-round2-fixes |
| 7 | code+doc | downstream promise observed on fire-and-forget `next()`; spec note | middleware-attacks |
| 8 | code+doc | `isEmptySecret` any-length; `deriveSessionSecret` rejects zero input; doc | psk-auth.test.ts |
| 9 | code | nonce recorded only after direction (`t`) check | review-round2-fixes |
| 10 | doc | protocol.md 446/595/726 aligned to code (typed context error preserved) | — |

Still pending (not a code fix): version bump `package.json` / `jsr.json` 0.7.0 → release.

> Note: sol produced these findings. An Opus-model verification pass was blocked mid-run by Anthropic's content-safety refusal (flagged the security probes as "violative cyber content"); the artifact re-check below was completed on the main agent without refusal. fable-5 is not wired to any agent; the non-Anthropic reviewers are `porter-audit-sol` / `reviewer-luna` (gpt-5.6).

## Gate at time of review

- `npm test`: 279/279 passed
- `npm run test:typecheck`: passed
- `npm run lint`: passed
- `npm run build`: passed
- ESM/CJS smoke on Node 22: passed
- `npm pack --dry-run`: passed
- Tracked files unchanged; `?? auth-api-review-question.md` still present
- `package.json` / `jsr.json` still at 0.7.0 — separate release bump pending

All findings are holes that pass the current test suite.

---

## 1. 🔴→🟠 JWT bearer visible in cleartext handshake frame

**Priority:** sol 🔴 / opus 🟠 (documentation completeness, not a code bug)
**Code:** `src/auth/client.ts:46-51`, `src/client.ts:602-613`
**Spec:** `spec/security.md:9,314-316`

`createJWTClientAuth()` puts the JWT into the auth payload, which rides the **unencrypted** TAG_HELLO. Probe decoded the token straight off the frame:

```text
{ capturedJwt: "secret-bearer-token", outerEncrypted: false }
```

The transcript digest binds the payload to this handshake but does not hide the JWT. A passive eavesdropper on the transport harvests the bearer token directly and can mint a fresh payload for its own session.

**Artifact check (opus):** `security.md:316` is honest about bearer *reuse* ("anyone holding one can authenticate until it expires. Combine with PSK or a real signature mode when this matters") and `security.md:9` lists eavesdrop in the threat model. But no text connects the dots: the JWT travels in cleartext in the hello, so **JWT-only mode over an untrusted transport hands the token to any passive listener**. Real gap, but in docs, not code.

**Required alignment:** state in the JWT section that JWT-only requires a confidential transport (or PSK / signature mode) because the token is wire-visible in the hello.

## 2. 🔴→🟠 Asymmetric examples do not authenticate the server

**Priority:** sol 🔴 / opus 🟠 (examples/docs; code is correct)
**Spec:** `spec/getting-started.md:222-237`, `spec/security.md:333-348`
**Code correct per:** `spec/protocol.md:260`

The built-in examples give the client `sign` only and the server `verify` only — one-directional. This authenticates the client to the server, but the client never verifies the server's identity. Under EMPTY_SECRET the client's HMAC proof only proves possession of the current ephemeral key. Probe: a client holding a real Ed25519 device key completed a handshake with an `attacker-server` that does not check the client proof.

**Artifact check (opus):** the protocol explicitly permits one-directional configuration (`protocol.md:260`), so the code conforms. The mutual-auth machinery and the MFA cross-principal warning exist (`security.md:323`). The gap is that the **examples** never state one-directional ≠ mutual: for the client to authenticate the server you need both directions (`sign`+`verify` on each side) or a PSK.

**Required alignment:** annotate the asymmetric examples with the one-directional caveat.

## 3. 🔴 CommonJS build breaks on the declared Node range

**Priority:** 🔴 (verified real)
**Code:** `package.json:40,54`

`engines: { node: ">=18" }`, but `@noble/* ^2.2.0` requires Node ≥ 20.19.0 and the CJS build calls ESM-only deps through `require()`.

```text
Node 18.20.8  → ERR_REQUIRE_ESM
Node 20.18.3  → ERR_REQUIRE_ESM
Node 20.19.5  → OK
Node 22       → OK
```

ESM entry loads on Node 18 but the dependency engines still conflict with the declared range. README promises Node 18+ AND dual ESM/CJS.

**Artifact check (opus):** confirmed `package.json:40` (`@noble/* ^2.2.0`) and `:54` (`node >=18`). Real.

**Required alignment:** raise `engines.node` to the real floor (≥ 20.19) and correct README, or pin deps that support 18.

## 4. 🔴 BigInt beyond 64 bits silently changes value

**Priority:** 🔴 (verified real)
**Code:** `src/common.ts` `sanitize()`, `mpEncode(..., { useBigInt64: true })` at `:203`

`sanitize()` returns any bigint unchanged (`typeof v !== "object" → return v`, no range guard). `mpEncode` then truncates to 64 bits:

```text
18446744073709551616n → 0n
-9223372036854775809n → 9223372036854775807n
```

End-to-end echo probe: `input 18446744073709551616 → output 0, equal: false`.

**Artifact check (opus):** confirmed — no range check between `sanitize()` and encode. The protocol permits big-integer but does not pin a range.

**Required alignment:** reject bigint outside `[-2^63, 2^64−1]` in `sanitize()` as `INVALID_DATA`, or document the hard range.

## 5. 🔴 Nested `undefined` violates the typed Zod contract

**Priority:** 🔴 (verified real)
**Code:** `src/common.ts` `mpEncode` (no `ignoreUndefined`)

Top-level `undefined` correctly omits `i`. Inside an object the sanitizer keeps `undefined` and msgpack encodes it as `nil`, so a type-valid call:

```ts
z.object({ x: z.string().optional() });
api.method({ x: undefined });
```

arrives on the server as `{ x: null }` → `INPUT_VALIDATION: expected string, received null`. `api.method({})` passes. Symmetrically, output `{ x: undefined }` reaches the client as `{ x: null }` though the inferred type promises `undefined`.

**Artifact check (opus):** confirmed — `mpEncode` (`common.ts:203`) does not set `ignoreUndefined`; @msgpack default is `false` → `undefined` encodes as `nil`.

**Required alignment:** either strip `undefined`-valued keys in the sanitizer (match top-level omission semantics), or set `ignoreUndefined: true` and document it.

## 6. 🟠 Server handshake deadline depends on timer-callback execution ("the guard")

**Priority:** 🟠 (verified real — the core code bug of this round)
**Code:** `src/server.ts` `promoteCandidate()` `:424`, candidate timer `:709`, TAG_MSG promote `:831`
**Spec:** `spec/protocol.md:262-265`

The attempt phase has an absolute-deadline guard:

```ts
// server.ts:513-516
const attemptDeadline = attemptStart + hsTimeout;
const attemptDead = () => attemptExpired || Date.now() >= attemptDeadline;
```

with the comment "The timer alone is not enough… Every guard therefore also checks wall-clock time" — matching the spec's "timer callbacks are only wakeups, every continuation after an async suspension must check the absolute deadline."

The **candidate-promotion phase has no equivalent.** `grep candidateDead|candidateDeadline src/server.ts` → 0 hits. `remainingBudget` feeds only the `setTimeout` at `:709`; the confirming TAG_MSG calls `promoteCandidate()` (`:831`) with no wall-clock check — `promoteCandidate` only guards `if (candidateKey === null) return`.

Probe with `handshakeTimeout: 100`:
1. candidate installed;
2. event loop busy 160 ms;
3. confirming frame processed before the overdue timer callback;
4. candidate promoted, request executed — an already-expired candidate confirmed.

**Second half — double onError.** The attempt timer fires `onError("Handshake timeout")` and sets `attemptExpired = true` but does not advance `attemptEpoch`. A later async auth-callback rejection reaches `onHsError` (`:766`), which only checks `attemptEpoch !== myAttempt` — still equal → fires a second `onError("Handshake failed")`. Late reply-send rejection produces the same doubling (timeout + "Handshake reply send failed").

```text
HANDSHAKE: Handshake timeout
HANDSHAKE: Handshake failed
```

**Artifact check (opus):** both halves confirmed. The deadline guard is half-built: present for the attempt, absent for promotion.

**Required alignment:** store `candidateDeadline = attemptStart + hsTimeout`; check `Date.now() >= candidateDeadline` in the TAG_MSG handler before `promoteCandidate()` (drop the candidate if expired). Gate the attempt catch on an already-reported flag so one attempt yields at most one `onError`.

## 7. 🟠 Unreturned `next()` can create an unhandled rejection

**Priority:** 🟠 (verified real — regression surface of the 2026-07-15 middleware change)
**Code:** `src/server.ts` `runMiddleware`

The docs now permit calling `next()` without return/await. If the middleware returns its own value and downstream later rejects, the client already has the middleware result and the downstream promise is unobserved:

```text
client result: outer-success
unhandled: 1 ["downstream-boom"]
```

On Node without an `unhandledRejection` listener this can terminate the process.

**Artifact check (opus):** confirmed. `result = await mw(...)` awaits the middleware's own return, not the downstream promise returned by `next()`; if unreturned and it rejects, nothing catches it. The `completed` guard does not cover this. This is a direct consequence of the sync/unreturned-`next()` pattern accepted in the same-day middleware fix.

**Required alignment:** either attach a `.catch` to the downstream promise when the middleware does not observe it, or drop the "unreturned `next()` is supported" claim from the spec/API docs.

## 8. 🟠 All-zero secret guard covers only one length

**Priority:** 🟠 (verified real)
**Code:** `src/common.ts` `isEmptySecret()`
**Spec:** `spec/security.md:203-207`

```ts
export function isEmptySecret(buf: Uint8Array): boolean {
  if (buf.length !== KEY_LEN) return false; // ← any non-32 length ⇒ "not empty"
  let acc = 0;
  for (let i = 0; i < buf.length; i++) acc |= buf[i]!;
  return acc === 0;
}
```

```text
32 zeros → REJECTED
33 zeros → ACCEPTED
64 zeros → ACCEPTED
65 zeros → ACCEPTED
```

Also `deriveSessionSecret("public-session-id", new Uint8Array(32))` turns a zero input into a non-zero but publicly derivable result the handshake accepts — diverging from `security.md:203-207`, which says such a config fails HANDSHAKE.

**Artifact check (opus):** confirmed — the `length !== KEY_LEN → false` early return lets any non-32 all-zero buffer through.

**Required alignment:** reject an all-zero secret of any length (guard the accumulator regardless of length), and reconcile `deriveSessionSecret` with the security.md example.

## 9. 🟡 Reflected server responses consume replay-window slots

**Priority:** 🟡 (verified real, subtle)
**Code:** `src/server.ts:787-792` (D2 replay comment), nonce record before `t` check

Both directions use one session key. The server records the nonce after a successful Poly1305 but before the `t` check, so a genuine server response reflected back to the server passes the crypto check and occupies a replay slot.

Probe with `replayWindow: 2`:

```text
without reflected response: handler count = 2
with reflected response:    handler count = 3
```

Adding the response nonce evicts the oldest request nonce one request early. No full bypass, but the effective window can shrink ~2×.

**Artifact check (opus):** confirmed. The comment "unforgeable frames can never pollute the window" (`server.ts:787-792`) does not account for frames the *other direction of the same session* produces.

**Required alignment:** record the nonce only after the `t`-direction check passes (so opposite-direction frames don't consume slots), or account for both directions in the window sizing/comment.

## 10. 🟡 Context error contract contradicts itself

**Priority:** 🟡 (verified real — spec self-contradiction)
**Spec:** `spec/protocol.md:430` vs `:446,595` + conformance checklist

`:430` says a typed `RPCError` thrown from the context factory keeps its `code`/`message`/`data`; `:446,595` and the checklist require a generic `INTERNAL`. The code preserves the typed error:

```text
RemoteRPCError  code: CTX_DENIED  message: "context detail"  data: { why: "x" }
```

**Artifact check (opus):** the two spec passages disagree; a port cannot pick a behavior unambiguously. Code follows `:430` (preserve typed).

**Required alignment:** pick one rule. If context-thrown typed errors should surface (matches code), fix `:446,595` + checklist to carve out the context stage; otherwise mask to `INTERNAL` and change the code.

---

## Suggested fix order

1. **#6** candidate-promotion deadline guard + single-onError (the core code bug of this round)
2. **#4 / #5 / #8** small code guards (bigint range, nested-undefined, all-zero secret any length)
3. **#7** decide: catch unobserved downstream, or retract the unreturned-`next()` claim
4. **#9** nonce-record ordering vs the `t` check
5. **doc pack #1 / #2 / #10** (JWT cleartext caveat, asymmetric one-directional caveat, context-error contract)
6. **#3** bump `engines.node` + README

## Cross-reference

- Prior round (all closed): `review-porter-audit-sol-2026-07-14.md` (Batches 1–4 + ambiguity closures).
- Same-day middleware fix that #7 regresses on: commit `36ebeaa`.
