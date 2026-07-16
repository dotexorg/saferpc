# 0.8.0 correctness & spec-conformance review — round 2

Context: I maintain an open-source RPC library and I'm gating its 0.8.0 release. Below are ten correctness / specification-conformance deltas found on commit `36ebeaa`. All are internal engineering findings about my own code and my own protocol spec — I'm deciding which block the release and whether my proposed fixes are right. The full test suite (279 cases), build, lint and typecheck are all green; these are gaps the suite does not currently cover.

**My question for you:** `<< paste your question here — e.g. which of these block a 0.8.0 release, and are the proposed fixes correct? >>`

---

## 1. Credential field is wire-observable in the opening frame

The JWT auth profile places the token in the auth payload, which travels in the first, not-yet-encrypted handshake frame (`src/auth/client.ts:46-51`, `src/client.ts:602-613`). My threat model already lists a passive observer of the transport as in-scope (`spec/security.md:9`). The docs correctly note that a bearer token can be reused if obtained (`security.md:314-316`), but they never state the direct consequence: in JWT-only mode over a non-confidential transport, the token is readable in that opening frame. Code is correct by design (the opening frame carries the ephemeral public key and cannot be encrypted yet). This is a documentation-completeness gap: the JWT section should say JWT-only requires a confidential transport, or a PSK / signature mode.

## 2. Asymmetric examples authenticate only one direction

The shipped examples give the client `sign` and the server `verify` (`spec/getting-started.md:222-237`, `security.md:333-348`). That establishes the client's identity to the server, but the client never establishes the server's identity — with an empty pre-shared secret the client's proof only demonstrates possession of the current ephemeral key, so the client will complete a handshake with any endpoint that finishes the key exchange. The protocol deliberately permits one-directional configuration (`protocol.md:260`), so the code conforms. The gap is that the examples don't state that mutual authentication needs both sides configured (`sign`+`verify` each) or a PSK.

## 3. Package declares a Node range the build doesn't support

`package.json` sets `engines.node: ">=18"`, but `@noble/* ^2.2.0` requires Node ≥ 20.19, and the CommonJS build loads these ESM-only dependencies via `require()`. Result:

```text
Node 18.20.8  → module-load error (ERR_REQUIRE_ESM)
Node 20.18.3  → module-load error
Node 20.19.5  → OK
Node 22       → OK
```

README promises both Node 18+ and a dual ESM/CJS build. Fix: raise the declared floor to the real one (≥ 20.19) and correct the README, or pin dependencies that still support 18.

## 4. Integers beyond 64 bits are silently altered

The input sanitizer passes any `bigint` through unchanged, and the encoder (`useBigInt64: true`) then reduces it to 64 bits (`src/common.ts:203`). Round-trip:

```text
18446744073709551616n → 0n
-9223372036854775809n → 9223372036854775807n
```

An end-to-end echo of `18446744073709551616` returns `0` — a silent value change, not an error. The protocol permits big integers but pins no range. Fix: reject out-of-range `bigint` in the sanitizer as invalid input, or document the hard `[-2^63, 2^64−1]` range.

## 5. Nested `undefined` diverges from the declared type contract

Top-level `undefined` is handled correctly (the field is omitted). Inside an object the sanitizer keeps `undefined` and the encoder writes it as `null`. So a type-valid call with an optional string field set to `undefined` arrives on the server as `null` and fails validation ("expected string, received null"), while an empty object passes. The same happens on the response path. The encoder does not set the "ignore undefined" option, so the default keeps it. Fix: strip `undefined`-valued keys in the sanitizer to match the top-level omission behavior, or enable "ignore undefined" and document it.

## 6. Second handshake phase has no absolute-deadline check ("the guard")

This is the main code finding. The handshake is time-boxed. The first phase (accepting the opening frame) checks an absolute wall-clock deadline on every continuation, not just a timer:

```ts
// server.ts:513-516
const attemptDeadline = attemptStart + hsTimeout;
const attemptDead = () => attemptExpired || Date.now() >= attemptDeadline;
```

with a comment explaining that a timer alone is insufficient because a JS timer is only a wakeup and can fire late, so each guard also checks the clock — matching the spec (`protocol.md:262-265`).

The second phase — a pending candidate session waiting for its confirming frame — has no such check. Searching the file for a candidate deadline returns zero hits; the remaining budget feeds only a `setTimeout` (`server.ts:709`), and the confirming frame calls `promoteCandidate()` (`:831`) with no clock check (`promoteCandidate` only guards `candidateKey === null`, `:424`). Consequence when the event loop is busy longer than the budget (measured: 160 ms busy vs a 100 ms budget): the confirming frame is processed before the overdue timer fires, and an already-expired candidate is promoted and its request runs. The spec disallows this.

Related: on a handshake timeout the server can emit two error callbacks for one attempt — the timer fires "timeout" without advancing the attempt epoch, then a late async-callback rejection reaches the catch (`:766`), which checks only the epoch (still equal) and fires "handshake failed" as well. A late reply-send rejection doubles the same way.

Fix, symmetric to phase one: store a candidate deadline (`attemptStart + hsTimeout`), check it in the frame handler before promoting (drop the candidate if past), and gate the attempt catch on an "already reported" flag so one attempt yields at most one error callback.

## 7. Fire-and-forget `next()` can produce an unhandled promise rejection

The docs now allow middleware to call `next()` without returning or awaiting it. If the middleware returns its own value and the downstream step later rejects, the client already has the middleware's result and the downstream promise is unobserved (`src/server.ts` `runMiddleware`). On a Node process with no `unhandledRejection` handler this can terminate the process. This is a direct consequence of the same-day change that started accepting the fire-and-forget pattern. Fix: either attach a `.catch` to the unobserved downstream promise, or remove the "unreturned `next()` is supported" claim from the docs.

## 8. All-zero secret guard only covers one length

The guard that rejects an all-zero secret returns early for any length other than 32 bytes, treating it as non-empty:

```ts
export function isEmptySecret(buf: Uint8Array): boolean {
  if (buf.length !== KEY_LEN) return false; // any non-32 length ⇒ "not empty"
  let acc = 0;
  for (let i = 0; i < buf.length; i++) acc |= buf[i]!;
  return acc === 0;
}
```

So 32 zeros are rejected but 33, 64, 65 zeros pass. Separately, deriving a session secret from a public identifier and a zero input yields a deterministic, publicly reproducible value the handshake accepts — while the security example (`security.md:203-207`) says such a configuration should fail. Fix: reject an all-zero secret of any length, and reconcile the derivation helper with the documented example.

## 9. Same-session opposite-direction frames consume replay-window slots

Both directions of a session use one key. The server records a frame's nonce right after the authentication tag verifies but before the direction check, so a genuine server response fed back to the server passes the crypto check and takes a slot in the replay window. Measured with a window of 2: replaying one server response advances the handler count by one extra and evicts the oldest request nonce a request early. Not a full defeat of the mechanism, but the effective window can shrink by roughly half. The in-code comment "unforgeable frames can never pollute the window" (`server.ts:787-792`) doesn't account for frames produced by the other direction of the same session. Fix: record the nonce only after the direction check passes, or size the window accounting for both directions.

## 10. Context-error contract contradicts itself in the spec

One passage (`protocol.md:430`) says a typed error thrown from the context factory keeps its code, message and data; two others (`:446`, `:595`) plus the conformance checklist require masking it to a generic INTERNAL error. The code keeps the typed error. A second implementer of this protocol can't pick a behavior unambiguously. Fix: choose one rule and align the other passages (and the code, if masking is chosen).

---

## Proposed order

1. #6 second-phase deadline check + single error callback (main code bug)
2. #4 / #5 / #8 small input/guard fixes
3. #7 decide: observe the downstream promise, or retract the fire-and-forget claim
4. #9 nonce-record ordering
5. docs #1 / #2 / #10
6. #3 raise Node floor + README

Version fields in `package.json` / `jsr.json` are still 0.7.0 — separate release bump.
