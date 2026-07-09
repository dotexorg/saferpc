# Spec: make-before-break session replacement (saferpc server)

Status: ready to implement. Target: `src/server.ts` + four spec docs + one test
file. Companion background (prose, already shared): `handshake-continuity-review.md`.

This document is self-contained. An implementer should be able to work from it
without the discussion that produced it.

---

## 1. The problem in one paragraph

The server retires a live session too early. When a hello arrives it runs as an
attempt on attempt-local state, and the live session keeps serving *during* the
attempt — but at the publish step the code zeroes the old session key and installs
the new one immediately, before the new session has been confirmed by a real
encrypted frame. In signature mode the hello signature only covers
initiator-chosen fields (epoch, pub, nonce) with no server contribution, so a
byte-for-byte duplicate hello verifies again and reaches publish. Result: a
replayed hello ends a working session and replaces it with one that never comes
alive (whoever replayed the hello can't produce the confirming frame). Reproduced:
inject a captured hello into an established session, the next call times out.

The exact line today (`src/server.ts`, publish block ~`:549`):

```ts
if (attemptEpoch !== myAttempt || destroyed) return;
clearHsTimer();
if (sessionKey !== null) zero(sessionKey);   // ← old session dies HERE
epoch++;
seenClear();
sessionKey = localSessionKey;                 // ← before confirmation
encrypt = createEncryptor(sessionKey);
decrypt = createDecryptor(sessionKey);
authData = localAuthData;
state = "pending";
```

## 2. The property we want

> A live session may only be replaced by a counterparty that proves possession of
> the key material (the initiator's ephemeral private key, and the PSK if
> configured). A duplicate or stale hello — bytes the server already processed —
> must never retire the live session.

Underlying rule, worth stating in the spec: *a transition that destroys
authenticated state must be authenticated at least as strongly as the state it
destroys. Creating state is gated on identity; destroying it is gated on proof of
key possession.* A hello (identity) may create a candidate; only a confirming
frame (key possession) may retire the live session.

## 3. Design: two independent key slots

Replace the single module-level session with two slots that live side by side.

- **live** — the confirmed session. Serves all traffic: `decrypt` inbound,
  `encrypt` outbound. May be null (no session yet).
- **candidate** — a session derived from a successful hello attempt but *not yet
  confirmed*. Used only to *try* decrypting inbound frames. Never used to encrypt
  a reply until it is promoted. May be null.

The confirmation rule that already exists for a fresh session ("first frame that
decrypts under the new key makes it real") now also governs *replacement*:

- A hello attempt that passes all checks installs a **candidate** and sends the
  handshake reply. It does **not** touch `live`.
- On an inbound `TAG_MSG`, try `live.decrypt` first; on Poly1305 failure, try
  `candidate.decrypt`.
  - Decrypts under **live** → normal request handling, as today.
  - Decrypts under **candidate** → **promote**: candidate becomes live, old live
    is zeroed, candidate slot cleared. Then handle the request under the new live.
  - Decrypts under neither → silent drop, as today.

This unifies bootstrap and rekey: at bootstrap `live` is null and the first hello
installs a candidate that the first client frame promotes; at rekey `live` is
non-null and keeps serving until the candidate is confirmed. Same code path.

### 3.1 State model

Derive `state` from the slots rather than tracking it separately, or keep the
enum but redefine it:

- `waiting` — `live == null && candidate == null`.
- `pending` — `candidate != null` (regardless of whether `live` is null). A hello
  has been answered; we're waiting for the confirming frame. **If `live != null`
  it keeps serving throughout** — that is the whole point.
- `ready` — `live != null && candidate == null`.

Note the change in meaning: `pending` no longer implies "no working session". A
rekey attempt on a healthy session is `pending` with `live` still serving.

### 3.2 Hello handling — install candidate, don't touch live

In the publish block, replace the swap-in-place with a candidate install. Keep
everything above it (attempt-local ephemeral keys, verify, ECDH, secret, proof,
sign) exactly as it is — those already run on attempt-local state and are correct.

```ts
// FINAL publish guard — unchanged.
if (attemptEpoch !== myAttempt || destroyed) return;

// Install as CANDIDATE. Do NOT touch the live session.
// If a previous unconfirmed candidate exists, zero and replace it
// (latest attempt wins; see §6 residual on hello-flood).
clearCandidateTimer();
if (candidateKey !== null) zero(candidateKey);
candidateEpoch++;                       // see §3.4
candidateKey = localSessionKey;
localSessionKey = null;                 // ownership transferred
candidateDecrypt = createDecryptor(candidateKey);
candidateAuthData = localAuthData;
// candidateEncrypt is created on promotion, not now — we never encrypt
// under an unconfirmed key.

// Confirmation timer applies to the CANDIDATE only. On expiry, drop the
// candidate; the live session is untouched.
const myCandEpoch = candidateEpoch;
candidateTimer = setTimeout(function onCandidateTimeout() {
  if (candidateEpoch !== myCandEpoch || destroyed) return;
  dropCandidate();                      // zero candidateKey, clear slot
  if (onError !== null) {
    onError(new RPCError("HANDSHAKE", "Handshake timeout"));
  }
}, hsTimeout);

// send handshake reply (unchanged)
await channel.send(reply);
if (candidateEpoch !== myCandEpoch || destroyed) return;
```

`dropCandidate()`: zero `candidateKey`, null the candidate slot fields, clear
`candidateTimer`. Does not touch `live` or the seen-nonce window.

### 3.3 TAG_MSG handling — trial order + promotion

Current handler decrypts with the single `decrypt`. New handler tries live then
candidate. The seen-nonce pre-check (§3.5) stays before decrypt.

**Gate change (mandatory).** Today's handler opens with
`if (tag === TAG_MSG && decrypt !== null && encrypt !== null)`. In this model a
bootstrap has `live == null` (no `liveDecrypt`/`liveEncrypt`) and
`candidateEncrypt` does not exist by design, so the old gate would reject the
very frame that confirms a bootstrap and the session would never go live.
Replace the gate — and the internal re-check `if (decrypt === null || encrypt
=== null) return;` — with a condition keyed on **decrypt availability of either
slot**: `liveDecrypt !== null || candidateDecrypt !== null`.

```ts
if (tag === TAG_MSG && (liveDecrypt !== null || candidateDecrypt !== null)) {
  if (data.length > maxBytes) return;

  // seen-nonce pre-check applies to the LIVE window only (see §3.5)
  const nKey = data.length >= 1 + NONCE_LEN
    ? nonceKey(data.subarray(1, 1 + NONCE_LEN)) : null;
  if (nKey !== null && seenHas(nKey)) return;

  (async function handleRequest() {
    let raw: unknown = undefined;
    let decryptedUnder: "live" | "candidate" | null = null;

    if (liveDecrypt !== null) {
      try { raw = liveDecrypt(data); decryptedUnder = "live"; } catch {}
    }
    if (decryptedUnder === null && candidateDecrypt !== null) {
      try { raw = candidateDecrypt(data); decryptedUnder = "candidate"; } catch {}
    }
    if (decryptedUnder === null) return;   // neither key — silent drop

    // Promotion (if any) MUST happen before reqEpoch is captured — it
    // advances `epoch` (§3.4). Capturing reqEpoch before this would make
    // the response guard drop the reply to this very frame. See below.
    if (decryptedUnder === "candidate") {
      promoteCandidate();                  // §3.4 — advances epoch
    }

    // Capture the response-guard epoch AFTER promotion, not at frame arrival.
    const reqEpoch = epoch;

    // record nonce in the (now-current) live window AFTER successful decrypt
    if (nKey !== null) seenAdd(nKey);

    // ... existing request handling, unchanged, using liveEncrypt for the
    //     response, guarded at the end by `if (epoch !== reqEpoch ...) return;`
  })();
}
```

Important ordering details:

- Try **live first** so steady-state traffic pays only one decrypt. Candidate is
  tried only when a frame fails under live (a genuine rekey confirmation, or junk).
- **`reqEpoch` is captured AFTER decrypt + promotion, not at frame arrival.**
  This is the one non-obvious correctness point. Today `const reqEpoch = epoch`
  is captured synchronously at the top of the handler, which is safe only because
  `epoch` advances at *publish* (before the frame arrives). Here `epoch` advances
  inside `promoteCandidate()`, i.e. *while processing the confirming frame*. If
  `reqEpoch` were captured before promotion, the final response guard
  (`epoch !== reqEpoch`) would drop the reply to the first call after every rekey
  and every bootstrap — reproducing the exact symptom of the bug this spec fixes.
  The confirming frame is not an in-flight leftover; it *is* the promoter.
- The nonce is recorded in the seen window **after** a successful decrypt, and
  after promotion, so it lands in the correct (post-promotion) live window.
- Do the sync decrypt + promotion **before** the first `await` in request
  handling, so back-to-back frames can't both trigger a promotion race.

### 3.4 promoteCandidate()

```ts
function promoteCandidate(): void {
  clearCandidateTimer();
  if (liveKey !== null) zero(liveKey);   // retire old live
  liveKey = candidateKey;
  liveEncrypt = createEncryptor(liveKey);
  liveDecrypt = candidateDecrypt;        // reuse the decryptor we just used
  liveAuthData = candidateAuthData;
  epoch++;                               // response-guard epoch advances
  seenClear();                           // new key → old nonces irrelevant
  // clear candidate slot (ownership moved to live; don't zero liveKey)
  candidateKey = null;
  candidateDecrypt = null;
  candidateAuthData = null;
  state = "ready";
}
```

**Three counters, three distinct jobs — keep all of them.** The two new ones
**complement** `attemptEpoch`; they do not replace it. Removing `attemptEpoch`
breaks D1's cancellation of competing attempts.

- **`attemptEpoch`** (exists today, DO NOT remove) — bumped on **every incoming
  hello**, before any `await`. Guards the three mid-attempt suspension points in
  `handleHello` (after `verify`, after `secret()`, after `sign`) so a stale
  suspended attempt abandons all writes when a newer hello arrives. This is the
  D1 mechanism; §3.2's publish guard still reads `attemptEpoch !== myAttempt`.
- **`candidateEpoch`** (new) — bumped **only when a candidate is installed** (in
  the publish block). Guards the candidate confirmation timer. It must be
  separate from `attemptEpoch`: if the timer were guarded on `attemptEpoch`, a
  later hello that bumps `attemptEpoch` and then *fails validation* (never
  installs a candidate) would disarm the *existing* candidate's timeout →
  an immortal unconfirmed candidate wedging the slot.
- **`epoch`** (exists today) — now advances on every **promotion** instead of at
  publish. In-flight responses from the previous live session self-drop at the
  existing response guard (`epoch !== reqEpoch`). Keep the guard; note the
  capture-timing fix in §3.3.

### 3.5 seen-nonce window

The window belongs to the **live** key. Rules:

- Pre-check and record against the live window only (candidate has no window —
  it's confirmed by a single frame; a replayed hello can't produce a valid
  candidate frame, so there's nothing to dedup there).
- `seenClear()` on promotion (already done inside `promoteCandidate`).
- No change to the ring/set structure or the `replayWindow` option.

### 3.6 resetHandshake / destroy

- **`resetHandshake()` loses its only caller.** Today it is invoked solely from
  the `hsTimer` callback; in this model the candidate timer calls
  `dropCandidate()` instead, and a confirming-frame timeout no longer tears down
  a live session. So `resetHandshake()` becomes dead code. Either delete it, or
  keep it deliberately for a future explicit-teardown path and say so in a
  comment — do not leave it looking live. If kept, it must clear **both** slots
  (zero `liveKey` and `candidateKey`, both timers, `seenClear()`,
  `state="waiting"`) and must not regenerate any module-level ephemeral (there is
  none — ephemerals are attempt-local, §4).
- `dropCandidate()`: zero `candidateKey`, null the candidate slot fields, clear
  `candidateTimer`. Leaves `live` and the seen window untouched.
- `destroy()`: zero both slots, clear both timers, unsubscribe.

## 4. Invariant to lock (do not skip)

The whole property rests on the server's ephemeral key being **fresh per hello
attempt**. It already is — `src/server.ts:407`:

```ts
const myPriv = x25519.utils.randomSecretKey();  // inside handleHello()
const myPub  = x25519.getPublicKey(myPriv);
```

If this key were ever moved back to module scope (as it was pre-D1), a duplicate
hello would derive the *same* key as the live session, and replayed traffic could
decrypt under the "candidate" and promote it — turning the continuity bug into a
full session-traffic replay. Add an implementation-checklist bullet to
`protocol.md` stating the ephemeral pair is generated per attempt and never held
at module scope, so a refactor can't silently reopen this.

## 5. Optional follow-up (decide, don't default): previous-key grace

WireGuard keeps the just-retired key decrypt-only for a short grace window so
messages already in flight under it aren't lost when a rekey promotes.

In saferpc the client is the sole handshake initiator and the server only
*responds*, so at a legitimate rekey the client has already moved to the new key;
inbound frames under the old live key are unlikely. This makes previous-key grace
lower value here than in WireGuard's symmetric case. **Recommendation:** ship §3
(live + candidate) first — it fully closes the continuity bug — and treat a third
`previous` slot as a separate, optional change only if a concrete in-flight-loss
case shows up during legit rekey. If added: a `previous` slot, decrypt-only, with
its own short grace timer, tried after candidate; never promotes, never encrypts.
Not required for the property in §2.

## 6. Out of scope (name, don't fix here)

- **Weak-secret proof oracle.** The server returns its HMAC proof to any
  well-formed hello, and the proof derives from a key salted with the PSK. Anyone
  who completes an ECDH can grind PSK guesses offline against the proof. Infeasible
  against a random 32-byte key (2²⁵⁶); real against a password-derived secret.
  Pre-existing, not introduced here. → **doc only** (§7, security.md): the secret
  must be a CSPRNG key, not a passphrase; if password-derived, run it through a
  slow KDF (scrypt/argon2) first.
- **Hello-flood starving a legit reconnect.** Latest-hello-wins means a flood of
  hellos keeps overwriting the candidate slot, so a legitimate peer's rekey
  candidate can be evicted before its confirming frame lands. DoS is explicitly
  outside saferpc's threat model. → **assessment.md**: name it as an accepted
  residual; note the cheap partial mitigation (drop byte-identical duplicate
  hellos via a small recent-transcript-hash cache before signature verification)
  as a possible future hardening, not shipped now.

## 7. Spec/doc changes

- **protocol.md**
  - §Handshake step 10 + §Re-handshake: the live session is replaced on the
    *first confirming frame under the candidate key*, not at publish. Publish
    installs a candidate; promotion retires the old live.
  - State machine (server): redefine `pending` as "candidate present, live may
    still be serving"; promotion edge is "first TAG_MSG decrypts under candidate".
  - Implementation checklist: add the §4 ephemeral-per-attempt invariant; update
    the "server accepts new hellos in any state" bullet to "a hello installs a
    candidate and never retires the live session before confirmation".
  - Add the §2 underlying rule as a short normative note.
- **security.md**: §Replay within a session unchanged; add the §6 weak-secret
  paragraph near the `secret` requirements.
- **assessment.md**: risk #3 (unauthenticated teardown) → note that duplicate/
  stale hello can no longer retire a live session in *either* mode (was "residual
  in PSK-only"); add the §6 hello-flood residual.
- **api.md**: no option changes. If `state` is observable anywhere, sync its
  described meaning.

## 8. Tests — `test/security/session-continuity.test.ts`

Use neutral naming/comments (no attack vocabulary; the test suite is read by
tooling that false-positives on it).

1. **Duplicate hello leaves the live session intact.** Establish a PSK session,
   capture the client hello, re-inject it into the server. Assert: subsequent
   calls succeed, and the client performed exactly one handshake (count TAG_HELLO
   frames == 1). Regression for the core bug.
2. **Same, signature mode.** With Ed25519 verify configured, re-inject the
   captured signed hello. Assert the live session survives (this is the case the
   old code broke even with verify configured).
3. **Genuine rekey still works — and the FIRST call after it gets a reply.** Force
   the client to a fresh handshake (real new ephemeral key), then make a call and
   **await its result**. This is the regression that catches the §3.3 reqEpoch
   capture-timing bug: if `reqEpoch` is captured before promotion, this first
   post-rekey call times out. The test MUST assert the resolved value, not just
   that a handshake happened.
4. **Candidate expiry.** Install a candidate (hello) that is never confirmed;
   after `handshakeTimeout` assert the candidate is dropped and the prior live
   session (if any) still serves.
5. **Promotion clears the replay window.** Non-trivial to write: clients use
   random nonces, so an old captured frame won't decrypt under the new key and
   you can't just replay bytes. Options: (a) assert the *observable* effect —
   after a rekey, normal traffic continues to be accepted (the window didn't
   carry stale entries that would false-reject); or (b) drive it with a seeded/
   stubbed RNG and a hand-assembled frame that reuses a nonce under the new key.
   Flag this in the test so the implementer doesn't burn an hour on "why won't it
   reproduce". Prefer (a) unless you specifically want to pin the clear.

Verified assumption (no test needed beyond #1, but note it): the server's
handshake reply to a duplicate hello reaches the legitimate client on the shared
channel and does **not** confuse it — `client.ts:347` guards
`if (tag === TAG_HELLO && state === "handshaking")`, so an unsolicited reply in
`ready`/`idle` is silently dropped. Test #1 covers this behaviorally.

Keep the existing `deferred-reset.test.ts` D1 tests green (they assert the weaker
"garbage hello during attempt doesn't reset" property, which make-before-break
also satisfies).

## 9. Open questions for the implementer

1. `state` enum vs derived: keep the three-value enum with redefined meaning
   (§3.1) or compute it from slot nullness? Enum is less churn; make sure every
   site that reads `state` still means the right thing (esp. the pending→ready
   promotion check now lives in the TAG_MSG decrypt branch).
2. Response epoch guard: the confirming frame's `reqEpoch` is captured AFTER
   promotion (§3.3), so its own reply survives the guard. Responses to requests
   that were genuinely in flight under the *pre-promotion* live session still
   drop when promotion advances `epoch` — acceptable, same as today's
   re-handshake behavior. Confirm no path captures `reqEpoch` before the
   decrypt/promotion step.
3. Does any caller rely on the old side effect that a hello *immediately* moved
   state to `pending` (e.g. tests, onError timing)? Grep before changing.
4. Stale docstrings: the file-header lifecycle comment and the D1 comment
   ("torn down only when the attempt fully validates and publishes") describe the
   old publish-retires-live behavior. Update them together with protocol.md, or
   they become false descriptions of the code.
```
