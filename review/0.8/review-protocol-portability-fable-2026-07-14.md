I have everything needed. Here is the audit.

---

# Safe RPC — Spec-vs-Implementation Port Audit

Scope: `spec/protocol.md` as sole normative input; `src/` consulted only to check what the spec pins. Findings are what a clean-room Rust/Go/Python porter would get wrong or leave insecure/incompatible. All line numbers are from the current tree.

---

## P0 — port would be wire-incompatible or insecure

### P0-1. msgpack **integer-width profile** is unspecified; the reference decoder maps 64-bit wire ints to BigInt and strict-checks `number`/`=== 1`, so a naïvely-encoded port is silently rejected

**Section:** Primitives / Frame format / RPC message format / Auth payload profiles (all msgpack).
**What's missing:** The spec says "msgpack, all extension types disabled" and, for the frame vector only, "map-key order follows encoding order." It never pins **which msgpack integer width** encodes the integer-valued fields, nor the decode-side number↔BigInt boundary. This is not cosmetic — it breaks interop:

Measured against the shipped codec (`mpEncode`/`mpDecode` use `useBigInt64: true`, `src/common.ts:180,184`):

- A wire **int64/uint64** (`0xd3`/`0xcf`) decodes to **BigInt**; every narrower int decodes to **number**.
- Receivers strict-check: server `msg["t"] !== 1` (`src/server.ts:830`), `typeof clientEpoch !== "number"` (`src/server.ts:544`), client `msg["t"] !== 2`, JWT verifier `typeof ts !== "number"` (`src/auth/server.ts`), version `payload["v"] !== 1` (`src/auth/server.ts:41`).
- Proven: a foreign encoder that writes `t: 1` as uint64 makes the TS server see `1n`, and `1n === 1` is **false** → frame silently dropped. Same for `epoch`/`v` → handshake fails; for `ts` → `UNAUTHORIZED`.
- Reference encoder emits non-negative integers ≤ 2³²−1 as fixint/uint8/16/32, integer-valued numbers **> 2³²−1 as float64 (`0xcb`)**, and int64/uint64 **only for BigInt** values.

Consequence for JWT `ts` (`Date.now()` ≈ 1.78e12): the reference puts it on the wire as **float64** (verified: `cb42…`). A port that encodes `ts` as msgpack uint64 (the natural choice for a ms timestamp) is decoded to BigInt and rejected with `"Invalid timestamp"`.

**Proposed wording (Primitives, add subsection "msgpack profile"):**
> Integer-valued fields are encoded in the **smallest** msgpack integer type that holds them; a value in `0..2³²−1` uses `fixint`/`uint8`/`uint16`/`uint32`, never `int64`/`uint64`. Integer values outside signed-32/unsigned-32 range are encoded as IEEE-754 `float64` (`0xcb`), **not** as 64-bit integers. The reference decoder maps only the 64-bit integer types (`0xcf`/`0xd3`) to a big-integer; every narrower integer decodes to a native number, and receivers type-check native-number for `t`, `v`, `epoch`, and JWT `ts` and compare small ints by value. A port **must** reproduce these width choices or its frames will be dropped as type-mismatched. In particular JWT `ts` is transmitted as `float64`. Byte-string fields (annotated `bin`) **must** use the msgpack `bin` family and text fields (annotated `string`) the `str` family; cross-encoding fails the receiver's type guards.

---

### P0-2. The protocol has **no self-framing**; frames are transport *messages*, but the spec advertises "duplex socket" (a byte stream)

**Section:** Goals and non-goals (#4) / Frame format.
**What's missing:** `frame := tag || payload` carries no length prefix. Decryption consumes `frame[25:]` = "the rest of the buffer"; hello decodes `data.subarray(1)` as exactly one msgpack document. The implementation relies entirely on the channel delivering one whole frame per `receive` callback (`src/channels/ws.ts` — WebSocket is message-oriented; every shipped adapter is WebSocket). Goal #4 lists "duplex socket" as a supported byte-pipe, but a raw TCP socket is a byte stream with no message boundaries — a porter wiring frames onto a stream with no length prefix will corrupt/merge frames.

**Proposed wording (Frame format, first paragraph):**
> Every frame is exactly one transport message. The protocol is **not** self-delimiting: it defines no length prefix and assumes the transport preserves message boundaries (WebSocket, datagram, `MessagePort`). Over a stream transport (raw TCP/TLS) the adapter **must** add its own framing (e.g. a length prefix) and hand each reassembled frame to the core as a single unit; that framing is out of protocol scope and not covered by the test vectors.

---

### P0-3. Low-order X25519 public-key rejection is security-critical but appears **only in the checklist**, not in the normative Handshake/Crypto body

**Section:** Handshake step 4 (server ECDH) / Crypto.
**What the code does:** relies on `@noble/curves` `getSharedSecret` throwing on RFC 7748 §6.1 low-order points; `test/security/f002-low-order-x25519-pubkey.test.ts` pins that dependency contract. There is **no explicit rejection in `src/`** — it is entirely implicit in the dependency.
**Risk:** In asymmetric-only mode (salt = `EMPTY_SECRET`), a port built on a library that returns an all-zero shared secret for a low-order pub lets an active MITM force a deterministic `session_key = HKDF(zeros, zeros, …)` and decrypt the session. The requirement exists in the checklist but a porter implementing from the Handshake section will miss it, and the reference itself has no in-tree guard to copy.

**Proposed wording (Handshake step 4, append):**
> Before or during the ECDH, the implementation **must** reject RFC 7748 §6.1 low-order `pub` values (this is normative, not implementation guidance). Either the X25519 primitive rejects them (as `@noble/curves` does) or the handshake rejects `pub` explicitly before `getSharedSecret`. Accepting them in asymmetric-only mode yields an all-zero shared secret and a fully-predictable session key.

---

## P1 — port would diverge observably

### P1-1. A well-formed request naming an **unknown procedure returns a `NOT_FOUND` error response**, not a silent drop

**Section:** RPC message format / Failure modes.
**Code:** `src/server.ts:850` — `if (!(procedure in frozen)) throw new RPCError("NOT_FOUND", …)`, which becomes an encrypted `{t:2, ok:false, e:{c:"NOT_FOUND"}}` reply. The spec's silent-drop rule (`§RPC`, "wrong `t`, missing/empty `id`, missing/empty `p` … must be dropped silently") covers only malformed **envelopes**; it never states that a valid envelope with an unknown `p` gets an error reply. A porter could reasonably silent-drop unknown procedures, diverging from the reference (client sees timeout instead of `RemoteRPCError("NOT_FOUND")`).

**Proposed wording (RPC message format, after the drop rules):**
> A **well-formed** request (`t:1`, valid `id`, non-empty string `p`) whose `p` does not name a procedure in the router is **not** silently dropped: the server returns a normal failure response with code `NOT_FOUND`. Silent drop applies only to malformed envelopes (wrong `t`, absent/oversized `id`, missing/empty `p`) and to frames that fail AEAD.

---

### P1-2. The reference **error-code vocabulary** that crosses the wire is not enumerated

**Section:** RPC message format (`e.c`).
**Code:** the server emits `INPUT_VALIDATION`, `OUTPUT_VALIDATION`, `MIDDLEWARE`, `NOT_FOUND`, `INVALID_DATA`, `INTERNAL` (`src/server.ts:149,166,185,850,893`, plus `sanitize` `INVALID_DATA`). The spec lists only `INPUT_VALIDATION`, `NOT_FOUND`, `UNAUTHORIZED` as examples and says codes are "any application-defined string." For behavior-compatible error handling a port's server should emit the same protocol-level codes and a port's client should expect them.

**Proposed wording (RPC message format, add a note):**
> The reference server emits these protocol-level codes (in addition to application codes): `INPUT_VALIDATION`, `OUTPUT_VALIDATION`, `MIDDLEWARE`, `NOT_FOUND`, `INVALID_DATA`, `INTERNAL`. A behavior-compatible port **should** use the same codes for the same conditions. The error `d` payload is implementation-defined (the reference puts the schema library's flattened issues there) and clients **must not** depend on its shape.

---

### P1-3. Candidate **confirmation-timer duration is the *remaining* handshake budget**, not a fresh `HANDSHAKE_TIMEOUT`

**Section:** Handshake step 2.11 / Constant reference (`HANDSHAKE_TIMEOUT_MS`).
**Code:** `src/server.ts:666,697` — `remainingBudget = max(1, hsTimeout − elapsed)`; the confirmation timer is armed for that remainder, so hello→first-confirming-frame is bounded by **one** `hsTimeout` total. The spec only says "Arm a confirmation timer for the candidate" and the constant table describes `HANDSHAKE_TIMEOUT_MS` as "timeout for completing the handshake," which a porter would read as a fresh full-length timer → candidate lives observably longer (up to ~2× under slow auth).

**Proposed wording (Handshake step 2.11):**
> The confirmation timer is armed for the **remaining** budget (`handshakeTimeout` minus the time already spent validating the attempt), so the total hello→first-confirming-frame window for one attempt is bounded by a single `handshakeTimeout`, not two.

---

### P1-4. `bin` vs `str` cross-encoding failure isn't stated as a hard requirement

**Section:** Frame format / RPC message format.
**Code:** `isPlainBytes` (`src/common.ts`) rejects anything that isn't an exact `Uint8Array`; `pub/nonce/proof/auth/sig/th` sent as msgpack `str` would decode to a JS string and be rejected. The schema annotations (`bin` / `string`) imply this, but there is no explicit "never interchange" statement. Folded into P0-1's proposed wording; keeping it here for the RPC-envelope fields (`id`, `p` must be `str`; there are no `bin` fields in the RPC envelope except inside app `i`/`d`).

---

### P1-5. Client drops a valid-but-mismatched reply epoch silently, but **fails the handshake on a malformed reply epoch** — spec only mentions the equality drop

**Section:** Handshake step 3.3.
**Code:** `src/client.ts` reply path validates `replyEpoch` is a uint32 and **throws → `failHandshake`** on a non-integer/out-of-range value, *before* the `replyEpoch !== currentEpoch` silent-drop. Spec step 3.3 says only "Silently drop if `reply.epoch !== this_epoch`." A porter implementing pure equality would silent-drop a malformed epoch (keep handshaking until timeout) instead of failing fast (reset + surface). Minor but observable.

**Proposed wording (step 3.3):**
> A reply whose `epoch` is not a valid uint32 fails the handshake attempt; a valid `epoch` that does not equal `this_epoch` is dropped silently (stale reply, keep waiting).

---

### P1-6. Client-side low-order rejection / secret-length symmetry

**Section:** Handshake step 3.5–3.6.
The client also runs `getSharedSecret(priv, serverPub)` (throws on low-order server pub → `failHandshake`) and requires `secretBytes.length ≥ KEY_LEN`. The spec covers the server's `secret` check (step 5) but states the client's only as "Validate ≥ KEY_LEN bytes" (step 6) and never says the client rejects a low-order **server** pub. Add the same low-order note (P0-3) to step 3.5, and state that the **full** secret byte-string (not truncated to 32) is the HKDF salt on both sides, so both peers must return byte-identical secrets of identical length.

---

## P2 — editorial / informative

- **NaCl `secretbox` tag position** (Poly1305 layout inside `ciphertext_with_tag`) is only implied by the frame vector. One sentence in Encryption ("the AEAD output layout is NaCl `secretbox`: 16-byte Poly1305 tag as produced by XSalsa20-Poly1305, matched by the test vector") would help porters not using a secretbox-shaped library.
- **JWT `maxAge` default = 30 000 ms** (`src/auth/server.ts`) is server-side policy not stated in the `jwt` profile; note it for helper-porters.
- **Empty/zero-length inbound frame** is dropped (`raw.length === 0`, `src/server.ts` / `src/client.ts`); not mentioned in Failure modes.
- **Context-factory throw** → `INTERNAL` error response with no leak (`src/server.ts` handler try/catch); worth one line in Authorization data flow.
- **`ts` is compared as integer milliseconds** but transmitted as float64 (P0-1) — a port's verifier must accept a float and treat it as ms; note under profile `jwt`.
- **msgpack map keys are `str`** (all field names). Standard, but the vector note ("map-key order follows encoding order") could add "keys are `str`, values per the schema."
- **ECDSA `sig`** length not fixed at 64 (`src/auth/server.ts` checks non-empty only); WebCrypto verify enforces raw r‖s implicitly. Fine, but a note that a wrong-length `sig` fails at verification (not at length-guard) avoids porter confusion.

---

## Normativity audit — sections mixing wire-normative and TS-local detail

1. **§Failure handling (no auto-retry).** Mixes a wire/security-normative rule (reset trigger set = exactly `RPCAbortedError("TIMEOUT")`; no resend; observable reset behavior) with **TS-local machinery**: the 250 ms `SEND_RETRY_MS` tick, `sendTimeout` default 3 000, the outbound-queue head-of-line policy, optimistic async-send accounting, `RPCError` vs `RPCAbortedError` class split. The *sent-boundary semantics* and *reset trigger set* are normative for "same security decisions"; the tick interval, queue data structure, and error-class taxonomy are implementation guidance. **Split into "Normative session-reset rules (MUST)" and "Reference outbound-queue behavior (informative)."**

2. **§State machines → Client.** The `idle/handshaking/ready/closed` states and the epoch-coalescing of concurrent resets are behavior-normative; the shared `handshakePromise`, `raceAbort`, and Proxy API are TS-local. Label the epoch/reset semantics MUST, the promise/proxy mechanics informative.

3. **§Handshake step 2 (server).** Interleaves wire-normative ordering (auth before ECDH; candidate install under a synchronous epoch-guarded block; reply-send-failure drops candidate) with TS event-loop specifics (microtask-vs-macrotask deadline reasoning, `attemptTimer`/`attemptDeadline` twin, `await`-guard idiom). The **absolute wall-clock deadline check after every suspension** is a normative *requirement* (a flag-only guard is exploitable), but the *reason* (JS microtask ordering) is language-specific — restate the requirement language-neutrally ("after every operation that may suspend, before writing any session state, re-check: still the current attempt, not destroyed, within the wall-clock deadline") and move the JS rationale to a note.

4. **§Constant reference.** `HANDSHAKE_TIMEOUT_MS`, `RPC_TIMEOUT_MS`, `SEND_TIMEOUT_MS`, `MAX_PENDING` are **defaults for local timers/limits**, not wire constants — mixed in the same table as truly wire-normative values (`TAG_*`, `NONCE_LEN`, `KEY_LEN`, magic strings, `MAX_HELLO_BYTES`). Add a column or split: "wire-normative (both peers must agree)" vs "local policy default (implementation may differ; affects observable behavior only)."

5. **§Sanitization.** Rules 3–4 (`Object.prototype`/`null` prototype check; `__proto__`/`constructor`/`prototype` stripping; `Object.create(null)` rebuild) are **JS-specific prototype-pollution defenses**. The section already flags "A port to a language without prototype pollution still has to…" — good — but the three language-neutral MUSTs (reject unknown ext types incl. Timestamp; depth cap 32; reject shape mismatch) should be lifted to the top as the normative core, with the prototype rules explicitly labeled "JS-specific realization."

6. **§Auth payload profiles.** Correctly labels itself "normative when a shipped helper is used." Keep — but note that `ed25519`/`ecdsa` bind to **raw transcript bytes** while `jwt` binds to `SHA-256(transcript)`; that per-profile difference is wire-normative and easy to miss.
