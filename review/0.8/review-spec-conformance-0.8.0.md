# SafeRPC 0.8.0 — Specification vs Implementation Review

**Target release:** 0.8.0  
**Review date:** 2026-07-14  
**Scope:** `src/`, `spec/*.md`, root implementation specs, README, package scripts, and tests.  
**Method:** direct code/spec comparison, full test and typecheck runs, plus focused runtime probes for auth payload decoding. No subagents were used.

## Verdict

The handshake, key derivation, make-before-break replacement, replay window, auth profile fields, and known-answer vectors closely match the normative protocol. Full conformance does not hold, however. Two contract-level mismatches remain:

1. shipped auth verifiers bypass the sanitization rules required by the protocol;
2. async `Channel.send()` crosses the implementation's sent boundary before the Promise resolves, contrary to the documented retry-safety contract.

The remaining findings are API, adapter-example, error-shape, and documentation drift.

---

## 1. Auth helper payloads bypass mandatory sanitization

**Priority:** high  
**Code:** `src/auth/server.ts:25-42`, `src/common.ts:145-174`  
**Specification:** `spec/protocol.md:475-483`, `spec/api.md:469`

`decodeAuthPayload()` calls `mpDecode()` but never passes the decoded value through `sanitize()`:

```ts
function decodeAuthPayload(proof: Uint8Array): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = mpDecode(proof);
  } catch {
    throw new RPCError("UNAUTHORIZED", "Malformed auth payload");
  }
  // ...
  return parsed as Record<string, unknown>;
}
```

This matters because `mpDecode()` alone does not enforce the complete hardened-data policy. Unknown extension types decode to `ExtData`; `sanitize()` is the layer that rejects them, strips poison keys, rejects host objects, and enforces the recursion-depth limit.

The API explicitly claims:

> Auth payloads decode through the hardened msgpack codec: extension types rejected, prototype-pollution keys stripped, recursion depth capped.

Focused probes confirmed that `createJWTServerAuth()` accepts both:

- a valid profile containing an unknown msgpack extension in an ignored extra field;
- a valid profile containing an ignored object nested 40 levels deep.

Both payloads should be rejected under the normative sanitization rules. The same common decoder is used by the JWT, Ed25519, and ECDSA server helpers.

**Impact:** a strict port following the protocol rejects payloads that the TypeScript reference accepts. The 32 KiB auth-payload cap bounds total allocation, but the documented type-confusion and depth defenses are not actually applied to helper payloads.

**Required alignment:** either sanitize the full decoded helper payload before field access, or narrow the specification and API claim. The former matches the existing security model.

---

## 2. Async sends cross the sent boundary before Promise resolution

**Priority:** high  
**Code:** `src/client.ts:263-267`, `src/client.ts:436-442`, `src/client.ts:1043-1046`  
**Specification:** `spec/protocol.md:444-453`, `spec-channel-lifecycle.md:60-69`

The normative sent boundary is defined as:

- synchronous adapter: `channel.send(frame)` returns without throwing;
- asynchronous adapter: the returned Promise resolves.

Before that boundary, terminal events are specified to produce a plain local `RPCError`; after it, they produce `RPCAbortedError` because the outcome is unknown.

The implementation deliberately marks an async send as sent immediately after receiving its Promise:

```ts
const sent = channel.send(encrypted) as unknown;
if (isThenable(sent)) {
  entry.sent = true;
  sent.catch(/* rollback on rejection */);
}
```

The queued flush path does the same before the Promise settles.

Therefore, while an async send Promise is still pending:

- abort produces `RPCAbortedError("ABORTED")`, not plain `RPCError("ABORTED")`;
- global timeout produces `RPCAbortedError("TIMEOUT")`, not plain `RPCError("CHANNEL")`;
- that timeout resets the session, although the specification says a pre-boundary failure must not reset it;
- `sendTimeout` does not govern the pending send because the frame has already been removed from the outbound queue.

The implementation's conservative choice is defensible: a pending Promise may later resolve and deliver the frame, so reporting UNKNOWN is safer than falsely reporting “never sent.” It nevertheless contradicts the public contract, which says the core still owns the only copy until Promise resolution.

**Required alignment:** choose one model and document it consistently. If optimistic accounting remains, the API and protocol must explicitly define invocation/Promise handoff—not resolution—as the conservative boundary for async adapters.

---

## 3. Documented adapters violate the send-or-throw contract

**Priority:** medium  
**Specification:** `spec/getting-started.md:99-110`, `spec/integrations.md:81-89`, `spec/integrations.md:303-339`, `spec/integrations.md:450-465`

The adapter contract says an adapter must throw or reject when it cannot hand a frame to a live transport immediately. It also forbids adapter-owned queues because they hide the sent boundary from the client core.

Several documented adapters do the opposite.

### Getting Started WebSocket

```ts
const ready = new Promise<void>((resolve) =>
  ws.addEventListener("open", () => resolve(), { once: true }),
);

async send(data) {
  await ready;
  ws.send(data);
}
```

This parks frames inside the adapter until the initial socket opens. It also does not check `readyState` after closure, reintroducing the browser behavior where `WebSocket.send()` on a closed socket may silently drop data.

### WebRTC DataChannel

```ts
async send(data) {
  if (dc.readyState !== "open") await waitDCOpen(dc);
  dc.send(data);
}
```

The text explicitly says sends are parked until open, directly contradicting the no-queue rule later in the same document.

### TCP

The example calls `socket.write()` immediately after `net.connect()`. Node may queue that write internally before the socket connects, while the SafeRPC core treats the synchronous return as crossing the sent boundary.

**Impact:** users copying these examples do not get the retry classification, stale-frame revocation, or queue ownership promised by the core design.

**Required alignment:** examples for mortal transports should check liveness and throw/reject while unavailable, or the contract must explicitly allow adapter buffering and give up the claimed definite sent boundary. The shipped `wsChannel` already implements the current contract correctly and should be the reference used by the quick start.

---

## 4. A route named `then` is typed but cannot be called

**Priority:** medium  
**Code:** `src/client.ts:1082-1086`  
**Specification:** `spec/api.md:235-245`

`Client<T>` promises a callable method for every string route key, and `rpc.router()` does not reserve or reject any name. The client proxy, however, always hides `then` to avoid becoming a thenable:

```ts
get(_target, prop) {
  if (typeof prop !== "string") return undefined;
  if (prop === "then") return undefined;
  // ...
}
```

A router containing `{ then: procedure }` therefore compiles as `api.then(...)`, while `api.then` is `undefined` at runtime. The wire protocol and server accept the procedure name; only the generated client makes it unreachable.

**Required alignment:** reserve and reject `then` when creating a router, exclude it from `Client<T>`, or expose procedures through a lookup API that does not conflict with Promise assimilation.

---

## 5. The client accepts malformed response discriminators

**Priority:** medium  
**Code:** `src/client.ts:840-868`  
**Specification:** `spec/protocol.md:347-381`

The protocol defines exactly two response forms:

- success: `ok: true`;
- failure: `ok: false`.

Unexpected field types are specified as malformed envelopes. The client only checks for `true`; every other value enters the failure branch:

```ts
if (msg["ok"] === true) {
  entry.resolve(msg["d"]);
} else {
  // treated as a remote failure
}
```

Responses with an absent `ok`, `ok: null`, `ok: 1`, or `ok: "false"` settle the pending call instead of being silently dropped. The pending entry is removed before this distinction is made.

**Impact:** the reference client and a strict port produce observably different results for malformed authenticated responses: immediate `RemoteRPCError` versus timeout/silent drop.

**Required alignment:** require `ok === true` or `ok === false`; drop any other value before removing the pending entry.

---

## 6. Handshake reply send errors use `data`, not `cause`

**Priority:** low  
**Code:** `src/server.ts:712-724`  
**Specification:** `spec/protocol.md:198`, `spec/assessment.md:84`

The protocol and assessment say the single handshake failure preserves the transport error as its cause. The implementation passes the object as the third `RPCError` argument:

```ts
throw new RPCError("HANDSHAKE", "Handshake reply send failed", {
  cause: sendErr instanceof Error ? sendErr.message : String(sendErr),
});
```

The third argument is `data`; constructor options are the fourth argument. The resulting error has:

```ts
err.cause === undefined;
err.data.cause === "...string...";
```

It also discards the original error object.

**Required alignment:** pass `{ cause: sendErr }` as the fourth argument, or document the current `data.cause` shape instead.

---

## 7. Security auth-order prose describes the pre-make-before-break server

**Priority:** low  
**Specification:** `spec/security.md:159-163`  
**Code:** `src/server.ts:742-752`, protocol handshake steps 3-10

The security page says:

1. all auth runs before any session key is materialized;
2. an auth failure resets the server to `waiting`.

Neither statement is generally true:

- server-side `verify` runs before ECDH, but server-side `sign` runs after session-key derivation and proof construction;
- a failed attempt does not reset an established live session. Under make-before-break it discards only the attempt and leaves the server ready on the existing session.

The actual security property still holds: failed verification runs before ECDH, and a failed signing step publishes no candidate. The prose should state those narrower guarantees.

---

## 8. Option validation is only partially documented

**Priority:** low  
**Code:** `src/client.ts:183-222`, `src/server.ts:273-298`  
**Specification:** `spec/api.md:138-151`, `spec/api.md:216-233`

Runtime validation includes:

- client `timeout`: finite and `> 0`;
- client `sendTimeout`: finite and `>= 0`;
- client/server `handshakeTimeout`: finite and `>= 100 ms`;
- client/server `maxMessageBytes`: positive integer;
- client `maxPending`: positive integer;
- server `replayWindow`: non-negative integer.

The API documents only part of this contract and does not mention the 100 ms handshake minimum. Calls that look valid from the option tables can therefore throw synchronously at construction.

The client-options paragraph also discusses auth-helper `maxAge`, which is not a `ClientOptions` field.

---

## 9. Remaining documentation and release drift

**Priority:** low

### `sendTimeout` default

`spec-channel-lifecycle.md:170` says the default is 10 seconds. The implementation, public API, protocol, and assessment use 3 seconds.

### Security assessment test count

`spec/assessment.md:10` records 265 tests. The current suite contains 268 passing tests. This may be retained as a dated historical measurement, but it is not the current count.

### Release command

README says `npm version patch` runs a `postversion` hook that publishes and pushes. `package.json` has no `postversion` script. It has:

- `version`: sync and stage `jsr.json`;
- `prepublishOnly`: lint, test, build;
- `postpublish`: push tags.

Running `npm version patch` alone therefore does not publish the package or push the tag as documented.

---

## Validation results

- Full test suite: **268/268 passed**.
- Typecheck: **passed**.
- Lint: **failed** due to formatting drift in:
  - `src/server.ts`
  - `test/unit/auth-server.test.ts`
  - `test/unit/vectors.test.ts`
- Focused auth probes:
  - unknown extension in an ignored helper-profile field: **accepted**;
  - ignored helper-profile field nested 40 levels deep: **accepted**.
- Working tree was not modified during the review itself. The pre-existing untracked `auth-api-review-question.md` remained untouched.

## Conformant areas checked

No mismatch was found in:

- X25519/HKDF/HMAC formulas and byte ordering;
- transcript magic, field order, and epoch encoding;
- low-order X25519 rejection through `@noble/curves`;
- make-before-break candidate installation and promotion;
- promotion on successful AEAD before inner-payload validation;
- replay-window insertion, FIFO eviction, and clearing on promotion;
- no-auto-resend and reset-on-sent-timeout policy for synchronous transports;
- input omission for `undefined`;
- built-in auth profile field names, versions, signature inputs, and published vectors;
- constant-time proof and JWT transcript-digest comparisons;
- handler/internal-error detail suppression;
- ESM/CJS/auth/channels package export paths.
