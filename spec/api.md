# API reference

Reference for every exported symbol. End-to-end walkthrough lives in [Getting Started](getting-started.md), threat model and crypto in [Security](security.md), wire format in [Protocol](protocol.md).

## Import paths

```typescript
// Root entry: everything
import {
  chain, server, client,
  RPCError, RemoteRPCError,
  deriveSessionSecret,
} from "@dotex/saferpc";

// Subpaths for tree-shaking
import { ... } from "@dotex/saferpc/common";
import { ... } from "@dotex/saferpc/server";
import { ... } from "@dotex/saferpc/client";
```

---

## `chain()`

```typescript
function chain(): Chain;
```

Returns a procedure builder. Every method is immutable and chainable. `.handler()` terminates the chain and returns a frozen `Procedure`.

```typescript
interface Chain<TCtx = {}, TIn = unknown, TOut = unknown> {
  use<E>(fn: (opts: {
    ctx: TCtx;
    input: TIn;
    next: (extra?: E) => Promise<unknown>;
  }) => Promise<unknown>): Chain<TCtx & E, TIn, TOut>;

  input<S extends ZodType>(schema: S): Chain<TCtx, z.output<S>, TOut>;
  output<S extends ZodType>(schema: S): Chain<TCtx, TIn, z.output<S>>;

  handler(fn: (opts: { ctx: TCtx; input: TIn }) => Promise<TOut>): Procedure;
}
```

### Method semantics

| Method | Effect | Notes |
|--------|--------|-------|
| `.use(fn)` | Adds middleware that can extend context | `fn` must call `next()` exactly once. `next(extra)` merges `extra` into ctx. |
| `.input(schema)` | Validates incoming input with Zod | On failure throws `RPCError("INPUT_VALIDATION", ...)`. |
| `.output(schema)` | Validates handler output with Zod | On failure throws `RPCError("OUTPUT_VALIDATION", ...)`. Runs *after* handler. |
| `.handler(fn)` | Terminates the chain | Returns a frozen `Procedure`. |

`schema` is anything with a `.safeParse()` method (a Zod schema in practice).

### `Procedure`

```typescript
interface Procedure {
  readonly _steps: ReadonlyArray<Step>;
  readonly _handler: HandlerFn;
}

type Router = Record<string, Procedure>;
```

Treat `Procedure` as opaque. The fields are exposed only so `server()` can introspect them.

---

## `server(router, channel, options)`

```typescript
function server<T extends Router>(
  router: T,
  channel: Channel,
  options: ServerOptions,
): { destroy: () => void };
```

Subscribes to `channel` and serves the router. Returns synchronously.

### `ServerOptions`

| Field | Type | Default | Required |
|-------|------|---------|----------|
| `auth` | `AuthOptions` | — | ✅ |
| `context` | `(ctx: { auth?: Ctx }) => Ctx \| Promise<Ctx>` | — | — |
| `handshakeTimeout` | `number` (ms) | `5000` | — |
| `maxMessageBytes` | `number` | `1_048_576` | — |
| `onError` | `(err: unknown) => void` | — | — |

`context` runs per request. The `auth` argument carries whatever `auth.verify` returned for the current session. When `context` is omitted, the request context falls back to the verified auth data (or `{}` if none).

`onError` fires on handshake failures and non-fatal internal errors. The server does **not** destroy itself on a failed handshake — it resets and accepts the next hello.

### `AuthOptions`

```typescript
interface AuthOptions {
  secret?: () => Uint8Array | Promise<Uint8Array>;
  sign?: (transcript: Uint8Array) => Uint8Array | Promise<Uint8Array>;
  verify?: (
    proof: Uint8Array,
    transcript: Uint8Array,
  ) => VerifyResult | Promise<VerifyResult>;
}

type VerifyResult = { auth?: Ctx } | void;
```

Set at least one of `secret` or asymmetric (`sign` / `verify`). Configuring neither throws a `TypeError` at construction.

| Field | Called | Notes |
|-------|--------|-------|
| `secret` | Per handshake attempt | Returned bytes must be ≥ 32. Empty secret used when `secret` is omitted but asymmetric auth is configured. |
| `sign` | Per handshake attempt, if set | Signature payload, ≤ 32 KiB. |
| `verify` | Per handshake attempt, if set | Throw to reject. Returned `auth` is bound to the resulting session. |

Returned `auth` data is sanitized (poison keys stripped) before reaching `context`.

### Server lifecycle

```
waiting → pending → ready
   ↑         |        |
   └─────────┴────────┘   (timeout / new hello / explicit destroy)
```

- `waiting`: accepting hellos, no session.
- `pending`: hello processed, reply sent. Transitions to `ready` only on successful decrypt of the first `TAG_MSG`.
- `ready`: session confirmed. Routes RPCs.
- A new hello in any state resets the server and starts over.
- `destroy()` is permanent: zeros all keys, unsubscribes from the channel, drops references.

---

## `client<T>(channel, options)`

```typescript
function client<T extends Router>(
  channel: Channel,
  options: ClientOptions,
): { api: Client<T>; destroy: () => void };
```

Returns synchronously. The handshake stays lazy: it starts on the first `api` call.

### `ClientOptions`

| Field | Type | Default | Required |
|-------|------|---------|----------|
| `auth` | `AuthOptions` | — | ✅ |
| `timeout` | `number` (ms) | `10_000` | — |
| `maxPending` | `number` | `256` | — |
| `handshakeTimeout` | `number` (ms) | `5000` | — |
| `maxMessageBytes` | `number` | `1_048_576` | — |

`maxPending` caps concurrent in-flight calls. Past the cap, calls reject with `RPCError("CLIENT", "Too many pending requests")`.

`timeout` is per call. On timeout the client throws `RPCError("TIMEOUT", "Timed out: <procedure>")` and triggers an auto-retry.

### `Client<T>`

```typescript
type Client<T extends Router> = {
  [K in keyof T & string]: (input: unknown) => Promise<unknown>;
};
```

The proxy types check against `T`. Use `typeof router` from the server side as the type argument to get full procedure inference.

### Client lifecycle

```
idle → handshaking → ready
  ↑         |          |
  └─────────┴──────────┘   (hs timeout / call timeout / destroy)
```

- `idle`: no session. Next call triggers `startHandshake()`.
- `handshaking`: hello sent. All concurrent calls await the same handshake promise.
- `ready`: session key established. Calls go through.
- `closed`: `destroy()` was called. All calls reject; no further work.

---

## Auto-retry

A call that fails on a `ready` session with a local `TIMEOUT` or send error triggers a single retry: the client zeros its session key, returns to `idle`, runs a fresh handshake, and resends the request **exactly once**. `RemoteRPCError` (server returned an error) is **not** retried — the server is alive and answered. Concurrent failures share one re-handshake via an epoch counter, so there are no retry storms. Full state-machine and wire-level semantics in [Protocol § Auto-retry semantics](protocol.md#auto-retry-semantics).

## Replay within a session

Per-message AEAD nonces are random, not counter-derived. An attacker who can inject into a live channel can replay a captured ciphertext and the receiver will execute it again. For non-idempotent procedures, add an idempotency key inside `input`, or keep a request-ID set on the server keyed by the verified principal. Full discussion in [Security § Replay within a session](security.md#replay-within-a-session).

---

## `Channel`

```typescript
interface Channel {
  send(data: Uint8Array): void | Promise<void>;
  receive(cb: (data: Uint8Array) => void): () => void;
}
```

The only transport contract. `receive` returns an unsubscribe function. The channel must:

- Transmit bytes intact (no silent corruption)
- Deliver each call to `cb` once, in any order
- Allow `send` and `receive` to run concurrently

Dropping, duplicating, or reordering messages is allowed — Safe RPC will time out and retry. Ready-made adapters live in [Integrations](integrations.md).

> Within a single session the protocol assumes the `TAG_HELLO` reply arrives before any `TAG_MSG` sent under the resulting session key. Transports that can reorder *across* the hello/reply boundary (multi-path links, fan-out buses) will hang the handshake until the timeout fires. `TAG_MSG`-to-`TAG_MSG` reordering stays safe: every encrypted frame is independently authenticated and the protocol imposes no ordering on application messages.

---

## Errors

```typescript
class RPCError extends Error {
  readonly code: string;
  readonly data: unknown;
  constructor(code: string, message: string, data?: unknown);
}

class RemoteRPCError extends RPCError {}
```

- `RPCError` is thrown for **local** failures: timeout, session destroyed, handshake failure, validation failure, channel error.
- `RemoteRPCError` is thrown when the remote peer's handler returned an error. The `code`, `message`, and `data` come from the remote side and are **untrusted strings** — sanitize before logging at warn/error level, or before showing them to a user.

### Standard local error codes

| Code | Thrown when |
|------|-------------|
| `TIMEOUT` | RPC call exceeded `timeout` ms |
| `SESSION` | `destroy()` called or session closed |
| `CLIENT` | Client-side guardrail tripped (e.g., `maxPending` exceeded) |
| `HANDSHAKE` | Handshake failed or timed out, auth payload malformed |
| `INPUT_VALIDATION` | `.input(schema)` rejected the input |
| `OUTPUT_VALIDATION` | `.output(schema)` rejected the handler output |
| `INVALID_DATA` | Wire-level data rejected by `sanitize()` |
| `INTERNAL` | Defensive: should not be reachable |
| `MIDDLEWARE` | Middleware misuse (`next()` called twice, bad `extra` arg) |

Handlers may throw `RPCError(...)` with any code; those codes surface as `RemoteRPCError.code` on the client.

### Pattern

```typescript
try {
  await api.getProfile({ id: "u_1" });
} catch (err) {
  if (err instanceof RemoteRPCError) {
    // handler threw on the other side: err.code, err.message, err.data
  } else if (err instanceof RPCError) {
    // local failure: TIMEOUT, SESSION, etc.
  } else {
    throw err;
  }
}
```

---

## Middleware and context

Middleware extends the context. Signature is `({ ctx, input, next })`, and `next(extra?)` must be called exactly once.

```typescript
const d = chain();

const authed = d.use(async ({ ctx, input, next }) => {
  const user = await getUser(ctx.token);
  if (!user) throw new RPCError("UNAUTHORIZED", "Bad token");
  return next({ user }); // merges into ctx
});

const router = {
  getProfile: authed
    .input(z.object({ id: z.string() }))
    .handler(async ({ ctx, input }) => db.getProfile(input.id)),
};

server(router, channel, {
  auth,
  context: ({ auth: verified }) => ({
    token: getCurrentToken(),
    userId: verified?.userId,
  }),
});
```

Calling `next()` twice in the same middleware throws `RPCError("MIDDLEWARE", ...)`. So does passing a non-object `extra`.

The `context` factory runs **per request**, after auth verification, and receives `{ auth }` carrying the data returned by `auth.verify` for that session.

---

## `deriveSessionSecret`

```typescript
function deriveSessionSecret(sessionId: string, secret: Uint8Array): Uint8Array;
```

HKDF-SHA-256 over `secret` with `sessionId` as salt and the fixed info string `"saferpc-session-v1"`. Returns 32 bytes.

Throws `TypeError` if `sessionId` is empty or `secret` is shorter than 32 bytes.

Use it to bind each handshake to a session identifier instead of relying on a single static secret.

---

## Built-in auth helpers

Every helper returns a partial `AuthOptions` you spread into the `auth` block. Each one binds its proof to the canonical handshake transcript, so a captured payload cannot be replayed into a new handshake.

### Client-side

```typescript
import {
  createJWTClientAuth,
  createEd25519ClientAuth,
  createECDSAClientAuth,
  generateEd25519Keypair,
  generateECDSAKeypair,
} from "@dotex/saferpc";
```

| Helper | Returns | Notes |
|--------|---------|-------|
| `createJWTClientAuth({ getToken })` | `{ sign }` | Embeds `{ jwt, ts, th }` where `th` is `SHA-256(transcript)`. |
| `createEd25519ClientAuth({ privateKey, deviceId })` | `{ sign }` | Signs the transcript via `@noble/curves` (no WebCrypto needed). |
| `createECDSAClientAuth({ privateKey, identifier })` | `{ sign }` | WebCrypto P-256, `privateKey` is a `CryptoKey`. |
| `generateEd25519Keypair()` | `{ privateKey: Uint8Array, publicKey: Uint8Array }` | Pure JS, works everywhere. |
| `generateECDSAKeypair()` | `{ privateKey: CryptoKey, publicKey: CryptoKey }` | Non-extractable. |

### Server-side

```typescript
import {
  createJWTServerAuth,
  createEd25519ServerAuth,
  createECDSAServerAuth,
  createCertificateServerAuth,
  createMultifactorServerAuth,
} from "@dotex/saferpc";
```

| Helper | Use |
|--------|-----|
| `createJWTServerAuth({ verifyToken, maxAge? })` | Verifies JWT + timestamp (symmetric skew check) + transcript digest. Returns the `verifyToken` result as `auth`. |
| `createEd25519ServerAuth({ getPublicKey, validateDevice? })` | Verifies Ed25519 signature against a device's 32-byte public key. |
| `createECDSAServerAuth({ getPublicKey, validateEntity? })` | Verifies ECDSA P-256 signature via WebCrypto. |
| `createCertificateServerAuth({ verifyCertificate, validateSubject? })` | Verifies a presented certificate chain + ECDSA P-256 signature. |
| `createMultifactorServerAuth({ primary, secondary, combineAuth? })` | Composes two verifiers; both must pass. |

Auth payloads decode through the hardened msgpack codec: extension types rejected, prototype-pollution keys stripped, recursion depth capped. Returned `auth` data is sanitized before reaching `context`.

---

## Constants

```typescript
import {
  NONCE_LEN,        // 24: XSalsa20-Poly1305 message nonce
  KEY_LEN,          // 32: symmetric key / X25519 key / hello nonce
  TAG_HELLO,        // 0x00
  TAG_MSG,          // 0x01
  MAX_MSG_BYTES,    // 1_048_576
  MAX_HELLO_BYTES,  // 65_536
  MAX_AUTH_BYTES,   // 32_768
  MAX_DEPTH,        // 32: max `sanitize()` recursion depth
  HANDSHAKE_TIMEOUT,// 5000
  EMPTY_SECRET,     // Uint8Array(32) of zeros: internal "no secret" sentinel
  // Type guards
  isPlainBytes,     // exact-prototype Uint8Array check for wire data
  isEmptySecret,    // constant-time check for the 32-zero secret sentinel
} from "@dotex/saferpc";
```

Exported for adapter authors. Application code rarely needs them.

---

## Cleanup

Call `destroy()` when you are done with a session.

```typescript
const { destroy: destroyServer } = server(router, channel, { auth });
const { api, destroy: destroyClient } = client<typeof router>(channel, { auth });

// later
destroyClient(); // rejects pending calls, zeros keys, unsubscribes
destroyServer(); // zeros keys, unsubscribes
```

After `destroy()`:

- Further `api.foo()` calls reject with `RPCError("SESSION", "Session destroyed")`.
- Incoming messages are ignored.
- Calling `destroy()` again is a no-op.

---

## Edge runtime compatibility

Both `server()` and `client()` return **synchronously**, with no top-level `await`. Dependencies are pure JavaScript. Compatible with:

- Node.js 18+
- Modern browsers
- Service Workers
- React Native
- Vercel Edge Functions
- Cloudflare Workers / Durable Objects
- Deno Deploy
