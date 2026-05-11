# API Reference

Strict reference for every exported symbol. For an end-to-end walkthrough see [Getting Started](getting-started.md). For threat model and crypto details see [Security](security.md). For the wire format see [Protocol](protocol.md).

## Import paths

```typescript
// Root entry — everything
import {
  chain, server, client,
  RPCError, RemoteRPCError,
  deriveSessionPSK,
} from "@dotex/erpc";

// Subpaths for tree-shaking
import { ... } from "@dotex/erpc/common";
import { ... } from "@dotex/erpc/server";
import { ... } from "@dotex/erpc/client";
```

---

## `chain()`

```typescript
function chain(): Chain;
```

Returns a procedure builder. All methods are immutable and chainable. The chain terminates with `.handler()`, which returns a frozen `Procedure`.

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

Treat `Procedure` as opaque. The fields are exported only so `server()` can introspect them.

---

## `server(router, channel, options)`

```typescript
function server<T extends Router>(
  router: T,
  channel: Channel,
  options: ServerOptions,
): { destroy: () => void };
```

Subscribes to `channel` and serves the given router. Returns synchronously.

### `ServerOptions`

| Field | Type | Default | Required |
|-------|------|---------|----------|
| `auth` | `AuthOptions` | — | ✅ (or legacy `psk` / `authenticator`) |
| `context` | `(ctx: { auth?: Ctx }) => Ctx \| Promise<Ctx>` | — | — |
| `handshakeTimeout` | `number` (ms) | `5000` | — |
| `maxMessageBytes` | `number` | `1_048_576` | — |
| `onError` | `(err: unknown) => void` | — | — |

`context` is called per request. The `auth` argument carries whatever `auth.verify` returned for the current session. When `context` is omitted, the request context is the verified auth data (or `{}` if none).

`onError` is called on handshake failures and non-fatal internal errors. The server does **not** destroy on handshake failure — it resets and accepts the next hello.

### `AuthOptions`

```typescript
interface AuthOptions {
  psk?: () => Uint8Array | Promise<Uint8Array>;
  sign?: (transcript: Uint8Array) => Uint8Array | Promise<Uint8Array>;
  verify?: (
    proof: Uint8Array,
    transcript: Uint8Array,
  ) => VerifyResult | Promise<VerifyResult>;
}

type VerifyResult = { auth?: Ctx } | void;
```

At least one of `psk` or asymmetric (`sign` / `verify`) must be set. Configuring neither throws a `TypeError` at construction.

| Field | Called | Notes |
|-------|--------|-------|
| `psk` | Per handshake attempt | Returned bytes must be ≥ 32. Empty PSK used when `psk` is omitted but asymmetric auth is configured. |
| `sign` | Per handshake attempt, if set | Signature payload, ≤ 32 KiB. |
| `verify` | Per handshake attempt, if set | Throw to reject. Returned `auth` is bound to the resulting session. |

Returned `auth` data is sanitized (poison keys stripped) before being passed to `context`.

### Legacy options

`psk: Uint8Array` and `authenticator: { produce?, verify? }` are accepted for backwards compatibility and converted to `auth` internally. Use `auth` in new code.

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

Returns synchronously. The handshake is lazy: it starts on the first `api` call.

### `ClientOptions`

| Field | Type | Default | Required |
|-------|------|---------|----------|
| `auth` | `AuthOptions` | — | ✅ (or legacy `psk` / `authenticator`) |
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

When an RPC call fails (timeout or send error) on an established session, the client automatically retries once with a fresh handshake.

```
api.foo("x") → sendRequest() → timeout (server died)
epoch === sentEpoch? → YES → reset() (zero keys, state → idle)
ensureHandshake() → new handshake (epoch++)
hello → reply → ready
sendRequest() again → success
api.foo() resolves
```

### Retry rules

| Failure | Retried? |
|---------|----------|
| `RemoteRPCError` (server returned an error) | No |
| `destroy()` was called | No |
| Local `RPCError("TIMEOUT" | send error)` | Yes, exactly once |

Concurrent calls coordinate via the epoch counter. Only the first failing call triggers `reset()`; subsequent calls notice the epoch advanced and share the new handshake. No infinite loops.

---

## Re-handshake

The server accepts a new hello in `ready` state. This is what enables transparent recovery:

```
Client (ready)                     Server (ready)

reset() → idle
        ── new hello ──►           resetHandshake()
                                   state → waiting → pending
        ◀── reply ────
state → ready
        ── retry RPC ──►          state → ready (confirmed)
        ◀── response ──
call resolves
```

The epoch counter increments on each handshake. Stale responses from a dead session are silently dropped when their epoch does not match.

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

It is **allowed** to drop messages, duplicate them, or reorder them — eRPC will time out and retry. Ready-made adapters live in [Integrations](integrations.md).

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
- `RemoteRPCError` is thrown when the remote peer's handler returned an error. The `code`, `message`, and `data` come from the remote side and are **untrusted strings** — do not log them at warn/error level without sanitization.

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
| `INTERNAL` | Defensive — should not be reachable |
| `MIDDLEWARE` | Middleware misuse (`next()` called twice, bad `extra` arg) |

Handlers may throw `RPCError(...)` with any code — those codes become `RemoteRPCError.code` on the client.

### Pattern

```typescript
try {
  await api.getProfile({ id: "u_1" });
} catch (err) {
  if (err instanceof RemoteRPCError) {
    // handler threw on the other side — err.code, err.message, err.data
  } else if (err instanceof RPCError) {
    // local failure — TIMEOUT, SESSION, etc.
  } else {
    throw err;
  }
}
```

---

## Middleware and context

Middleware extends the context. Each middleware is `({ ctx, input, next })`. It must call `next(extra?)` exactly once.

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

Calling `next()` twice in the same middleware throws `RPCError("MIDDLEWARE", ...)`. Passing a non-object `extra` does the same.

The `context` factory runs **per request**, after auth verification, and receives `{ auth }` carrying the data returned by `auth.verify` for the session.

---

## `deriveSessionPSK`

```typescript
function deriveSessionPSK(sessionId: string, secret: Uint8Array): Uint8Array;
```

HKDF-SHA-256 over `secret` with `sessionId` as salt and the fixed info string `"erpc-session-v1"`. Returns 32 bytes.

Throws `TypeError` if `sessionId` is empty or `secret` is shorter than 32 bytes.

Use to bind each handshake to a session identifier instead of holding a single static PSK.

---

## Built-in auth helpers

All return partial `AuthOptions` you can spread into the `auth` block.

### Client-side

```typescript
import {
  createJWTClientAuth,
  createEd25519ClientAuth,
  createECDSAClientAuth,
  generateEd25519Keypair,
  generateECDSAKeypair,
} from "@dotex/erpc";
```

| Helper | Returns |
|--------|---------|
| `createJWTClientAuth({ getToken })` | `{ sign }` — embeds JWT + timestamp in the hello auth payload |
| `createEd25519ClientAuth({ privateKey, deviceId })` | `{ sign }` |
| `createECDSAClientAuth({ privateKey, identifier })` | `{ sign }` |
| `generateEd25519Keypair()` | `{ privateKey: Uint8Array, publicKey: Uint8Array }` |
| `generateECDSAKeypair()` | `{ privateKey: CryptoKey, publicKey: CryptoKey }` |

### Server-side

```typescript
import {
  createJWTServerAuth,
  createEd25519ServerAuth,
  createECDSAServerAuth,
  createCertificateServerAuth,
  createMultifactorServerAuth,
} from "@dotex/erpc";
```

| Helper | Use |
|--------|-----|
| `createJWTServerAuth({ verifyToken })` | Verifies JWT from `createJWTClientAuth`. Returns `{ auth: { userId, ... } }`. |
| `createEd25519ServerAuth({ getPublicKey })` | Verifies Ed25519 signature against a device's public key. |
| `createECDSAServerAuth({ getPublicKey })` | Verifies ECDSA P-256 signature. |
| `createCertificateServerAuth({ validateChain })` | Verifies certificate chain + signature. |
| `createMultifactorServerAuth({ factors })` | Combines multiple verifiers; all must pass. |

All return partial `AuthOptions` (`{ verify }` or `{ sign, verify }`).

---

## Constants

```typescript
import {
  NONCE_LEN,        // 24 — XSalsa20-Poly1305 message nonce
  KEY_LEN,          // 32 — symmetric key / X25519 key / hello nonce
  TAG_HELLO,        // 0x00
  TAG_MSG,          // 0x01
  MAX_MSG_BYTES,    // 1_048_576
  MAX_HELLO_BYTES,  // 65_536
  MAX_AUTH_BYTES,   // 32_768
  HANDSHAKE_TIMEOUT,// 5000
  EMPTY_PSK,        // Uint8Array(32) of zeros
} from "@dotex/erpc";
```

Exported for adapter authors. Application code does not normally need these.

---

## Cleanup

Always call `destroy()` when you are done with a session.

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

Both `server()` and `client()` return **synchronously**. No top-level `await`. Pure JavaScript dependencies. Compatible with:

- Cloudflare Workers / Durable Objects
- Deno Deploy
- Vercel Edge Functions
- Service Workers
- React Native
- Node.js 18+
- Modern browsers
