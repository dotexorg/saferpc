# API reference

Reference for every exported symbol. End-to-end walkthrough lives in [Getting Started](getting-started.md), threat model and crypto in [Security](security.md), wire format in [Protocol](protocol.md).

## Import paths

```typescript
// Root entry: everything
import {
  saferpc, chain, server, client,
  RPCError, RemoteRPCError,
  deriveSessionSecret,
} from "@dotex/saferpc";

// Subpaths for tree-shaking
import { ... } from "@dotex/saferpc/common";
import { ... } from "@dotex/saferpc/server";
import { ... } from "@dotex/saferpc/client";

// Auth helpers: combined or split per side
import { ... } from "@dotex/saferpc/auth";        // client + server helpers
import { ... } from "@dotex/saferpc/auth/client"; // client helpers only
import { ... } from "@dotex/saferpc/auth/server"; // server helpers only
```

---

## `saferpc()`

```typescript
function saferpc<TCtx = {}>(): SafeRPC<TCtx>;

// SafeRPC *is* a ProcedureBuilder (bound to TCtx) that also namespaces
// two typed helpers. The returned value is the procedure itself.
interface SafeRPC<TCtx = {}> extends ProcedureBuilder<TCtx> {
  router<R extends Router>(routes: R): R;
  middleware<TExtra>(mw: Middleware<TCtx, TExtra>): Middleware<TCtx, TExtra>;
}
```

Initialise once, binding the handler context type `TCtx` (mirrors tRPC's
`initTRPC.context<Ctx>().create()`; the flat, chainable root mirrors oRPC's
`os`). The returned value is itself the [`ProcedureBuilder`](#procedurebuilder)
— no `.procedure` indirection — so procedures authored in any file get a
fully-typed `ctx`.

```typescript
interface Context { user: { id: string } | null }

// rpc IS the procedure builder; rpc.router / rpc.middleware hang off it.
export const rpc = saferpc<Context>();
```

- **`rpc`** — the root [`ProcedureBuilder`](#procedurebuilder) whose handler `ctx` is `TCtx`. `rpc.input(...).handler(...)` builds a procedure; `rpc.use(...)` derives a middleware-bearing builder. Chained calls return a plain `ProcedureBuilder` (no `router`/`middleware`).
- **`rpc.router(routes)`** — validates and returns the map unchanged, keeping each procedure's precise input/output types so `Client<typeof appRouter>` infers a typed call per route. Equivalent to `{ ... } satisfies Router`.
- **`rpc.middleware(mw)`** — authors a reusable middleware bound to `TCtx`; its context extension is inferred from what it passes to `next()`. Plugs into `rpc.use(...)`.

### `ProcedureBuilder`

```typescript
interface ProcedureBuilder<TCtx = {}, TInputIn = unknown, TInput = unknown, TOutputDef = unknown> {
  use<TExtra = {}>(mw: (opts: {
    ctx: TCtx;
    input: TInput;
    next: NextFn;
  }) => Promise<MiddlewareResult<TExtra>>): ProcedureBuilder<TCtx & TExtra, TInputIn, TInput, TOutputDef>;

  input<S extends ZodType>(schema: S): ProcedureBuilder<TCtx, z.input<S>, z.output<S>, TOutputDef>;
  output<S extends ZodType>(schema: S): ProcedureBuilder<TCtx, TInputIn, TInput, { handler: z.input<S>; client: z.output<S> }>;

  handler<R>(fn: (opts: { ctx: TCtx; input: TInput }) => Promise<R>): Procedure<TInputIn, ...>;
}
```

Every method is immutable and chainable. `.handler()` terminates the builder and returns a frozen `Procedure`.

### Method semantics

| Method | Effect | Notes |
|--------|--------|-------|
| `.use(mw)` | Adds middleware that can extend context | `mw` must return `next()` (call it exactly once). `next(extra)` merges `extra` into ctx — and its type flows into every downstream step. |
| `.input(schema)` | Validates & parses input with Zod | Handler receives `z.output<S>`; callers send `z.input<S>`. On failure throws `RPCError("INPUT_VALIDATION", ...)`. |
| `.output(schema)` | Validates & parses output with Zod | Handler returns `z.input<S>` (pre-transform); callers observe `z.output<S>`. On failure throws `RPCError("OUTPUT_VALIDATION", ...)`. Runs *after* handler. |
| `.handler(fn)` | Terminates the builder | Returns a frozen `Procedure`. Without `.output()`, the caller-facing output type is inferred from `fn`'s return. |

`schema` is anything with a `.safeParse()` method (a Zod schema in practice).

### `chain()`

```typescript
function chain(): ProcedureBuilder; // empty, untyped context
```

Backward-compatible alias for `saferpc().procedure`. Prefer `saferpc<Ctx>()` so the context type flows into procedures authored in separate files.

### `Procedure`

```typescript
interface Procedure<TInput = unknown, TOutput = unknown> {
  readonly _steps: ReadonlyArray<Step>;
  readonly _handler: HandlerFn;
  readonly $types?: { input: TInput; output: TOutput }; // phantom, never present at runtime
}

type Router = Record<string, Procedure>;

// Extract a procedure's caller-facing types:
type inferInput<P>  = P extends Procedure<infer I, unknown> ? I : never;
type inferOutput<P> = P extends Procedure<unknown, infer O> ? O : never;
```

Treat `Procedure` as opaque at runtime. `_steps`/`_handler` are exposed only so `server()` can introspect them; `$types` is a compile-time-only carrier that powers end-to-end inference in [`Client<Router>`](#clientt).

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
  [K in keyof T & string]: T[K] extends Procedure<infer TInput, infer TOutput>
    ? (input: TInput) => Promise<TOutput>
    : (input: unknown) => Promise<unknown>;
};
```

Each procedure maps to a call whose argument and result are inferred from that procedure. Pass `typeof appRouter` as the type argument — `client<typeof appRouter>(...)` — to get full end-to-end inference. A loose `Router` collapses to `(input: unknown) => Promise<unknown>`, so untyped usage keeps working.

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
const authed = rpc.middleware(async ({ ctx, next }) => {
  if (ctx.user === null) throw new RPCError("UNAUTHORIZED", "Login required");
  return next({ user: ctx.user }); // merges into ctx; type flows downstream
});

const getProfile = rpc
  .use(authed)
  .input(z.object({ id: z.string() }))
  .handler(async ({ ctx, input }) => db.getProfile(ctx.user.id, input.id));

const appRouter = rpc.router({ getProfile });

server(appRouter, channel, {
  auth,
  context: ({ auth: verified }) => ({
    user: verified ? { id: verified.userId } : null,
  }),
});
```

The middleware must **return** `next(...)`. Calling `next()` twice throws `RPCError("MIDDLEWARE", ...)`; so does passing a non-object `extra`.

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
} from "@dotex/saferpc/auth/client";
// Also re-exported from "@dotex/saferpc" and "@dotex/saferpc/auth".
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
} from "@dotex/saferpc/auth/server";
// Also re-exported from "@dotex/saferpc" and "@dotex/saferpc/auth".
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
