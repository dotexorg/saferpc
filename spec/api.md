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
interface Context {
  user: { id: string } | null;
}

// rpc IS the procedure builder; rpc.router / rpc.middleware hang off it.
export const rpc = saferpc<Context>();
```

- **`rpc`** — the root [`ProcedureBuilder`](#procedurebuilder) whose handler `ctx` is `TCtx`. `rpc.input(...).handler(...)` builds a procedure; `rpc.use(...)` derives a middleware-bearing builder. Chained calls return a plain `ProcedureBuilder` (no `router`/`middleware`).
- **`rpc.router(routes)`** — validates and returns the map unchanged, keeping each procedure's precise input/output types so `Client<typeof appRouter>` infers a typed call per route. Equivalent to `{ ... } satisfies Router`.
- **`rpc.middleware(mw)`** — authors a reusable middleware bound to `TCtx`; its context extension is inferred from what it passes to `next()`. Plugs into `rpc.use(...)`.

### `ProcedureBuilder`

```typescript
interface ProcedureBuilder<
  TBaseCtx = {},    // base context the server must supply (never grows)
  TCtx = TBaseCtx,  // handler-visible context (grows through .use())
  TInputIn = unknown,
  TInput = unknown,
  TOutputDef = unknown,
> {
  use<TExtra = {}>(mw: (opts: {
    ctx: TCtx;
    input: TInput;
    next: NextFn;
  }) => Promise<MiddlewareResult<TExtra>>): ProcedureBuilder<TBaseCtx, TCtx & TExtra, TInputIn, TInput, TOutputDef>;

  input<S extends ZodType>(schema: S): ProcedureBuilder<TBaseCtx, TCtx, z.input<S>, z.output<S>, TOutputDef>;
  output<S extends ZodType>(schema: S): ProcedureBuilder<TBaseCtx, TCtx, TInputIn, TInput, { handler: z.input<S>; client: z.output<S> }>;

  // handler may be sync or async
  handler<R>(fn: (opts: { ctx: TCtx; input: TInput }) => R | Promise<R>): Procedure<TInputIn, ..., TBaseCtx>;
}
```

Every method is immutable and chainable. The handler may be **sync or async**. `.handler()` terminates the builder and returns a frozen `Procedure` that records `TBaseCtx` so [`server()`](#serverrouter-channel-options) can demand a matching `context()`.

### Method semantics

| Method            | Effect                                  | Notes                                                                                                                                                                                 |
| ----------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.use(mw)`        | Adds middleware that can extend context | `mw` may be a plain (non-`async`) function but must **return** `next()` (called exactly once). `next(extra)` merges `extra` into ctx — and its type flows into every downstream step. |
| `.input(schema)`  | Validates & parses input with Zod       | Handler receives `z.output<S>`; callers send `z.input<S>`. On failure throws `RPCError("INPUT_VALIDATION", ...)`.                                                                     |
| `.output(schema)` | Validates & parses output with Zod      | Handler returns `z.input<S>` (pre-transform); callers observe `z.output<S>`. On failure throws `RPCError("OUTPUT_VALIDATION", ...)`. Runs _after_ handler.                            |
| `.handler(fn)`    | Terminates the builder                  | `fn` may be **sync or async**. Returns a frozen `Procedure`. Without `.output()`, the caller-facing output is inferred from `fn`'s (awaited) return.                                  |

`schema` is anything with a `.safeParse()` method (a Zod schema in practice).

### `chain()`

```typescript
function chain(): ProcedureBuilder; // empty, untyped context
```

Backward-compatible alias for the base builder — an empty, untyped context. Prefer `saferpc<Ctx>()`, which binds the context type so procedures authored in separate files get a fully-typed `ctx`.

### `Procedure`

```typescript
interface Procedure<TInput = unknown, TOutput = unknown, TContext = {}> {
  readonly _steps: ReadonlyArray<Step>;
  readonly _handler: HandlerFn;
  // phantom, never present at runtime
  readonly $types?: { input: TInput; output: TOutput; context: TContext };
}

type Router = Record<string, Procedure>;

// Extract a procedure's caller-facing types:
type inferInput<P> = P extends Procedure<infer I, unknown, unknown> ? I : never;
type inferOutput<P> =
  P extends Procedure<unknown, infer O, unknown> ? O : never;

// Also exported — RouterContext<T>: the base context a whole router requires
// (the intersection of its procedures' base contexts). server() uses it.
```

Treat `Procedure` as opaque at runtime. `_steps`/`_handler` are exposed only so `server()` can introspect them; `$types` is a compile-time-only carrier that powers end-to-end inference in [`Client<Router>`](#clientt) (input/output) and the required `context()` in [`server()`](#serverrouter-channel-options) (the base context).

---

## `server(router, channel, options)`

```typescript
function server<T extends Router>(
  router: T,
  channel: Channel,
  options: ServerOptions<RouterContext<T>>,
): { destroy: () => void };
```

Subscribes to `channel` and serves the router. Returns synchronously. The options type is inferred from the router: if its procedures declare a non-empty base context (the type passed to `saferpc<Ctx>()`), `context` is **mandatory** and must return that type.

### `ServerOptions`

| Field              | Type                                             | Default     | Required                                                        |
| ------------------ | ------------------------------------------------ | ----------- | --------------------------------------------------------------- |
| `auth`             | `AuthOptions`                                    | —           | ✅                                                              |
| `context`          | `(ctx: { auth?: Ctx }) => TCtx \| Promise<TCtx>` | —           | ✅ when `TCtx` (the router's base context) is non-empty, else — |
| `handshakeTimeout` | `number` (ms)                                    | `5000`      | —                                                               |
| `maxMessageBytes`  | `number`                                         | `1_048_576` | —                                                               |
| `replayWindow`     | `number`                                         | `4096`      | —                                                               |
| `onError`          | `(err: unknown) => void`                         | —           | —                                                               |

`context` runs per request and must return the router's base context `TCtx`. The `auth` argument carries whatever `auth.verify` returned for the current session. When the base context is empty, `context` is optional and the request context falls back to the verified auth data (or `{}` if none).

`replayWindow` is the number of recently-seen AEAD nonces the server remembers per session so it can drop replayed request frames (in-session replay defense). FIFO-evicted: a replay older than the last `replayWindow` accepted messages executes again, so the window is narrowed to N, not closed. Cleared on every re-handshake. Set `0` to disable.

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

| Field    | Called                        | Notes                                                                                                      |
| -------- | ----------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `secret` | Per handshake attempt         | Returned bytes must be ≥ 32. Empty secret used when `secret` is omitted but asymmetric auth is configured. |
| `sign`   | Per handshake attempt, if set | Signature payload, ≤ 32 KiB.                                                                               |
| `verify` | Per handshake attempt, if set | Throw to reject. Returned `auth` is bound to the resulting session.                                        |

Returned `auth` data is sanitized (poison keys stripped) before reaching `context`.

### Server lifecycle

```
waiting → pending → ready
   ↑         |        |
   └─────────┴────────┘   (candidate timeout / new hello / explicit destroy)
```

State is described by two key slots — a **live** session and a validated-but-unconfirmed **candidate** (make-before-break):

- `waiting`: no live session, no candidate. Accepting hellos.
- `pending`: a validated hello has installed a candidate; the reply is sent. **If a live session already exists it keeps serving throughout.** The candidate is promoted only on successful decrypt of the first `TAG_MSG` under the candidate key.
- `ready`: a live session is confirmed, no candidate pending. Routes RPCs.
- A new hello in any state opens an attempt and, if it validates, installs a candidate — it does **not** reset or displace the live session. A replayed or forged hello can at most create a candidate that expires unconfirmed.
- `destroy()` is permanent: zeros all keys, unsubscribes from the channel, drops references.

---

## `client<T>(channel, options)`

```typescript
function client<T extends Router>(
  channel: Channel,
  options: ClientOptions,
): {
  api: Client<T>;
  abortPending: (err?: RPCError) => void;
  destroy: () => void;
};
```

Returns synchronously. The handshake stays lazy: it starts on the first `api` call. `abortPending(err?)` lets the application reject all in-flight calls (and any in-progress handshake) at once when it knows further waiting is pointless — the session itself survives; see [Failure handling](#failure-handling-no-auto-retry).

### `ClientOptions`

| Field              | Type          | Default     | Required |
| ------------------ | ------------- | ----------- | -------- |
| `auth`             | `AuthOptions` | —           | ✅       |
| `timeout`          | `number` (ms) | `30_000`    | —        |
| `maxPending`       | `number`      | `256`       | —        |
| `handshakeTimeout` | `number` (ms) | `5000`      | —        |
| `maxMessageBytes`  | `number`      | `1_048_576` | —        |

`maxPending` caps concurrent in-flight calls. Past the cap, calls reject with `RPCError("CLIENT", "Too many pending requests")`.

`timeout` applies to every call. On timeout the client throws `RPCError("TIMEOUT", "Timed out: <procedure>")` and resets the session (no auto-retry — the error surfaces and the caller decides whether to retry; the next call re-handshakes). Set it generously — it is the safety net, not a UX budget; shorten a single call with [`AbortSignal.timeout`](#calloptions--per-call-abort) instead.

### `Client<T>`

```typescript
type Client<T extends Router> = {
  [K in keyof T & string]: T[K] extends Procedure<infer TInput, infer TOutput>
    ? (input: TInput, opts?: CallOptions) => Promise<TOutput>
    : (input: unknown, opts?: CallOptions) => Promise<unknown>;
};
```

Each procedure maps to a call whose argument and result are inferred from that procedure. Pass `typeof appRouter` as the type argument — `client<typeof appRouter>(...)` — to get full end-to-end inference. A loose `Router` collapses to `(input: unknown, opts?: CallOptions) => Promise<unknown>`, so untyped usage keeps working.

### `CallOptions` — per-call abort

```typescript
interface CallOptions {
  signal?: AbortSignal;
}

const ac = new AbortController();
const p = api.getProfile({ id: "u_1" }, { signal: ac.signal });
ac.abort(); // p rejects with RPCError("ABORTED"), signal.reason on .cause

// a shorter budget for ONE call — the platform's timeout-signal:
await api.getPrice(input, { signal: AbortSignal.timeout(500) });
```

Fetch-style. Aborting rejects **that call** with `RPCError("ABORTED")`:

- An already-aborted signal rejects immediately — nothing is sent and no handshake is triggered.
- Aborting while the call waits on a shared handshake rejects the call only; the handshake keeps running for other callers and for the next call.
- Abort is client-local. Like a `TIMEOUT`, the outcome on the server is **UNKNOWN** — the request may still execute there. Abort does not cancel server-side execution; never blind-resend a non-idempotent call after aborting it.
- The session is never touched: `ABORTED` does not trigger the reset path, and a reply arriving after the abort is silently dropped.

There is deliberately **no per-call `timeout` field**: the two-lever model is a *global* timeout (the client-level `timeout` option — the safety net that heals a dead session) plus a *local* abort (`AbortSignal.timeout(ms)` for a shorter single-call budget — gives `ABORTED`, session untouched). A signal can only shrink a call's budget, not extend it past the global timer; procedures slower than the global timeout mean the global value is too small — raise `ClientOptions.timeout` (this is also why the default is a generous 30 s), don't look for a per-call escape hatch.

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

## Failure handling (no auto-retry)

As of 0.7.0 a call that fails on a `ready` session with a local `TIMEOUT` or `CHANNEL` send error resets the session (zeros the key, returns to `idle`) but is **not** resent — the error surfaces so the caller, the only party that knows whether the procedure is idempotent, decides. Resending after a `TIMEOUT` (outcome unknown) would silently double-execute non-idempotent handlers. `RemoteRPCError` (server answered) and local guardrail errors (`CLIENT`, `ABORTED`) never reset the session. The reset alone keeps a desynced peer from wedging future calls: the next call re-handshakes lazily. Concurrent failures share one re-handshake via an epoch counter. Full state-machine and wire-level semantics in [Protocol § Failure handling](protocol.md#failure-handling-no-auto-retry).

As of 0.7.0 **transport death is not a session event**. The session is bound to key material, not to a transport instance; when a socket dies, the client does nothing — keys are kept, pending calls keep waiting under their own timers. A call's outcome is decided by exactly two events: a reply that decrypts, or the call's own timeout. Channel liveness (reconnecting, queueing frames that never left) is the adapter's job — see [Integrations § adapter lifecycle contract](integrations.md) and the shipped `@dotex/saferpc/channels`. If the server lost its session with the socket, the first call after recovery times out and the reset above heals lazily.

`abortPending(err?)` is the application-driven "stop waiting": it rejects every in-flight call and any hello-waiter immediately with `err ?? RPCError("ABORTED", "Pending calls aborted")` and fails an in-progress handshake. A `ready` session's keys and state are **untouched** — the next call reuses the session, no re-handshake. Use it when the app knows waiting is pointless (user logged out, tab hiding); use per-call `signal` for single-call aborts.

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

The only transport contract. `receive` should return an unsubscribe function; returning `void` is tolerated but then `destroy()` cannot detach the listener (a leak on long-lived channels — prefer returning the unsubscribe). The channel must:

- Transmit bytes intact (no silent corruption)
- Deliver each call to `cb` once, in any order
- Allow `send` and `receive` to run concurrently

Dropping, duplicating, or reordering messages is allowed — Safe RPC will time out and surface a typed error (no auto-retry; the caller decides whether to resend). For transports that can die (sockets), the adapter owns liveness: reopen immediately, hold open, queue frames that provably never left while down — see [Integrations § adapter lifecycle](integrations.md#adapter-lifecycle-reopen-immediately-queue-what-never-left). Ready-made adapters live in [Integrations](integrations.md) and ship as code in `@dotex/saferpc/channels`.

> Within a single session the protocol assumes the `TAG_HELLO` reply arrives before any `TAG_MSG` sent under the resulting session key. Transports that can reorder _across_ the hello/reply boundary (multi-path links, fan-out buses) will hang the handshake until the timeout fires. `TAG_MSG`-to-`TAG_MSG` reordering stays safe: every encrypted frame is independently authenticated and the protocol imposes no ordering on application messages.

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

| Code                | Thrown when                                                                                                           |
| ------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `TIMEOUT`           | RPC call exceeded `timeout` ms                                                                                        |
| `SESSION`           | `destroy()` called or session closed                                                                                  |
| `CLIENT`            | Client-side guardrail tripped (e.g., `maxPending` exceeded)                                                           |
| `CHANNEL`           | `channel.send` failed (request provably never left). Original error on `.cause`                                       |
| `ABORTED`           | Per-call `signal` fired, or `abortPending()`; outcome on the server UNKNOWN (like `TIMEOUT`). `signal.reason` on `.cause` |
| `HANDSHAKE`         | Handshake failed or timed out, auth payload malformed                                                                 |
| `INPUT_VALIDATION`  | `.input(schema)` rejected the input                                                                                   |
| `OUTPUT_VALIDATION` | `.output(schema)` rejected the handler output                                                                         |
| `INVALID_DATA`      | Wire-level data rejected by `sanitize()`                                                                              |
| `INTERNAL`          | Defensive: should not be reachable                                                                                    |
| `MIDDLEWARE`        | Middleware misuse (`next()` called twice, bad `extra` arg)                                                            |

`INPUT_VALIDATION`, `OUTPUT_VALIDATION`, `MIDDLEWARE`, and `NOT_FOUND` are raised **server-side**. The client never validates locally, so these always arrive wrapped as `RemoteRPCError` (the remote branch of the pattern below), never as a bare local `RPCError`. Only `TIMEOUT`, `SESSION`, `CLIENT`, `ABORTED`, and `HANDSHAKE` are genuinely client-local.

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

| Helper                                              | Returns                                             | Notes                                                           |
| --------------------------------------------------- | --------------------------------------------------- | --------------------------------------------------------------- |
| `createJWTClientAuth({ getToken })`                 | `{ sign }`                                          | Embeds `{ jwt, ts, th }` where `th` is `SHA-256(transcript)`.   |
| `createEd25519ClientAuth({ privateKey, deviceId })` | `{ sign }`                                          | Signs the transcript via `@noble/curves` (no WebCrypto needed). |
| `createECDSAClientAuth({ privateKey, identifier })` | `{ sign }`                                          | WebCrypto P-256, `privateKey` is a `CryptoKey`.                 |
| `generateEd25519Keypair()`                          | `{ privateKey: Uint8Array, publicKey: Uint8Array }` | Pure JS, works everywhere.                                      |
| `generateECDSAKeypair()`                            | `{ privateKey: CryptoKey, publicKey: CryptoKey }`   | Non-extractable.                                                |

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

| Helper                                                                 | Use                                                                                                              |
| ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `createJWTServerAuth({ verifyToken, maxAge? })`                        | Verifies JWT + timestamp (symmetric skew check) + transcript digest. Returns the `verifyToken` result as `auth`. |
| `createEd25519ServerAuth({ getPublicKey, validateDevice? })`           | Verifies Ed25519 signature against a device's 32-byte public key.                                                |
| `createECDSAServerAuth({ getPublicKey, validateEntity? })`             | Verifies ECDSA P-256 signature via WebCrypto.                                                                    |
| `createCertificateServerAuth({ verifyCertificate, validateSubject? })` | Verifies a presented certificate chain + ECDSA P-256 signature.                                                  |
| `createMultifactorServerAuth({ primary, secondary, combineAuth? })`    | Composes two verifiers; both must pass.                                                                          |

Auth payloads decode through the hardened msgpack codec: extension types rejected, prototype-pollution keys stripped, recursion depth capped. Returned `auth` data is sanitized before reaching `context`.

---

## Constants

```typescript
import {
  NONCE_LEN, // 24: XSalsa20-Poly1305 message nonce
  KEY_LEN, // 32: symmetric key / X25519 key / hello nonce
  TAG_HELLO, // 0x00
  TAG_MSG, // 0x01
  MAX_MSG_BYTES, // 1_048_576
  MAX_HELLO_BYTES, // 65_536
  MAX_AUTH_BYTES, // 32_768
  MAX_DEPTH, // 32: max `sanitize()` recursion depth
  HANDSHAKE_TIMEOUT, // 5000
  EMPTY_SECRET, // Uint8Array(32) of zeros: internal "no secret" sentinel
  // Type guards
  isPlainBytes, // exact-prototype Uint8Array check for wire data
  isEmptySecret, // constant-time check for the 32-zero secret sentinel
} from "@dotex/saferpc";
```

Exported for adapter authors. Application code rarely needs them.

---

## Cleanup

Call `destroy()` when you are done with a session.

```typescript
const { destroy: destroyServer } = server(router, channel, { auth });
const { api, destroy: destroyClient } = client<typeof router>(channel, {
  auth,
});

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
