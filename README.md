# eRPC

**Encrypted** Remote Procedure Calls over any bidirectional channel. Every call is end-to-end encrypted (PSK + X25519 key exchange, XSalsa20-Poly1305 AEAD) with type-safe contracts, zero-config retry, and forward secrecy. Works everywhere JavaScript runs.

## Install

```bash
npm install @dotex/erpc
```

## File Structure

```
src/
  common.ts  — Types, crypto, chain builder, utilities
  server.ts  — Server with resilient handshake
  client.ts  — Client with lazy handshake + auto-retry
  index.ts   — Barrel export
```

## Quick Start

```typescript
import { chain } from "@dotex/erpc/common";
import { server } from "@dotex/erpc/server";
import { client } from "@dotex/erpc/client";
import { z } from "zod";

// ── Define procedures ─────────────────────────────────────
const d = chain();

const router = {
  greet: d
    .input(z.object({ name: z.string() }))
    .output(z.object({ message: z.string() }))
    .handler(async ({ input }) => ({
      message: `Hello, ${input.name}!`,
    })),
};

// ── Shared secret (both sides must know this) ─────────────
const psk = crypto.getRandomValues(new Uint8Array(32));

// ── Server ────────────────────────────────────────────────
const { destroy: destroyServer } = server(router, serverChannel, {
  psk,
  onError: console.error,
});

// ── Client ────────────────────────────────────────────────
const { api, destroy: destroyClient } = client<typeof router>(clientChannel, {
  psk,
});

// ── Call (handshake happens automatically) ────────────────
const result = await api.greet({ name: "World" });
console.log(result.message); // "Hello, World!"
```

## API

### `chain()` — Procedure Builder

```typescript
import { chain } from "@dotex/erpc/common";

const d = chain();

d.use(middlewareFn) // Add middleware
  .input(zodSchema) // Validate + type input
  .output(zodSchema) // Validate + type output
  .handler(async ({ ctx, input }) => result); // Terminal handler
```

All methods are chainable. `.handler()` returns a frozen `Procedure`.

### `server(router, channel, options)`

Creates a server that listens on the channel. Returns `{ destroy }`.

```typescript
import { server } from "@dotex/erpc/server";

interface ServeOptions {
  psk: Uint8Array; // REQUIRED. Min 32 bytes.
  context?: () => Ctx | Promise<Ctx>; // Per-request context factory
  handshakeTimeout?: number; // Default: 5000ms
  maxMessageBytes?: number; // Default: 1MB
  onError?: (err: unknown) => void; // Handshake/send errors
}
```

### `client<Router>(channel, options)`

Creates a client. Returns `{ api, destroy }`.

```typescript
import { client } from "@dotex/erpc/client";

interface ClientOptions {
  psk: Uint8Array; // REQUIRED. Min 32 bytes.
  timeout?: number; // Per-call timeout. Default: 10000ms
  maxPending?: number; // Max concurrent calls. Default: 256
  handshakeTimeout?: number; // Default: 5000ms
  maxMessageBytes?: number; // Default: 1MB
}
```

The `api` proxy triggers the handshake lazily on first call. No `await` needed at creation.

### `Channel` Interface

```typescript
interface Channel {
  send(data: Uint8Array): void | Promise<void>;
  receive(cb: (data: Uint8Array) => void): () => void; // Returns unsubscribe
}
```

### Errors

```typescript
import { RPCError, RemoteRPCError } from "@dotex/erpc/common";

RPCError; // Local errors (TIMEOUT, SESSION, CLIENT, HANDSHAKE, ...)
RemoteRPCError; // Errors from the remote peer (subclass of RPCError)
```

Callers can distinguish:

```typescript
try {
  await api.foo(input);
} catch (err) {
  if (err instanceof RemoteRPCError) {
    // Server handler threw — err.code, err.message, err.data
  } else if (err instanceof RPCError) {
    // Local failure — timeout, session lost, etc.
  }
}
```

---

## Middleware & Context

```typescript
const d = chain();

const authProcedure = d.use(async ({ ctx, input, next }) => {
  const user = await getUser(ctx.token);
  if (!user) throw new RPCError("UNAUTHORIZED", "Bad token");
  return next({ user }); // Merge into ctx
});

const router = {
  getProfile: authProcedure
    .input(z.object({ id: z.string() }))
    .handler(async ({ ctx, input }) => {
      // ctx.user is available here
      return db.getProfile(input.id);
    }),
};

// Provide base context per-request
server(router, channel, {
  psk,
  context: () => ({ token: getCurrentToken() }),
});
```

---

## Channel Adapters

### postMessage (Window / iframe)

```typescript
function postMessageChannel(target: Window, origin: string): Channel {
  return {
    send(data) {
      target.postMessage(data, origin);
    },
    receive(cb) {
      const handler = (e: MessageEvent) => {
        if (e.origin !== origin) return;
        if (e.data instanceof Uint8Array) cb(e.data);
      };
      window.addEventListener("message", handler);
      return () => window.removeEventListener("message", handler);
    },
  };
}
```

### WebSocket

```typescript
function wsChannel(ws: WebSocket): Channel {
  return {
    send(data) {
      ws.send(data);
    },
    receive(cb) {
      const handler = (e: MessageEvent) => {
        if (e.data instanceof ArrayBuffer) cb(new Uint8Array(e.data));
      };
      ws.addEventListener("message", handler);
      return () => ws.removeEventListener("message", handler);
    },
  };
}
```

### MessageChannel (Worker / iframe)

```typescript
function portChannel(port: MessagePort): Channel {
  return {
    send(data) {
      port.postMessage(data, [data.buffer]);
    },
    receive(cb) {
      const handler = (e: MessageEvent) => cb(new Uint8Array(e.data));
      port.addEventListener("message", handler);
      port.start();
      return () => port.removeEventListener("message", handler);
    },
  };
}
```

### Chrome Extension Port

```typescript
function extensionPortChannel(port: chrome.runtime.Port): Channel {
  return {
    send(data) {
      port.postMessage(Array.from(data));
    },
    receive(cb) {
      const handler = (msg: number[]) => cb(new Uint8Array(msg));
      port.onMessage.addListener(handler);
      return () => port.onMessage.removeListener(handler);
    },
  };
}
```

### BroadcastChannel

```typescript
function broadcastChannel(name: string): Channel {
  const bc = new BroadcastChannel(name);
  return {
    send(data) {
      bc.postMessage(data);
    },
    receive(cb) {
      const handler = (e: MessageEvent) => {
        if (e.data instanceof Uint8Array) cb(e.data);
      };
      bc.addEventListener("message", handler);
      return () => bc.removeEventListener("message", handler);
    },
  };
}
```

---

## Handshake Flow

```
┌────────┐                              ┌────────┐
│ Client │                              │ Server │
│  idle  │                              │waiting │
└───┬────┘                              └───┬────┘
    │                                       │
    │  api.foo() called (lazy trigger)      │
    │                                       │
    │  ── Phase 1: Hello ──────────────►    │
    │  [0x00, { pub, nonce, epoch }]        │
    │                                       │
    │  handshaking                     pending
    │                                       │
    │    ◄────────── Phase 2: Reply ──      │
    │    [0x00, { pub, proof, epoch }]      │
    │                                       │
    │  Client verifies proof (PSK check)    │
    │  Derives session key                  │
    │                                       │
    │  ready                           pending
    │                                       │
    │  ── Phase 3: First RPC ──────────►    │
    │  [0x01, encrypted({ t:1, id, p, i })]│
    │                                       │
    │                                  ready (confirmed)
    │                                       │
    │    ◄────────── RPC Response ──────    │
    │    [0x01, encrypted({ t:2, id, ok })] │
    │                                       │
    │  api.foo() resolves                   │
    └───────────────────────────────────────┘
```

The server only transitions to `ready` when it successfully decrypts the first message. This proves the client has the correct PSK without requiring an explicit auth message.

## State Machines

### Server States

```
              new hello
    ┌─────────────────────────────────────────┐
    │                                         │
    ▼           hello received         1st valid TAG_MSG
┌────────┐  ─────────────────►  ┌─────────┐  ──────────►  ┌───────┐
│waiting │                      │ pending │                │ ready │
└────────┘  ◄─────────────────  └─────────┘                └───────┘
                 timeout /                                     │
                 error                                         │
    ▲                                                          │
    │               new hello (client re-handshaking)          │
    └──────────────────────────────────────────────────────────┘

    Any state ──► [destroyed]  (explicit destroy() only)
```

### Client States

```
    ┌──────────────────────────────────────────────────┐
    │              timeout / send error                 │
    │              (auto-reset, epoch check)            │
    │                                                   │
    │  api call     hello sent        server reply OK   │
    ▼  ────────►                      ──────────────►   │
┌──────┐        ┌──────────────┐                    ┌───────┐
│ idle │        │ handshaking  │                    │ ready │
└──────┘        └──────────────┘                    └───────┘
    ▲                  │
    │    hs timeout /  │
    │    hs error      │
    └──────────────────┘

    Any state ──► [closed]  (explicit destroy() only)
```

## Auto-Retry Flow

When an RPC call fails (timeout or send error) while the session is established, the client automatically retries once with a fresh handshake:

```
Call A: api.foo("x")
  │
  ├─ sendRequest() ──► timeout! (server died)
  │
  ├─ catch block fires
  │   ├─ epoch === sentEpoch?  YES ──► reset() (zero keys, state → idle)
  │   ├─ ensureHandshake() ──► startHandshake() (epoch++)
  │   │   └─ new hello ──► server processes ──► reply ──► ready
  │   └─ sendRequest() again ──► success ──► api.foo() resolves
  │
  │
Call B: api.bar("y")  (was in-flight, still has its timer)
  │
  ├─ timer fires ──► timeout!
  │
  ├─ catch block fires
  │   ├─ epoch === sentEpoch?  NO (A already bumped it) ──► skip reset
  │   ├─ ensureHandshake() ──► shares A's handshake promise
  │   └─ sendRequest() again ──► success ──► api.bar() resolves
  │
  │
Call C: api.baz("z")  (still pending, server responds on old session)
  │
  ├─ server response arrives ──► decrypt with new key ──► poly1305 fails
  │   └─ silent drop
  ├─ timer fires ──► timeout!
  └─ same retry path as B
```

**Key rules:**

- `RemoteRPCError` (server responded) → throw directly, no retry
- `destroy()` was called → throw directly, no retry
- Only the first timed-out call resets; others ride the new handshake via epoch check
- Retry happens exactly once per call (no infinite loop)

## Re-Handshake on Ready Server

The server accepts new hello messages even when in `ready` state. This enables transparent session refresh:

```
Client (ready)         Server (ready)
    │                      │
    │  Session dies (timeout, transport hiccup)
    │                      │
    │  reset()             │
    │  state → idle        │
    │                      │
    │  ── new hello ──►    │
    │                      │  resetHandshake()
    │                      │  (zeros old session, fresh keys)
    │                      │  state → waiting → pending
    │                      │
    │  ◄── reply ────      │
    │                      │
    │  state → ready       │
    │                      │
    │  ── retry RPC ──►    │
    │                      │  state → ready (confirmed)
    │                      │
    │  ◄── response ──     │
    │                      │
    │  Call resolves ✓     │
```

## Security Model

### Threat Model

eRPC assumes the transport channel is **untrusted**. An attacker may:

- Read all messages (eavesdrop)
- Inject messages (forge)
- Replay captured messages
- Drop or reorder messages

eRPC does **not** protect against denial of service (attacker drops all messages).

### Protections

| Property            | Mechanism                                                   |
| ------------------- | ----------------------------------------------------------- |
| Confidentiality     | XSalsa20-Poly1305 AEAD per message                          |
| Authentication      | PSK mixed into HKDF key derivation                          |
| Server identity     | HMAC proof in handshake reply                               |
| Client identity     | Implicit — wrong PSK → invalid ciphertext                   |
| Forward secrecy     | Fresh ephemeral X25519 keys per session                     |
| Replay (handshake)  | Random nonce bound into HMAC proof                          |
| Replay (session)    | Random 24-byte nonces per message (probabilistic)           |
| Stale responses     | Epoch counter in hello/reply                                |
| Prototype pollution | `sanitize()` strips `__proto__`, `constructor`, `prototype` |
| Type confusion      | msgpack extension types disabled                            |

### What PSK Provides

The PSK is **never sent over the wire**. It's used as the HKDF salt, so even if an attacker observes the full X25519 exchange, they cannot derive the session key without knowing the PSK.

**PSK reuse across sessions is safe.** Each session uses fresh ephemeral X25519 keys. Different ephemeral keys → different raw shared secret → different session key (even with the same PSK salt).

### Note on Replay Within a Session

eRPC uses random nonces (not counters) for XSalsa20-Poly1305. With 24-byte (192-bit) random nonces, collision probability is negligible. However, a captured ciphertext **could** be replayed if the attacker can inject into the channel while the session is alive. The replayed message would decrypt and execute again on the server. For non-idempotent operations, consider adding application-level idempotency keys.

## Cleanup

Always call `destroy()` when done:

```typescript
const { destroy: destroyServer } = server(router, channel, { psk });
const { api, destroy: destroyClient } = client<typeof router>(channel, { psk });

// When shutting down:
destroyClient(); // Rejects all pending calls, zeros keys
destroyServer(); // Zeros keys, stops listening
```

After `destroy()`, all calls throw `RPCError("SESSION", "Session destroyed")`.

## Edge Runtime Compatibility

Both `server()` and `client()` return **synchronously**. No top-level `await` required. Pure JavaScript dependencies. Compatible with:

- Cloudflare Workers / Durable Objects
- Deno Deploy
- Vercel Edge Functions
- Service Workers
- React Native
- Node.js
- Browsers
