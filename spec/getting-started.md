# Getting started

Install, define a router, configure auth, attach a channel, call functions.

## Install

```bash
npm install @dotex/saferpc
```

The only peer dependency is `zod` (or any library exposing `.safeParse()`).

## Define a router

One file, shared between server and client as a **type**. The client never imports the handler code.

```typescript
// router.ts
import { saferpc } from "@dotex/saferpc";
import { z } from "zod";

// Bind the handler context type once. `rpc` IS the procedure builder;
// `rpc.router` / `rpc.middleware` hang off the same instance.
export interface Context {
  user: { id: string } | null;
}
export const rpc = saferpc<Context>();

const greet = rpc
  .input(z.object({ name: z.string() }))
  .output(z.object({ message: z.string() }))
  .handler(async ({ ctx, input }) => ({
    message: `Hello, ${ctx.user?.id ?? input.name}!`,
  }));

export const appRouter = rpc.router({ greet });
export type AppRouter = typeof appRouter;
```

Because `rpc` carries `Context`, you can move procedures into their own files
(`import { rpc }` and keep chaining) and `ctx` stays fully typed.

## Quick start: Node server, browser client over WebSocket

Generate a 32-byte secret once and paste the same bytes on both sides:

```typescript
crypto.getRandomValues(new Uint8Array(32)); // run once, store the result
```

### Server (Node.js, `ws` package)

```typescript
// server.ts
import { server, type Channel } from "@dotex/saferpc";
import { WebSocketServer, type WebSocket } from "ws";
import { appRouter } from "./router.js";

const secret = new Uint8Array([/* 32 bytes from your generator */]);

function wsChannel(ws: WebSocket): Channel {
  return {
    send(data) {
      ws.send(data);
    },
    receive(cb) {
      const handler = (data: Buffer) => cb(new Uint8Array(data));
      ws.on("message", handler);
      return () => ws.off("message", handler);
    },
  };
}

const wss = new WebSocketServer({ port: 8080 });

wss.on("connection", (ws) => {
  const { destroy } = server(appRouter, wsChannel(ws), {
    auth: { secret: () => secret },
    context: () => ({ user: null }),
    onError: console.error,
  });
  ws.on("close", destroy);
});
```

### Client (browser)

```typescript
// app.ts
import { client, type Channel } from "@dotex/saferpc";
import type { AppRouter } from "./router";

const secret = new Uint8Array([/* same 32 bytes as the server */]);

function wsChannel(url: string): Channel {
  const ws = new WebSocket(url);
  ws.binaryType = "arraybuffer";
  
  const ready = new Promise<void>((resolve) =>
    ws.addEventListener("open", () => resolve(), { once: true }),
  );
  
  return {
    async send(data) {
      await ready;
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

const { api } = client<AppRouter>(wsChannel("ws://localhost:8080"), {
  auth: { secret: () => secret },
});

const { message } = await api.greet({ name: "World" });
console.log(message); // "Hello, World!"
```

That is the whole loop. The handshake runs on the first call, every payload is XSalsa20-Poly1305 AEAD over the WS, and the client retries once if the session drops.

## What just happened

1. `client()` and `server()` returned synchronously. No top-level `await` for the library itself.
2. On `api.greet(...)`, the client sent a `TAG_HELLO` frame and the server replied with its own.
3. Both sides derived the same session key from the secret + a fresh ECDH exchange.
4. The actual call payload went encrypted, with schema validation on both ends.
5. If the WS reconnects later, the next call re-handshakes transparently.

## Error handling

Two error classes:

- `RPCError`: local failure (timeout, session lost, validation error, handshake failure).
- `RemoteRPCError`: error returned from the remote peer (`code`, `message`, `data`).

```typescript
import { RPCError, RemoteRPCError } from "@dotex/saferpc";

try {
  await api.greet({ name: "World" });
} catch (err) {
  if (err instanceof RemoteRPCError) {
    if (err.code === "UNAUTHORIZED") await refreshCredentials();
  } else if (err instanceof RPCError) {
    if (err.code === "HANDSHAKE") console.warn("auth mismatch?");
  } else {
    throw err;
  }
}
```

## Middleware and context

Middleware runs before the handler and extends the context. Whatever you
pass to `next({ ... })` is merged into `ctx` **and its type is inferred** for
every downstream step. Author reusable middleware with `middleware(...)` or
inline it with `.use()`:

```typescript
import { RPCError } from "@dotex/saferpc";
import { rpc } from "./router.js";
import { z } from "zod";

// Reusable, and typed against the app's Context. Narrows `user` to non-null.
const authed = rpc.middleware(async ({ ctx, next }) => {
  if (ctx.user === null) throw new RPCError("UNAUTHORIZED", "Login required");
  return next({ user: ctx.user }); // downstream ctx.user is now non-null
});

const getProfile = rpc
  .use(authed)
  .input(z.object({ id: z.string() }))
  .handler(async ({ ctx, input }) => {
    // ctx.user is { id: string } here — no null check, no cast
    return db.getProfile(ctx.user.id, input.id);
  });

export const appRouter = rpc.router({ getProfile });
```

The base context comes from the server. The factory runs per request, so the context is always fresh:

```typescript
server(appRouter, channel, {
  auth,
  context: ({ auth: verified }) => ({
    user: verified ? { id: verified.userId } : null,
  }),
});
```

---

## Advanced auth

A pre-shared secret is enough for the fast start. For public clients, per-device identity, or defense-in-depth, Safe RPC ships three more configurations.

### Derived session secret

Bind the secret to a per-session identifier instead of a single static key:

```typescript
import { deriveSessionSecret } from "@dotex/saferpc";

const auth = {
  secret: async () => {
    const sessionToken = await getCurrentSessionToken();
    const deviceSecret = await getDeviceSecret(); // 32+ bytes
    return deriveSessionSecret(sessionToken, deviceSecret);
  },
};
```

### Asymmetric signatures

For public clients or device-level identity. The signer proves identity over the handshake transcript. The verifier rejects bad signatures.

```typescript
const auth = {
  sign: async (transcript) => signWithDeviceKey(transcript),
  verify: async (proof, transcript) => {
    await verifyPeerSignature(proof, transcript);
    return { auth: { deviceId: "device-123" } };
  },
};
```

Or use the built-in Ed25519 helpers:

```typescript
import {
  createEd25519ClientAuth,
  createEd25519ServerAuth,
} from "@dotex/saferpc";

// Client
const auth = createEd25519ClientAuth({ privateKey, deviceId: "device-123" });

// Server
const auth = createEd25519ServerAuth({
  getPublicKey: async (deviceId) => loadDevicePub(deviceId),
});
```

All built-in helpers (Ed25519, ECDSA, JWT, certificate, multifactor) bind their proof to the canonical handshake transcript. See [Security → Built-in signature helpers](security.md#built-in-signature-helpers).

### Both (defense-in-depth)

Combine a pre-shared secret and asymmetric when you need session binding *and* individual revocation.

```typescript
const auth = {
  secret: () => deriveSessionSecret(sessionId, deploymentSecret),
  sign: (transcript) => signWithDeviceKey(transcript),
  verify: (proof, transcript) => verifyPeerSignature(proof, transcript),
};
```

### Choosing an auth mode

**Secret** when you control both endpoints: server-to-server, internal services, parent ↔ iframe of the same origin. No signature ops on the hot path.

**Asymmetric** when one side is untrusted or there is no shared secret: public web clients, mobile apps, IoT devices. Per-device revocation.

**Both** when you want session binding *and* per-device identity: regulated environments, high-value systems.

The full trade-off breakdown lives in [Security](security.md).

## Next steps

- [Security](security.md): threat model, handshake details, what each auth mode protects against
- [Integrations](integrations.md): adapters for WebSocket, postMessage, MessagePort, Chrome extensions, BroadcastChannel, WebRTC, TCP, SSE
- [API](api.md): full reference for `saferpc()`, `server()`, `client()`, and every option
- [Protocol](protocol.md): wire format and key derivation, enough to port Safe RPC to another language
