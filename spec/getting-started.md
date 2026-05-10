# Getting Started

Five minutes from `npm install` to encrypted, typed procedure calls. The shape is always the same: define a router, configure auth, attach a channel, call functions.

## Install

```bash
npm install @dotex/erpc
```

Peer dependency: a Zod-compatible schema library. eRPC uses `zod` for input/output validation in procedures.

## Define procedures

A procedure has an input schema, an output schema, and a handler. Each one is a chain that ends in `.handler()`.

```typescript
import { chain } from "@dotex/erpc";
import { z } from "zod";

const d = chain();

const router = {
  greet: d
    .input(z.object({ name: z.string() }))
    .output(z.object({ message: z.string() }))
    .handler(async ({ input }) => ({
      message: `Hello, ${input.name}!`,
    })),
};
```

The router is a plain object — keys are procedure names, values are procedures. It's shared between server and client as a **type**. The client infers the entire API surface from `typeof router` without ever importing the runtime code.

## Configure authentication

eRPC requires at least one authentication method. Choose based on your deployment.

### PSK (shared secret)

Both sides hold the same 32-byte key. Simplest and fastest.

```typescript
const sharedSecret = crypto.getRandomValues(new Uint8Array(32));

const auth = { psk: () => sharedSecret };
```

For better security, derive a fresh PSK from a per-session identifier:

```typescript
import { deriveSessionPSK } from "@dotex/erpc";

const auth = {
  psk: async () => {
    const sessionToken = await getCurrentSessionToken();
    const deviceSecret = await getDeviceSecret(); // 32+ bytes
    return deriveSessionPSK(sessionToken, deviceSecret);
  },
};
```

### Asymmetric (signatures)

For public clients or when device-level identity matters. The signer proves identity over the handshake transcript; the verifier rejects bad signatures.

```typescript
const auth = {
  sign: async (transcript) => signWithDeviceKey(transcript),
  verify: async (proof, transcript) => {
    await verifyPeerSignature(proof, transcript);
    return { auth: { deviceId: "device-123" } };
  },
};
```

### Both (defense-in-depth)

Combine them when you need both session binding and individual revocation.

```typescript
const auth = {
  psk: () => deriveSessionPSK(sessionId, deploymentSecret),
  sign: (transcript) => signWithDeviceKey(transcript),
  verify: (proof, transcript) => verifyPeerSignature(proof, transcript),
};
```

Full breakdown of trade-offs lives in [Security](security.md).

## Start the server

```typescript
import { server } from "@dotex/erpc";

const { destroy: destroyServer } = server(router, serverChannel, {
  auth,
  onError: console.error,
});
```

The server listens on a `Channel` — any bidirectional transport that can carry `Uint8Array`. See [Integrations](integrations.md) for ready-made adapters.

## Connect the client

```typescript
import { client } from "@dotex/erpc";

const { api, destroy: destroyClient } = client<typeof router>(clientChannel, {
  auth,
});
```

Construction is **synchronous**. The handshake is lazy — it runs on the first call, not when the client is created. This means no top-level `await`, which matters in edge runtimes.

## Make calls

```typescript
const result = await api.greet({ name: "World" });
console.log(result.message); // "Hello, World!"
```

That's all. Handshake, encryption, msgpack serialization, schema validation — handled. If the session drops, the client retries once with a fresh handshake. See [API: Auto-Retry](api.md).

## End-to-end example

PSK mode, in-memory channels, two procedures:

```typescript
import { chain, server, client } from "@dotex/erpc";
import { z } from "zod";

const d = chain();

const router = {
  greet: d
    .input(z.object({ name: z.string() }))
    .output(z.object({ message: z.string() }))
    .handler(async ({ input }) => ({
      message: `Hello, ${input.name}!`,
    })),

  add: d
    .input(z.object({ a: z.number(), b: z.number() }))
    .output(z.object({ sum: z.number() }))
    .handler(async ({ input }) => ({ sum: input.a + input.b })),
};

const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
const auth = { psk: () => sharedSecret };

const { destroy: destroyServer } = server(router, serverChannel, {
  auth,
  onError: console.error,
});

const { api, destroy: destroyClient } = client<typeof router>(clientChannel, {
  auth,
});

const greeting = await api.greet({ name: "World" });
const math = await api.add({ a: 2, b: 3 });

destroyClient();
destroyServer();
```

## Middleware and context

Middleware runs before the handler. It can extend the context that the handler sees. Chain middleware with `.use()`.

```typescript
import { chain, RPCError } from "@dotex/erpc";

const d = chain();

const authed = d.use(async ({ ctx, next }) => {
  const user = await getUser(ctx.token);
  if (!user) throw new RPCError("UNAUTHORIZED", "Bad token");
  return next({ user }); // merges { user } into ctx
});

const router = {
  getProfile: authed
    .input(z.object({ id: z.string() }))
    .handler(async ({ ctx, input }) => {
      // ctx.user is available, typed
      return db.getProfile(input.id);
    }),
};
```

Set the base context on the server. The factory is called per request, so the context is always fresh, and verified auth data is passed through:

```typescript
server(router, channel, {
  auth,
  context: ({ auth: verified }) => ({
    token: getCurrentToken(),
    userId: verified?.userId,
  }),
});
```

## Errors

Two error types:

- `RPCError` — local failure (timeout, session lost, validation error, handshake failure)
- `RemoteRPCError` — error returned from the remote peer (subclass of `RPCError`, carries `code`, `message`, `data`)

```typescript
import { RPCError, RemoteRPCError } from "@dotex/erpc";

try {
  const result = await api.greet({ name: "World" });
} catch (err) {
  if (err instanceof RemoteRPCError) {
    // The remote peer threw — code/message/data come from there
    if (err.code === "UNAUTHORIZED") await refreshCredentials();
  } else if (err instanceof RPCError) {
    // Local failure — timeout, network, handshake
    if (err.code === "HANDSHAKE") console.warn("auth mismatch?");
  } else {
    throw err;
  }
}
```

## When to pick which auth mode

**PSK** when you control both endpoints — server-to-server, internal services, parent ↔ iframe of the same origin. Fast (no signature ops). Simple.

**Asymmetric** when one side is untrusted or there is no shared secret — public web clients, mobile apps, IoT devices. Per-device revocation, no shared-secret distribution problem.

**Both** when you want session binding *and* per-device identity — regulated environments, high-value systems, anything where one secret is one too few.

## Next steps

- [Security](security.md) — threat model, handshake details, what each auth mode protects against
- [Integrations](integrations.md) — adapters for WebSocket, postMessage, MessagePort, Chrome extensions, BroadcastChannel, WebRTC, TCP, SSE
- [API](api.md) — full reference for `chain()`, `server()`, `client()`, and every option
- [Protocol](protocol.md) — wire format and key derivation, enough to port eRPC to another language
