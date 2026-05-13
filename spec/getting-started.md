# Getting Started

Five minutes from `npm install` to encrypted, typed procedure calls. The shape never changes: define a router, configure auth, attach a channel, call functions.

## Install

```bash
npm install @dotex/erpc
```

Peer dependency: a Zod-compatible schema library. eRPC validates procedure input and output through `zod`.

## Define procedures

A procedure has an input schema, an output schema, and a handler. Build one with `chain()`:

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

The router is a plain object. Keys are procedure names, values are procedures. Share it between server and client as a **type** — the client infers the whole API surface from `typeof router` and never imports the runtime code.

## Configure authentication

eRPC requires at least one authentication method.

### PSK (shared secret)

Both sides hold the same 32-byte key. Cheapest mode, no signature ops on the hot path.

```typescript
const sharedSecret = crypto.getRandomValues(new Uint8Array(32));

const auth = { psk: () => sharedSecret };
```

`psk()` may return the same `Uint8Array` across calls. eRPC reads it and never mutates the buffer. Lifecycle stays with you: zero it yourself if the secret should disappear from memory.

A single static PSK works, but a per-session derivation is harder to misuse — leaked traffic only compromises one session, not every past or future one:

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

For public clients, or when device-level identity matters. The signer proves identity over the handshake transcript; the verifier rejects bad signatures.

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
} from "@dotex/erpc";

// Client
const auth = createEd25519ClientAuth({ privateKey, deviceId: "device-123" });

// Server
const auth = createEd25519ServerAuth({
  getPublicKey: async (deviceId) => loadDevicePub(deviceId),
});
```

All built-in helpers (Ed25519, ECDSA, JWT, certificate, multifactor) bind their proof to the canonical handshake transcript. See [Security → Built-in signature helpers](security.md#built-in-signature-helpers).

### Both (defense-in-depth)

Combine them when you need session binding and per-key revocation at the same time.

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

The server listens on a `Channel`: any bidirectional transport that can carry `Uint8Array`. Ready-made adapters live in [Integrations](integrations.md).

## Connect the client

```typescript
import { client } from "@dotex/erpc";

const { api, destroy: destroyClient } = client<typeof router>(clientChannel, {
  auth,
});
```

Construction is **synchronous**. The handshake is lazy: it runs on the first call, not when the client is created. No top-level `await`.

## Make calls

```typescript
const result = await api.greet({ name: "World" });
console.log(result.message); // "Hello, World!"
```

Handshake, encryption, msgpack serialization, schema validation — all handled internally. If the session drops, the client retries once with a fresh handshake. See [API: Auto-Retry](api.md).

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

Middleware runs before the handler. It can extend the context that the handler receives. Chain middleware with `.use()`:

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

Set the base context on the server. The factory is called per request, so the context is always fresh:

```typescript
server(router, channel, {
  auth,
  context: ({ auth: verified }) => ({
    token: getCurrentToken(),
    userId: verified?.userId,
  }),
});
```

## Error handling

Two error types, and the distinction matters because they imply different recovery paths.

- `RPCError` — local failure: timeout, session lost, validation error, handshake failure. Worth retrying or surfacing as a transient problem.
- `RemoteRPCError` — the remote peer's handler threw. Carries `code`, `message`, `data`. The other side is alive and made a deliberate decision.

```typescript
import { RPCError, RemoteRPCError } from "@dotex/erpc";

try {
  const result = await api.greet({ name: "World" });
} catch (err) {
  if (err instanceof RemoteRPCError) {
    // The remote peer threw
    if (err.code === "UNAUTHORIZED") await refreshCredentials();
  } else if (err instanceof RPCError) {
    // Local failure — timeout, network, handshake
    if (err.code === "HANDSHAKE") console.warn("auth mismatch?");
  } else {
    throw err;
  }
}
```

## Choosing an auth mode

PSK fits when you control both endpoints: server-to-server, internal services, an iframe talking to its parent on the same origin. No signature work per handshake.

Asymmetric fits when one side is untrusted or there is no safe place to put a shared secret: public browser clients, mobile apps, IoT devices. Each key revokes independently.

Use both when you need session binding *and* per-device identity. Regulated environments, high-value systems. An attacker now has to compromise the derivation secret *and* a device key, and forward secrecy still protects past traffic if either leaks.

## Next steps

- [Security](security.md) — threat model, handshake details, what each auth mode protects against
- [Integrations](integrations.md) — adapters for WebSocket, postMessage, MessagePort, Chrome extensions, BroadcastChannel, WebRTC, TCP, SSE
- [API](api.md) — full reference for `chain()`, `server()`, `client()`, and every option
- [Protocol](protocol.md) — wire format and key derivation, enough to port eRPC to another language
