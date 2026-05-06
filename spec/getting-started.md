# Getting Started

## Install

```bash
npm install @dotex/erpc
```

## Define Procedures

Procedures are the building blocks of your API. Each procedure has a typed input, a typed output, and a handler.

```typescript
import { chain } from "@dotex/erpc/common";
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

The `router` is a plain object where keys are procedure names and values are procedures. This object is shared between server and client as a type — the client infers the full API surface from it.

## Create a PSK

Both sides need a shared secret (pre-shared key). It must be at least 32 bytes.

```typescript
// Generate once, distribute to both sides securely
const psk = crypto.getRandomValues(new Uint8Array(32));
```

How you distribute the PSK is up to you — environment variables, config files, key management systems. The PSK never leaves the endpoints and is never sent over the wire. See [Security](security.md) for details on how the PSK is used in key derivation.

## Start the Server

```typescript
import { server } from "@dotex/erpc/server";

const { destroy: destroyServer } = server(router, serverChannel, {
  psk,
  onError: console.error,
});
```

The server listens on a `Channel` — any bidirectional transport. See [Integrations](integrations.md) for ready-made adapters (WebSocket, postMessage, MessagePort, etc.).

## Connect the Client

```typescript
import { client } from "@dotex/erpc/client";

const { api, destroy: destroyClient } = client<typeof router>(clientChannel, {
  psk,
});
```

The client creation is synchronous. The handshake is lazy — it runs automatically on the first call.

## Make Calls

```typescript
const result = await api.greet({ name: "World" });
console.log(result.message); // "Hello, World!"
```

That's it. The handshake, encryption, serialization, validation — all handled for you. If the session drops, the client [retries automatically](api.md).

## Full Example

```typescript
import { chain } from "@dotex/erpc/common";
import { server } from "@dotex/erpc/server";
import { client } from "@dotex/erpc/client";
import { z } from "zod";

// Procedures
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
    .handler(async ({ input }) => ({
      sum: input.a + input.b,
    })),
};

// PSK — both sides must know this
const psk = crypto.getRandomValues(new Uint8Array(32));

// Server side
const { destroy: destroyServer } = server(router, serverChannel, {
  psk,
  onError: console.error,
});

// Client side
const { api, destroy: destroyClient } = client<typeof router>(clientChannel, {
  psk,
});

// Use the API — fully typed, fully encrypted
const greeting = await api.greet({ name: "World" });
const math = await api.add({ a: 2, b: 3 });

// Cleanup when done
destroyClient();
destroyServer();
```

For the full list of options available to `server()` and `client()`, see the [API Reference](api.md). To add authentication or other pre-handler logic, check out [middleware](api.md).
