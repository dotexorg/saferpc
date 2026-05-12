# eRPC

[![npm](https://img.shields.io/npm/v/@dotex/erpc.svg)](https://www.npmjs.com/package/@dotex/erpc)
[![license](https://img.shields.io/npm/l/@dotex/erpc.svg)](./LICENSE)
[![types](https://img.shields.io/badge/types-TypeScript-blue.svg)](https://www.typescriptlang.org/)

**Encrypted, typed RPC over any bidirectional channel.** Two peers, one shared secret (or one keypair), every call end-to-end encrypted with XSalsa20-Poly1305 AEAD. WebSocket, `postMessage`, `MessagePort`, `chrome.runtime`, `BroadcastChannel`, WebRTC — if it can carry bytes, eRPC encrypts and types them.

Think tRPC, but transport-agnostic and encrypted by default.

```bash
npm install @dotex/erpc
```

![eRPC](erpc.png)

---

- **Full docs:** <https://dotex.org/epic/erpc>
- [Quickstart](./spec/getting-started.md) · [API](./spec/api.md) · [Wire Protocol](./spec/protocol.md) · [Security](./spec/security.md) · [Transports](./spec/integrations.md)

---

## Why eRPC

|  | tRPC | eRPC |
|---|---|---|
| **Transport** | HTTP (mostly) | Anything that carries bytes |
| **Encryption** | TLS at the edge | End-to-end, every message |
| **Roles** | Server / client | Peer / peer (either side can serve) |
| **Edge runtimes** | Mostly | Yes (synchronous init, no top-level `await`) |
| **Auth** | App-level (middleware) | Built into the handshake |

eRPC is designed for the cases tRPC wasn't:

- Browser extensions (content script ↔ background ↔ popup)
- iframes embedding third-party code over `postMessage`
- Workers and SharedWorkers over `MessagePort`
- Edge-to-edge services over WebSocket
- Tab coordination over `BroadcastChannel`
- Peer-to-peer WebRTC data channels

## Features

- **Typed procedures** with Zod input/output validation
- **End-to-end encryption** — X25519 ECDH, XSalsa20-Poly1305 AEAD, HKDF-SHA-256, forward secrecy
- **Lazy handshake** on first call, transparent auto-retry on session drop
- **Three auth modes** — PSK, asymmetric (Ed25519 / ECDSA / JWT / cert / multifactor), or both for defense-in-depth
- **All built-in auth helpers are transcript-bound** — captured payloads cannot be replayed into a new handshake
- **Synchronous** `client()` / `server()` — works in Node.js, browsers, Service Workers, React Native, Vercel Edge, Cloudflare Workers, Deno Deploy.
- **Tiny surface** — `@noble/*` crypto, `@msgpack/msgpack`, `zod` and nothing else
- **Pure ESM + CJS dual build**, side-effect-free, tree-shakeable

## Quick start

```typescript
import { chain, server, client } from "@dotex/erpc";
import { z } from "zod";

// 1. Define your router
const d = chain();

const router = {
  greet: d
    .input(z.object({ name: z.string() }))
    .output(z.object({ message: z.string() }))
    .handler(async ({ input }) => ({
      message: `Hello, ${input.name}!`,
    })),
};

// 2. Shared secret (32 bytes)
const psk = crypto.getRandomValues(new Uint8Array(32));
const auth = { psk: () => psk };

// 3. Server (attach to any Channel)
const { destroy: stopServer } = server(router, serverChannel, {
  auth,
  onError: console.error,
});

// 4. Client (typed from the router)
const { api, destroy: stopClient } = client<typeof router>(clientChannel, {
  auth,
});

// 5. Call. Handshake, encryption, validation — all automatic.
const { message } = await api.greet({ name: "World" });
console.log(message); // "Hello, World!"
```

`client()` and `server()` are **synchronous** — no top-level `await`. The handshake happens lazily on the first procedure call. If the session drops, the next call retries once with a fresh handshake.

## Channel — the only transport contract

```typescript
interface Channel {
  send(data: Uint8Array): void | Promise<void>;
  receive(cb: (data: Uint8Array) => void): () => void; // returns unsubscribe
}
```

Anything that satisfies this can host an eRPC session. A minimal WebSocket adapter:

```typescript
function wsChannel(ws: WebSocket): Channel {
  return {
    send: (data) => ws.send(data),
    receive: (cb) => {
      const h = (e: MessageEvent) => {
        if (e.data instanceof ArrayBuffer) cb(new Uint8Array(e.data));
      };
      ws.addEventListener("message", h);
      return () => ws.removeEventListener("message", h);
    },
  };
}
```

Ready-made adapters for WebSocket, postMessage, MessagePort, Chrome extension ports, BroadcastChannel, WebRTC, TCP, and SSE: [spec/integrations.md](./spec/integrations.md).

## Authentication

Three modes, all configured through the same `auth` block.

```typescript
// PSK only — simple, fast, controlled environments
auth: { psk: () => sharedSecret }

// Asymmetric only — public clients, no shared secrets
auth: {
  sign: (transcript) => signWithDeviceKey(transcript),
  verify: (proof, transcript) => verifyPeerSignature(proof, transcript),
}

// Both — defense-in-depth (session binding + identity proof)
auth: {
  psk: () => deriveSessionPSK(sessionId, deploymentSecret),
  sign: (transcript) => signWithDeviceKey(transcript),
  verify: (proof, transcript) => verifyPeerSignature(proof, transcript),
}
```

Ready-made helpers ship for Ed25519, ECDSA P-256, JWT, certificate-based, and multifactor auth. See [spec/security.md](./spec/security.md) for the threat model, transcript format, and the trade-offs between each mode.

## Errors

```typescript
import { RPCError, RemoteRPCError } from "@dotex/erpc";

try {
  await api.greet({ name: "World" });
} catch (err) {
  if (err instanceof RemoteRPCError) {
    // The remote peer threw — err.code / err.message / err.data come from there
  } else if (err instanceof RPCError) {
    // Local failure — TIMEOUT, SESSION, HANDSHAKE, INPUT_VALIDATION, ...
  } else {
    throw err;
  }
}
```

## Package layout

```
src/
  common.ts       — Shared types, crypto, msgpack, chain builder
  server.ts       — Resilient handshake server
  client.ts       — Lazy handshake client with auto-retry
  auth.ts         — Re-exports for auth helpers
  authClient.ts   — Ed25519, ECDSA, JWT client helpers
  authServer.ts   — Ed25519, ECDSA, JWT, certificate, multifactor server helpers
  index.ts        — Public entry point
```

Importing:

```typescript
import { chain, server, client, RPCError } from "@dotex/erpc";
// Subpaths also available for tree-shaking:
import { server } from "@dotex/erpc/server";
import { client } from "@dotex/erpc/client";
import { chain, RPCError } from "@dotex/erpc/common";
```

## Compatibility

- **Node.js** 18+
- **Modern browsers** (WebCrypto required only for the ECDSA/cert helpers)
- **Service Workers**, **Web Workers**, **SharedWorkers**
- **React Native**
- **Vercel Edge**, **Cloudflare Workers**, **Deno Deploy**

## Project status

eRPC is at `0.x` and has a stable wire protocol (`drpc-v1` HKDF info, `erpc-hs-{hello,reply}-v1` transcript prefixes). Test coverage exists for handshake attacks, replay, tampering, type confusion, prototype pollution, middleware misuse, and DoS limits — see `test/security/`.

A 1.0 release will lock the public API surface.

## License

MIT © [Dotex](https://dotex.org/about)
