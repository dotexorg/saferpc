# Encrypted RPC

<!-- NAV
## Intro
- [Encrypted RPC](index.md)

## Start
- [Getting Started](spec/getting-started.md)

## Deep Dive
- [Security](spec/security.md)
- [Integrations](spec/integrations.md)

## Reference
- [API](spec/api.md)
- [Protocol](spec/protocol.md)
-->

Two peers, one shared secret. Define your API as typed procedures — every call is end-to-end encrypted. Do not rely on TLS or other transport layers.

![eRPC](erpc.png)

## What it is

eRPC is an encrypted, typed RPC library for any two counterparties over any bidirectional channel. WebSocket, postMessage, MessagePort, `chrome.runtime`, BroadcastChannel — if it can carry bytes, eRPC encrypts and types them.

The handshake runs transparently on the first call. Session drops recover themselves. Your code just calls functions.

Think tRPC, but transport-agnostic and encrypted by default. A browser tab can call into an extension's background script. Both sides are equal — both can expose and call procedures.

## Core ideas

- **Transport-agnostic.** eRPC works over any bidirectional channel — WebSockets, `postMessage`, MessagePorts, extension ports, BroadcastChannel, or anything custom. tRPC assumes HTTP. eRPC does not.
- **Encrypted by default.** Every message is end-to-end encrypted with XSalsa20-Poly1305. No TLS termination, no mTLS, no API keys. A single pre-shared key is enough.
- **Peer-to-peer.** There is no built-in "server" and "client." An iframe can serve procedures to its parent. A service worker can be the server. Roles are assigned by your code, not the protocol.
- **Lazy handshake.** Construction is synchronous. The handshake runs on the first RPC call, so there is no top-level `await` and no initialization ceremony in edge runtimes.

## How it works

1. Both sides share a pre-shared key (PSK) or verify each other's signatures.
2. On the first call, a handshake runs automatically. Ephemeral X25519 keys are exchanged and a session key is derived using the PSK as HKDF salt.
3. The server proves it knows the PSK with an HMAC over the transcript. The client proves it implicitly by producing valid ciphertext.
4. All calls are encrypted with XSalsa20-Poly1305 AEAD under the session key.
5. If the session drops, the client resets and re-handshakes transparently — your call retries once.

No certificates. No token refresh. No auth middleware. A shared secret and a channel.

See the [Getting Started](spec/getting-started.md) guide to set it up in under five minutes.

## When to use it

**Browser extension internals.** Content scripts, background workers, popups, and sidepanels — `chrome.runtime.sendMessage` gives untyped JSON with no contracts. eRPC gives a typed, encrypted API between all extension components.

**iframe sandboxing.** Embed a third-party widget or sandboxed module. eRPC turns `postMessage` into typed procedure calls with encryption — no hand-parsing `MessageEvent.data`.

**Worker communication.** Web Workers, SharedWorkers, and Service Workers communicate through MessagePorts. eRPC provides a structured, validated API layer instead of ad-hoc message passing.

**Microservices over WebSocket.** Two services need a persistent bidirectional connection. REST falls apart. eRPC over WebSocket gives typed calls in both directions, encrypted, with auto-retry — no API gateway, no TLS proxy.

**Electron / Tauri IPC.** Main process and renderer need a secure channel. eRPC works over any IPC mechanism that can carry binary data.

**Edge-to-edge.** Two Cloudflare Workers, two Deno Deploy isolates, any combination of edge runtimes. WebSocket between them, eRPC on top. Encrypted, typed, auto-retry.

## Platform support

The reference implementation is **TypeScript/JavaScript** and runs anywhere JS runs:

- Node.js
- Browsers
- Service Workers
- Cloudflare Workers
- Vercel Edge
- Deno Deploy
- React Native

The protocol is language-agnostic. It uses msgpack for serialization and standard primitives (X25519, XSalsa20-Poly1305, HKDF-SHA-256, HMAC-SHA-256). Implementations in Rust, Go, C++, or anything else are welcome — the [Protocol](spec/protocol.md) page is the contract.
