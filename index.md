# Encrypted RPC (eRPC)

<!-- NAV
- [Encrypted RPC](index.md)
- [Getting Started](spec/getting-started.md)
- [Security](spec/security.md)
- [Integrations](spec/integrations.md)
- [API](spec/api.md)
-->

Just two peers talking securely. Define your API as typed procedures - and every call is end-to-end encrypted. No TLS termination. No certificates. No API keys. No auth middleware.

![eRPC](erpc.png)

eRPC is an encrypted RPC library for any two counterparties over any bidirectional channel. WebSocket, postMessage, MessagePort, chrome.runtime, BroadcastChannel - if it can carry bytes, eRPC encrypts and types them. The handshake happens on the first call, transparently. Session drops are recovered automatically. Your code just calls functions.

Think tRPC, but transport-agnostic and encrypted by default. No HTTP assumption. No server/client hierarchy. An iframe can serve procedures to its parent. A service worker can be the server. A browser tab can call into an extension's background script. Both sides are equal — both can expose and call procedures.

## Language Support

The current implementation is in **TypeScript/JavaScript** and runs on any JS runtime:

- Node.js
- Browsers
- Service Workers
- Vercel Edge
- Deno Deploy
- Cloudflare Workers
- React Native

The protocol itself is language-agnostic — it uses msgpack for serialization and standard cryptographic primitives (X25519, XSalsa20-Poly1305, HKDF, HMAC). Implementations in other languages (Rust, Go, С++) are welcome. If you're interested in contributing a port, check the [Security](security.md) page for the full handshake spec and message format.

## Why RPC Over REST

If you've used [tRPC](https://trpc.io), you already know how much better typed RPC is compared to REST for inter-service and client-server communication. No more URL strings, no manual serialization, no OpenAPI schemas to keep in sync. You define a procedure, and both sides get full type safety — the compiler catches mismatches, not your users.

eRPC takes the same approach but goes further:

- **Transport-agnostic.** tRPC is built around HTTP. eRPC works over any bidirectional channel — WebSockets, postMessage, MessagePorts, Chrome extension ports, BroadcastChannel, or [anything custom](integrations.md). This makes it the natural choice when your counterparties aren't just "frontend and backend talking over HTTP."
- **Encrypted by default.** Every message is end-to-end encrypted. You don't need TLS termination, mTLS setup, or API keys. A single [pre-shared key](security.md) is all it takes.
- **Works peer-to-peer.** There's no assumption about who is the "server" and who is the "client" in a traditional sense. An iframe can serve procedures to its parent. A service worker can be the server. A browser extension popup can call into a content script.

## Use Cases

**Browser extension internals.** Content scripts, background workers, popups, and sidepanels need to talk to each other — but `chrome.runtime.sendMessage` gives you untyped JSON with no contracts. eRPC gives you a typed, encrypted API between all extension components.

**iframe sandboxing.** You embed a third-party widget or a sandboxed module in an iframe. You need a clean API boundary with postMessage as the transport. eRPC turns that into typed procedure calls with encryption — no more hand-parsing `MessageEvent.data`.

**Worker communication.** Web Workers, SharedWorkers, and Service Workers communicate through MessagePorts. eRPC provides a structured, validated API layer over these ports instead of ad-hoc message passing.

**Microservices over WebSocket.** When two services need a persistent bidirectional connection, REST falls apart. eRPC over WebSocket gives you typed calls in both directions with built-in encryption — no API gateway, no TLS termination proxy.

**Electron / Tauri IPC.** Main process and renderer need a secure communication channel. eRPC works over any IPC mechanism that can carry binary data.

**Edge-to-edge.** Two Cloudflare Workers, two Deno Deploy isolates, or any combination of edge runtimes can talk to each other with eRPC over WebSocket — encrypted, typed, with auto-retry.

## How It Works

1. Both sides share a pre-shared key (PSK)
2. On the first call, a [handshake](security.md) runs automatically — ephemeral X25519 keys are exchanged, and a session key is derived using the PSK as HKDF salt
3. The server proves it knows the PSK via an HMAC proof; the client proves it implicitly by encrypting valid messages
4. All calls are encrypted with XSalsa20-Poly1305 AEAD using the session key
5. If the session drops, the client [resets and re-handshakes transparently](api.md) — your call retries once automatically

No certificates. No token refresh. No auth middleware. Just a shared secret and a channel. See the [Getting Started](getting-started.md) guide to set it up in under 5 minutes.
