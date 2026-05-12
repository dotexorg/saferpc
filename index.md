# Encrypted RPC

<!-- NAV
## Overview
- [Encrypted RPC](index.md)

## Get Started
- [Quickstart](spec/getting-started.md)

## Concepts
- [Security & Auth](spec/security.md)
- [Transports & Integrations](spec/integrations.md)

## Reference
- [API](spec/api.md)
- [Wire Protocol](spec/protocol.md)
-->

Just two peers talking securely. Define your API as typed procedures - every call is end-to-end encrypted. No TLS, no transport-layer trust. Either peer can serve and call on the same channel.

![eRPC](erpc.png)

## What it is

eRPC is an encrypted, typed RPC library for any two counterparties over any bidirectional channel. WebSocket, postMessage, MessagePort, `chrome.runtime`, BroadcastChannel, WebRTC — if it can carry bytes, eRPC encrypts and types them.

The handshake runs transparently on the first call. Session drops recover themselves. Your code just calls functions.

Think tRPC, but transport-agnostic and encrypted by default. A browser tab can call into an extension's background script. Both sides are equal — both can expose and call procedures.

## Why eRPC

Most RPC libraries assume the world is a browser talking to an HTTP server behind TLS. That assumption breaks the moment your code lives anywhere else: a content script talking to a background worker, an iframe embedding third-party code, two tabs coordinating over a `BroadcastChannel`, an extension calling a native messaging host, a WebRTC data channel between peers that never touch a server, a Service Worker proxying for an offline app.

In each of those cases the usual path is `postMessage` (or a cousin), a string-keyed protocol defined by hand, a `switch` statement, custom request IDs, input that isn't validated, errors that leak stack traces, and a working result that holds until it doesn't. eRPC is the version of that code you actually wanted to write.

You define a router. You hand it a `Channel`. You get a typed, validated, authenticated, encrypted API on the other side.

```typescript
const { api } = client<typeof router>(channel, { auth });
await api.greet({ name: "World" });
```

No HTTP. No JSON. No middleware stack. Encryption is the default because the design starts there.

## What problems it solves

**The trusted-transport assumption.** TLS protects the wire between two specific endpoints. Once a message hits a proxy, a service worker, a content script, or a postMessage bridge, TLS is gone and the payload is plaintext to anyone in that hop. eRPC encrypts payloads at the *application* layer, so it does not matter how many hops sit between the two peers — only the two endpoints can read anything.

**The handwritten message bus.** Every team that ships a browser extension or an iframe-embedded widget eventually grows its own RPC layer: a request-id map, a `Promise` registry, a timeout sweeper, an error-coercion path, type definitions kept in sync by hand. eRPC is that code, written once.

**Peer-to-peer that isn't bolted on.** WebRTC and `BroadcastChannel` have no notion of "server." Most RPC libraries do. eRPC's roles are symmetric — either side can serve, either side can call, both at the same time on the same channel.

**Encryption and auth are part of the protocol, not the application.** In most RPC setups, security is something you add on top — a JWT check in middleware, a TLS certificate managed by your infra, an API key passed in a header. These are all application-layer conventions that can be misconfigured, skipped, or bypassed. eRPC builds authentication directly into the handshake and encrypts every message as a protocol primitive. There is no way to make a call before identity is established, and there is no message that travels in plaintext. You cannot accidentally ship an unauthenticated endpoint or forget to enable encryption for a specific route — it is on by default for every call on every channel.

## Core ideas

- **Transport-agnostic.** Any bidirectional channel — WebSockets, `postMessage`, MessagePorts, extension ports, BroadcastChannel, WebRTC, or custom. tRPC assumes HTTP. eRPC does not.
- **Encrypted by default.** Every message is end-to-end encrypted with XSalsa20-Poly1305. No TLS termination, no mTLS, no API keys. A single pre-shared key is enough.
- **Peer-to-peer.** No built-in server or client. An iframe can serve procedures to its parent. A service worker can be the server. Roles are assigned by your code, not the protocol.
- **Auth in the handshake, not middleware.** Identity is proven before any procedure runs. If a peer cannot authenticate, it gets no session — there is no parsed request to bypass.

## How it works

1. Both sides share a pre-shared key (PSK) or verify each other's signatures.
2. On the first call, a handshake runs automatically. Ephemeral X25519 keys are exchanged and a session key is derived using the PSK as HKDF salt.
3. The server proves it knows the PSK with an HMAC over the transcript. The client proves it implicitly by producing valid ciphertext.
4. All calls are encrypted with XSalsa20-Poly1305 AEAD under the session key.
5. If the session drops, the client resets and re-handshakes transparently — your call retries once.

No certificates. No token refresh. No auth middleware. A shared secret and a channel.

See the [Getting Started](spec/getting-started.md) guide to set it up in under five minutes.

## eRPC vs tRPC (and its plugin ecosystem)

tRPC is excellent. It solved type-safe RPC for the HTTP world, and for a Next.js app calling its own backend, tRPC is the right answer. eRPC is for the cases tRPC's HTTP assumption rules out.

|  | tRPC (+ plugins) | eRPC |
|---|---|---|
| **Transport** | HTTP, WebSocket via adapter | Any bidirectional byte channel — same API |
| **Encryption** | TLS at the edge; plaintext after that | E2E AEAD on every message, every hop |
| **Roles** | Server / client (asymmetric) | Peer / peer — either side can serve |
| **Auth** | `trpc-shield`, middleware per-procedure, enforced after parse | Bound to the handshake — no session, no calls |
| **Edge runtimes** | Mostly works; init can be async | Synchronous init, no top-level `await` |
| **Browser extension** | Possible with a custom link and plugins | Drop-in: content script ↔ background ↔ popup |
| **WebRTC / iframes** | Not the target use case | First-class |
| **Dependencies** | Adapters per transport, plugins per concern | One package: `@noble/*`, `@msgpack/msgpack`, `zod` |
| **Wire format** | JSON | msgpack inside an AEAD envelope |

The plugin route works, but it stacks: `@trpc/server` + `@trpc/client` + a WebSocket link + a custom transformer + `trpc-shield` for auth + a logger + a rate limiter + something to encrypt the payload (which does not exist as a polished plugin, so you write it). Each plugin has its own release cadence and its own opinions. eRPC ships the whole thing as one surface because it is the same problem viewed from a different angle.

## Why encryption matters

"It's HTTPS, it's encrypted" is true and also insufficient in the contexts eRPC targets.

**Browser extensions.** Other extensions installed in the same browser can `postMessage` into shared windows, observe `chrome.runtime` traffic with the right permission, and inject scripts into pages you also touch. A leaky or compromised extension in the same profile is a real adversary. AEAD on every message means the other extension can see bytes but not contents.

**Embedded iframes.** Stripe, Plaid, an SSO provider, an analytics SDK — every iframe you embed gets a `window.postMessage` channel. The parent page, every script the parent runs, and every browser extension watching that window can read those messages. Sending session tokens, personal data, or financial detail across that boundary in plaintext means publishing it to the entire client environment.

**WebRTC peer-to-peer.** STUN/TURN relays see your traffic. Signaling servers see your traffic. DTLS protects the transport but not your application semantics from a malicious peer or a misconfigured TURN. Application-layer AEAD plus an authenticated handshake means a peer outside your trust model can connect but cannot make a single valid call.

**Shared workers and BroadcastChannel.** Any same-origin script can join. A single XSS — even one isolated from your auth cookies — joins the channel and gets a seat at every RPC call. Encrypted RPC turns a same-origin XSS into a session-key problem instead of immediate data exfiltration.

**Service workers.** They proxy for an entire origin. A worker compromised through cache poisoning or a stale deploy can read every plaintext request flowing through it. AEAD keeps the worker honest: it can route bytes, but it cannot read them unless it is the legitimate endpoint.

**Compliance posture.** Even when nothing is technically broken, "end-to-end encrypted between application endpoints" is a sentence that fits in a SOC 2 doc, a GDPR data-flow diagram, or a customer security review without caveats. TLS termination at a load balancer does not give you that sentence.

Encryption is the difference between trusting every box on the path and not needing to.

## When to use it

**Browser extension internals.** Content scripts, background workers, popups, and sidepanels — `chrome.runtime.sendMessage` gives untyped JSON with no contracts. eRPC gives a typed, encrypted API between all extension components.

**iframe sandboxing.** Embed a third-party widget or sandboxed module. eRPC turns `postMessage` into typed procedure calls with encryption — no hand-parsing `MessageEvent.data`.

**Worker communication.** Web Workers, SharedWorkers, and Service Workers communicate through MessagePorts. eRPC provides a structured, validated API layer instead of ad-hoc message passing.

**Microservices over WebSocket.** Two services need a persistent bidirectional connection. REST falls apart. eRPC over WebSocket gives typed calls in both directions, encrypted, with auto-retry — no API gateway, no TLS proxy.

**Electron / Tauri IPC.** Main process and renderer need a secure channel. eRPC works over any IPC mechanism that can carry binary data.

## Platform support

The reference implementation is **TypeScript/JavaScript** and runs anywhere JS runs:

- Node.js
- Browsers
- Service Workers
- React Native
- Vercel Edge
- Cloudflare Workers
- Deno Deploy

The protocol is language-agnostic. It uses msgpack for serialization and standard primitives (X25519, XSalsa20-Poly1305, HKDF-SHA-256, HMAC-SHA-256). Implementations in Rust, Go, C++, or anything else are welcome — the [Protocol](spec/protocol.md) page is the contract.
