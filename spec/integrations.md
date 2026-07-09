# Integrations

Safe RPC asks one thing of the transport: it must move `Uint8Array` in both directions. That is the whole contract.

```typescript
interface Channel {
  send(data: Uint8Array): void | Promise<void>;
  receive(cb: (data: Uint8Array) => void): () => void; // returns unsubscribe
}
```

Everything below is a one-screen adapter that satisfies that interface. Each one is a few lines of glue around a native transport, and none of them need to know what Safe RPC does.

## Duplex socket transports

Bidirectional byte streams. Each connection maps to one Safe RPC session.

### WebSocket

The most common case: browser or service talking to a server over WS. Ships
as code — `@dotex/saferpc/channels` — because WS is the one transport with a
lifecycle trap (see [the adapter lifecycle contract](#adapter-lifecycle-reopen-immediately-queue-what-never-left) below).

```typescript
// Server (Node.js, ws package)
import { WebSocketServer } from "ws";
import { server } from "@dotex/saferpc";
import { socketChannel } from "@dotex/saferpc/channels";

const serverSecret = crypto.getRandomValues(new Uint8Array(32));
const wss = new WebSocketServer({ port: 8080 });

wss.on("connection", (ws) => {
  const { destroy } = server(router, socketChannel(ws), {
    auth: { secret: () => serverSecret },
    onError: console.error,
  });
  ws.on("close", destroy);
});

// Client (browser)
import { client } from "@dotex/saferpc";
import { wsChannel } from "@dotex/saferpc/channels";

const channel = wsChannel("ws://localhost:8080");
const { api } = client<typeof router>(channel, {
  auth: { secret: () => serverSecret },
});

const user = await api.getUser({ id: "123" });
// on app shutdown: channel.close()
```

`wsChannel(source, opts?)` **owns the socket lifecycle**: it connects
immediately, and when the socket closes it reconnects at once and keeps the
transport open as long as possible (exponential backoff, forever, until
`close()`). While the socket is down, `send` never throws — frames that
provably never left are queued (default cap 256, drop-oldest) and flushed in
order on reconnect; transport errors are swallowed and surfaced only through
the optional `onDown`/`onUp` observability hooks. `source` is a URL string
(uses the global `WebSocket`) or a factory `() => ws` for the `ws` package /
custom construction.

`socketChannel(ws)` is the plain single-socket wrapper: no reconnect, no
queue. The server uses it because a server cannot reconnect a client's
socket — there, connection death IS session death, and `ws.on("close",
destroy)` stays right.

With a per-connection `server()` (the wiring above) the client's kept session
is useless after a reconnect — the first call times out and the client
re-handshakes lazily. Keeping the session pays off when the server side
outlives the socket (a long-lived session binding that re-attaches to each
new connection): then calls in flight across a socket blip just complete.

### TCP socket (Node.js)

Raw TCP does not preserve message boundaries, so the adapter frames every payload with a 4-byte length prefix.

```typescript
import net from "net";

function tcpChannel(socket: net.Socket): Channel {
  let buffer = new Uint8Array(0);

  return {
    send(data) {
      const len = new Uint8Array(4);
      new DataView(len.buffer).setUint32(0, data.length, false);
      socket.write(Buffer.concat([len, data]));
    },
    receive(cb) {
      const handler = (chunk: Buffer) => {
        buffer = new Uint8Array([...buffer, ...chunk]);
        while (buffer.length >= 4) {
          const length = new DataView(
            buffer.buffer,
            buffer.byteOffset,
            4,
          ).getUint32(0, false);
          if (buffer.length < 4 + length) break;
          const message = buffer.slice(4, 4 + length);
          buffer = buffer.slice(4 + length);
          cb(message);
        }
      };
      socket.on("data", handler);
      return () => socket.off("data", handler);
    },
  };
}
```

```typescript
const tcpServer = net.createServer((socket) => {
  const { destroy } = server(router, tcpChannel(socket), {
    auth: { secret: () => sharedSecret },
    onError: console.error,
  });
  socket.on("close", destroy);
});
tcpServer.listen(8080);

const socket = net.connect({ port: 8080, host: "localhost" });
const { api } = client<typeof router>(tcpChannel(socket), {
  auth: { secret: () => sharedSecret },
});
```

## Message-based transports

Fire-and-forget messaging with reliable delivery semantics.

### postMessage (window / iframe)

Two windows on the same machine. Cross-origin if you want.

```typescript
function postMessageChannel(target: Window, origin: string): Channel {
  return {
    send(data) {
      target.postMessage(data, origin);
    },
    receive(cb) {
      const handler = (e: MessageEvent) => {
        if (e.origin !== origin) return; // critical
        if (e.data instanceof Uint8Array) cb(e.data);
      };
      window.addEventListener("message", handler);
      return () => window.removeEventListener("message", handler);
    },
  };
}
```

**Always check `origin`.** Skipping it is how cross-window attacks happen. The wildcard `"*"` is fine in development and dangerous in production.

```typescript
// Parent (server)
const iframe = document.querySelector("iframe") as HTMLIFrameElement;

const { destroy } = server(
  router,
  postMessageChannel(iframe.contentWindow!, "https://widget.example.com"),
  { auth: { secret: () => sharedSecret } },
);

// iframe (client)
const { api } = client<typeof router>(
  postMessageChannel(parent, "https://app.example.com"),
  { auth: { secret: () => sharedSecret } },
);
```

### MessagePort (Worker / SharedWorker / MessageChannel)

Web Workers, SharedWorkers, and any code path that hands you a `MessagePort`.

```typescript
function portChannel(port: MessagePort): Channel {
  return {
    send(data) {
      port.postMessage(data, [data.buffer]); // transferable: zero-copy
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

```typescript
// Main thread
const worker = new Worker("worker.js");
const { port1, port2 } = new MessageChannel();
worker.postMessage({ port: port2 }, [port2]);

const { api } = client<typeof router>(portChannel(port1), {
  auth: { secret: () => sharedSecret },
});

// worker.js
self.onmessage = (e) => {
  const port = e.data.port as MessagePort;
  server(router, portChannel(port), { auth: { secret: () => sharedSecret } });
};
```

SharedWorker is the same shape, except `self.onconnect` gives you the port and you can serve multiple tabs from one worker.

### Chrome extension port

Content scripts ↔ background service worker ↔ popup. Native messaging is untyped JSON.

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

The `Array.from` round-trip is the price of `chrome.runtime`. High-throughput extensions should pin a `chrome.runtime.connect` between a content script and an offscreen document, then switch to MessagePort there.

```typescript
// background.js (service worker)
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "saferpc") return;
  const { destroy } = server(router, extensionPortChannel(port), {
    auth: { secret: () => getExtensionPSK() },
    context: () => ({
      tabId: port.sender?.tab?.id,
      frameId: port.sender?.frameId,
    }),
  });
  port.onDisconnect.addListener(destroy);
});

// content-script.js
const port = chrome.runtime.connect({ name: "saferpc" });
const { api } = client<typeof router>(extensionPortChannel(port), {
  auth: { secret: () => getExtensionPSK() },
});
```

`getExtensionPSK()` is whatever your extension uses to derive a secret both sides agree on. Extension ID + version + a stored secret, for example.

### BroadcastChannel

Tabs of the same origin talking to each other. One channel, many participants.

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

Safe RPC is a 1:1 protocol. To use BroadcastChannel, elect a single server tab (leader) and let other tabs become clients. The leader holds the session state; clients re-handshake when leadership moves.

```typescript
const isLeader = await electLeader();

if (isLeader) {
  server(router, broadcastChannel("tab-sync"), {
    auth: { secret: () => getLeaderPSK() },
  });
}

const { api } = client<typeof router>(broadcastChannel("tab-sync"), {
  auth: { secret: () => getLeaderPSK() },
});
```

## Peer-to-peer transports

Direct connection between peers without a central relay.

### WebRTC DataChannel

Peer-to-peer, no relay. `RTCDataChannel` is ordered and reliable by default. The signalling (offer/answer/ICE) is your problem. Safe RPC starts after the data channel fires `"open"`. And there is no central party to hold a PSK, so peers usually authenticate by signing the handshake transcript with device keys. PSK still works if both sides derive the same secret from a shared room code or account, it just rarely matches how WebRTC apps are wired.

```typescript
function webRTCChannel(dc: RTCDataChannel): Channel {
  dc.binaryType = "arraybuffer";

  return {
    async send(data) {
      if (dc.readyState !== "open") await waitDCOpen(dc);
      dc.send(data);
    },
    receive(cb) {
      const handler = (e: MessageEvent) => {
        if (e.data instanceof ArrayBuffer) cb(new Uint8Array(e.data));
      };
      dc.addEventListener("message", handler);
      return () => dc.removeEventListener("message", handler);
    },
  };
}

function waitDCOpen(dc: RTCDataChannel): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (dc.readyState === "open") return resolve();
    dc.addEventListener("open", () => resolve(), { once: true });
    dc.addEventListener(
      "error",
      () => reject(new Error("data channel error")),
      { once: true },
    );
    dc.addEventListener(
      "close",
      () => reject(new Error("data channel closed")),
      { once: true },
    );
  });
}
```

Sends are parked until the channel opens, so the data channel can go straight into `client()` / `server()` — no need to wait for signalling to finish first.

#### Usage

No central party to hold a PSK, so peers authenticate by signing the handshake transcript with their device keys:

```typescript
const auth = {
  sign: (transcript) => myKey.sign(transcript),
  verify: (proof, transcript) => peerKey.verify(proof, transcript),
};
```

One side opens the channel and acts as a client, the other accepts it and acts as a server:

```typescript
// Initiator
const dc = pc.createDataChannel("saferpc", { ordered: true });
const { api } = client<typeof router>(webRTCChannel(dc), { auth });

// Accepter
pc.addEventListener("datachannel", (e) => {
  if (e.channel.label !== "saferpc") return;
  server(router, webRTCChannel(e.channel), { auth, onError: console.error });
});
```

#### Symmetric peer

WebRTC peers are symmetric — nothing says one side is the server. To expose a router _and_ call the other side's, open two channels on the same `RTCPeerConnection`: one where you serve, one where you call. They share the underlying DTLS/SCTP transport.

```typescript
function joinPeer(pc: RTCPeerConnection) {
  // Serve our router on a channel we open
  const outbound = pc.createDataChannel("peer", { ordered: true });
  const serving = server(router, webRTCChannel(outbound), {
    auth,
    onError: console.error,
  });

  // Call the peer's router on the channel they open
  const calling = new Promise<Client<typeof router>>((resolve) => {
    pc.addEventListener("datachannel", (e) => {
      if (e.channel.label !== "peer") return;
      resolve(client<typeof router>(webRTCChannel(e.channel), { auth }).api);
    });
  });

  return {
    api: () => calling,
    close: () => {
      serving.destroy();
      pc.close();
    },
  };
}
```

Both peers run the same code; neither is "the server".

## Split-channel transports

Asymmetric transports work too. You only need a `send` and a `receive`, not a single duplex socket.

### Server-Sent Events + fetch

The client sends over `fetch` and receives over SSE.

```typescript
function sseChannel(url: string): Channel {
  let cb: ((data: Uint8Array) => void) | null = null;
  let es: EventSource | null = null;

  return {
    async send(data) {
      await fetch(`${url}/send`, {
        method: "POST",
        body: data,
        headers: { "Content-Type": "application/octet-stream" },
      });
    },
    receive(handler) {
      cb = handler;
      es = new EventSource(url);
      es.onmessage = (e) => {
        if (!cb) return;
        cb(new Uint8Array(JSON.parse(e.data)));
      };
      return () => {
        cb = null;
        es?.close();
        es = null;
      };
    },
  };
}
```

The server side needs an in-memory map from session to SSE stream so it knows where to send replies. The adapter is more involved than the duplex transports, but the Safe RPC code on top stays identical.

## Custom transports

The rules are the same as everywhere else:

1. `send` accepts `Uint8Array` and gets it to the other side.
2. `receive(cb)` calls `cb` with each incoming `Uint8Array`. It returns an unsubscribe function.
3. The transport is allowed to drop, duplicate, or reorder messages. Safe RPC will time out and surface a typed error (it does not auto-retry — the caller decides whether to resend). It will not behave correctly if your transport silently corrupts bytes. Wrap it in something that fails noisily if you cannot trust it.
4. If the transport can die (sockets), the adapter owns liveness — see the lifecycle contract below.

That is the whole API surface. Encryption, framing, key management: all on the Safe RPC side. Your adapter does not need to care.

### Adapter lifecycle: reopen immediately, queue what never left

As of 0.7.0 the client core treats transport death as a non-event: the session
is bound to key material, not to a transport instance, so when a socket dies
the client keeps its keys and its pending calls keep waiting under their own
timers. A call's outcome is decided by exactly two events — a reply that
decrypts, or the call's own timeout. That works only if the adapter holds up
its half of the deal:

- **Reopen immediately.** When the transport closes, reconnect at once and
  keep it open as long as possible (backoff, forever). Don't wait for the
  next `send` to notice.
- **While down, `send` must not throw.** Queue the frame — it provably never
  left, so flushing it after reconnect is safe and is NOT an auto-retry — and
  drop any transport error inside the adapter (log it through your own hook
  if you want; don't surface it per-call).
- **Never resend a frame that was written to a live transport.** Its outcome
  is unknown; resending is exactly the double-execution hazard the no-retry
  rule exists to prevent. Only queued-while-down frames may be flushed.

`wsChannel` in `@dotex/saferpc/channels` implements this contract; use it as
the reference. Two WS-specific traps it absorbs, for anyone writing their
own: browser `WebSocket.send()` on a **CLOSED** socket silently drops the
frame (it only throws while `CONNECTING`) — without a `readyState` check in
`send`, every failure degrades into a stacked RPC + handshake timeout (~35s
with defaults) surfacing as a misleading `HANDSHAKE "Handshake timeout"`; and
a socket can report OPEN before the reconnect flush has run — sending
directly then would reorder frames past the queued ones.

A fail-fast adapter (throw from `send` when the transport is down, get an
immediate `CHANNEL` error) is still a legal, simpler choice — the failed call
rejects at once and the caller decides. What it costs you is exactly the new
property: calls no longer survive a socket blip.
