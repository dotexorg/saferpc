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

The most common case: browser or service talking to a server over WS.

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

Make sure `ws.binaryType = "arraybuffer"` on the browser side.

```typescript
// Server (Node.js, ws package)
import { WebSocketServer } from "ws";
import { server } from "@dotex/saferpc";

const serverSecret = crypto.getRandomValues(new Uint8Array(32));
const wss = new WebSocketServer({ port: 8080 });

wss.on("connection", (ws) => {
  const { destroy } = server(router, wsChannel(ws), {
    auth: { secret: () => serverSecret },
    onError: console.error,
  });
  ws.on("close", destroy);
});

// Client (browser)
const ws = new WebSocket("ws://localhost:8080");
ws.binaryType = "arraybuffer";
await new Promise((r) => (ws.onopen = r));

const { api } = client<typeof router>(wsChannel(ws), {
  auth: { secret: () => serverSecret },
});

const user = await api.getUser({ id: "123" });
```

A WebSocket carries one logical Safe RPC session per connection. Reconnect = new handshake.

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

Peer-to-peer, no central relay. Usually paired with mutual signature auth because there is no shared infrastructure to put a PSK on.

```typescript
function webRTCChannel(dc: RTCDataChannel): Channel {
  return {
    send(data) {
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
```

```typescript
const { api } = client<typeof router>(webRTCChannel(dataChannel), {
  auth: {
    sign: async (transcript) => signWithMyDeviceKey(transcript),
    verify: async (proof, transcript) => verifyPeerKey(proof, transcript),
  },
});
```

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
3. The transport is allowed to drop, duplicate, or reorder messages. Safe RPC will time out and retry. It will not behave correctly if your transport silently corrupts bytes. Wrap it in something that fails noisily if you cannot trust it.

That is the whole API surface. Encryption, framing, retry, key management: all on the Safe RPC side. Your adapter does not need to care.
