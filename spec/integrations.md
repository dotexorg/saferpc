# Integrations

eRPC works over any bidirectional channel. Below are ready-made adapters for common transports. Each implements the `Channel` interface:

```typescript
interface Channel {
  send(data: Uint8Array): void | Promise<void>;
  receive(cb: (data: Uint8Array) => void): () => void;
}
```

## WebSocket

The most common case — client-server communication over WebSocket.

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

## postMessage (Window / iframe)

For communication between a window and an iframe, or between windows.

```typescript
function postMessageChannel(target: Window, origin: string): Channel {
  return {
    send(data) {
      target.postMessage(data, origin);
    },
    receive(cb) {
      const handler = (e: MessageEvent) => {
        if (e.origin !== origin) return;
        if (e.data instanceof Uint8Array) cb(e.data);
      };
      window.addEventListener("message", handler);
      return () => window.removeEventListener("message", handler);
    },
  };
}
```

> Always check `origin` — this protects against cross-window attacks.

## MessagePort (Worker / iframe)

For Web Workers, SharedWorkers, or iframes via `MessageChannel`.

```typescript
function portChannel(port: MessagePort): Channel {
  return {
    send(data) {
      port.postMessage(data, [data.buffer]);
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

> `[data.buffer]` in `postMessage` marks the buffer as transferable — zero-copy transfer.

## Chrome Extension Port

For communication between content scripts, background/service workers, and popups in browser extensions.

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

> Chrome Extension ports don't support binary data directly, so `Uint8Array` is converted to a plain number array.

## BroadcastChannel

For communication between tabs of the same origin or between workers.

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

## Custom Adapters

Writing your own adapter is straightforward — implement `send` and `receive`. Works for TCP, UDP, serial ports, Bluetooth, or any other transport. The only requirement is a bidirectional channel that can carry `Uint8Array`.
