/**
 * drpc/channels/ws — WebSocket channel adapters.
 *
 * Two adapters, one contract (see `Channel` in common.ts):
 *
 * - `wsChannel(source)` — reconnecting client adapter. OWNS the socket
 *   lifecycle: when the socket closes it immediately creates a new one and
 *   keeps retrying (exponential backoff, forever) until `close()`. While the
 *   transport is down, `send` throws synchronously — the core outbound queue
 *   owns retry; the adapter's job is availability, not delivery bookkeeping.
 *   `onDown`/`onUp` hooks report transitions for observability only.
 *
 * - `socketChannel(ws)` — plain single-socket adapter, no lifecycle
 *   ownership. This is the server-side wrapper (a server cannot reconnect a
 *   client's socket) and the choice when the caller manages the socket.
 *   `send` checks `readyState` and throws when not OPEN (browser CLOSED
 *   silently drops — that silent drop is the trap this check closes).
 */

import type { Channel } from "../common.ts";

/** WebSocket.readyState OPEN — identical in the DOM and the `ws` package. */
const WS_OPEN = 1;

/**
 * Minimal structural WebSocket. Covers the browser/Node global `WebSocket`
 * and the `ws` package without depending on DOM types.
 */
export interface WebSocketLike {
  binaryType: string;
  readyState: number;
  send(data: Uint8Array): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: string, listener: (ev: never) => void): void;
  removeEventListener(type: string, listener: (ev: never) => void): void;
}

export interface WsChannelOptions {
  /**
   * Reconnect backoff. The first retry is immediate; subsequent retries are
   * exponential from `backoffMin` (default 250 ms) to `backoffMax`
   * (default 5000 ms) with full jitter. Retries forever until `close()`.
   */
  backoffMin?: number;
  backoffMax?: number;
  /** Observability only — never affects behavior. */
  onDown?: (err?: unknown) => void;
  onUp?: () => void;
}

interface MessageEventLike {
  data?: unknown;
}

function toBytes(data: unknown): Uint8Array | null {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (data instanceof Uint8Array) return data; // includes Node Buffer
  return null;
}

/**
 * Reconnecting WebSocket channel (client side).
 *
 * @param source a URL string (uses `globalThis.WebSocket`) or a factory
 *   returning a fresh socket per connection attempt (use this with the `ws`
 *   package or custom construction). A factory throw on the FIRST attempt
 *   propagates to the caller (misconfiguration surfaces immediately); later
 *   throws are treated as a failed attempt and retried with backoff.
 */
export function wsChannel(
  source: string | (() => WebSocketLike),
  opts: WsChannelOptions = {},
): Channel & { close: () => void } {
  const backoffMin = opts.backoffMin !== undefined ? opts.backoffMin : 250;
  const backoffMax = opts.backoffMax !== undefined ? opts.backoffMax : 5000;

  const factory: () => WebSocketLike =
    typeof source === "function"
      ? source
      : function fromUrl() {
          const Ctor = (
            globalThis as { WebSocket?: new (url: string) => WebSocketLike }
          ).WebSocket;
          if (typeof Ctor !== "function") {
            throw new TypeError(
              "wsChannel: no global WebSocket constructor; pass a factory",
            );
          }
          return new Ctor(source);
        };

  const callbacks = new Set<(data: Uint8Array) => void>();
  let sock: WebSocketLike | null = null;
  let closed = false;
  /** True after onOpen (socket usable) until the next down event. */
  let up = false;
  /** Consecutive failed attempts since the socket was last open. */
  let attempts = 0;
  let retryTimer: ReturnType<typeof setTimeout> | null = null;

  function scheduleReconnect(): void {
    if (closed || retryTimer !== null) return;
    const cap = Math.min(
      backoffMax,
      backoffMin * 2 ** Math.max(0, attempts - 1),
    );
    const delay = attempts === 0 ? 0 : Math.random() * cap;
    attempts++;
    retryTimer = setTimeout(function onRetry() {
      retryTimer = null;
      connect(false);
    }, delay);
  }

  function connect(initial: boolean): void {
    if (closed) return;
    let s: WebSocketLike;
    try {
      s = factory();
    } catch (err: unknown) {
      if (initial) throw err; // bad URL / misconfig — surface immediately
      scheduleReconnect();
      return;
    }
    sock = s;
    try {
      s.binaryType = "arraybuffer";
    } catch {
      // some implementations restrict when binaryType may be set
    }

    let lastErr: unknown = undefined;

    function onMessage(ev: MessageEventLike): void {
      const bytes = toBytes(
        ev !== null && typeof ev === "object" ? ev.data : null,
      );
      if (bytes === null) return;
      for (const cb of callbacks) cb(bytes);
    }
    function onError(ev: unknown): void {
      // Recorded for onDown; the close event drives the actual transition.
      // Registering a listener also keeps the `ws` package from throwing
      // on an unhandled 'error' event.
      lastErr = ev;
    }
    function onOpen(): void {
      if (closed || s !== sock) return;
      attempts = 0;
      up = true;
      if (opts.onUp !== undefined) {
        try {
          opts.onUp();
        } catch {
          // observability hook must not break the channel
        }
      }
    }
    function onClose(): void {
      s.removeEventListener("message", onMessage as (ev: never) => void);
      s.removeEventListener("error", onError as (ev: never) => void);
      s.removeEventListener("open", onOpen as (ev: never) => void);
      s.removeEventListener("close", onClose as (ev: never) => void);
      if (closed || s !== sock) return;
      sock = null;
      if (up) {
        up = false;
        if (opts.onDown !== undefined) {
          try {
            opts.onDown(lastErr);
          } catch {
            // observability hook must not break the channel
          }
        }
      }
      scheduleReconnect();
    }

    s.addEventListener("message", onMessage as (ev: never) => void);
    s.addEventListener("error", onError as (ev: never) => void);
    s.addEventListener("open", onOpen as (ev: never) => void);
    s.addEventListener("close", onClose as (ev: never) => void);
  }

  connect(true);

  return {
    send(data: Uint8Array): void {
      if (closed) {
        throw new Error("wsChannel: channel closed");
      }
      const s = sock;
      if (s === null || !up || s.readyState !== WS_OPEN) {
        throw new Error("wsChannel: no open socket");
      }
      s.send(data); // a sync throw here is a real send failure — propagate
    },
    receive(cb: (data: Uint8Array) => void): () => void {
      callbacks.add(cb);
      return function unsubscribe() {
        callbacks.delete(cb);
      };
    },
    close(): void {
      if (closed) return;
      closed = true;
      if (retryTimer !== null) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
      callbacks.clear();
      const s = sock;
      sock = null;
      up = false;
      if (s !== null) {
        try {
          s.close();
        } catch {
          // already dead
        }
      }
    },
  };
}

/**
 * Plain single-socket channel. No reconnect — the caller owns the socket
 * lifecycle. Use on the server side
 * (`wss.on("connection", sock => server(router, socketChannel(sock), ...))`,
 * with `sock.on("close", destroy)`) or anywhere the socket is managed
 * externally.
 *
 * `send` checks `readyState` and throws when not OPEN (browser CLOSED silently
 * drops — that silent drop is the trap this check closes).
 */
export function socketChannel(ws: WebSocketLike): Channel {
  try {
    ws.binaryType = "arraybuffer";
  } catch {
    // some implementations restrict when binaryType may be set
  }
  return {
    send(data: Uint8Array): void {
      if (ws.readyState !== WS_OPEN) {
        throw new Error("socketChannel: socket not open");
      }
      ws.send(data);
    },
    receive(cb: (data: Uint8Array) => void): () => void {
      function handler(ev: MessageEventLike): void {
        const bytes = toBytes(
          ev !== null && typeof ev === "object" ? ev.data : null,
        );
        if (bytes === null) return;
        cb(bytes);
      }
      ws.addEventListener("message", handler as (ev: never) => void);
      return function unsubscribe() {
        ws.removeEventListener("message", handler as (ev: never) => void);
      };
    },
  };
}
