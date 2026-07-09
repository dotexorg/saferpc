/**
 * drpc/channels/ws — WebSocket channel adapters.
 *
 * Two adapters, one contract (see `Channel` in common.ts):
 *
 * - `wsChannel(source)` — reconnecting client adapter. OWNS the socket
 *   lifecycle: when the socket closes it immediately creates a new one and
 *   keeps retrying (exponential backoff, forever) until `close()`. While the
 *   transport is down, `send` never throws — frames that provably never left
 *   are queued and flushed in order on reconnect, transport errors are
 *   swallowed (surfaced only via the `onDown` observability hook). A frame
 *   written to a live socket is spent — it is NEVER resent, so nothing here
 *   violates the client's no-auto-retry semantics.
 *
 * - `socketChannel(ws)` — plain single-socket adapter, no lifecycle
 *   ownership. This is the server-side wrapper (a server cannot reconnect a
 *   client's socket) and the choice when the caller manages the socket.
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
   * Max frames buffered while the socket is down. Default 256 (matches the
   * client's default `maxPending`). On overflow the OLDEST frame is dropped
   * silently — the affected call times out and the session heals lazily;
   * keeping the newest frames means a fresh hello beats a stale request.
   */
  maxQueue?: number;
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
  const maxQueue = opts.maxQueue !== undefined ? opts.maxQueue : 256;
  const backoffMin = opts.backoffMin !== undefined ? opts.backoffMin : 250;
  const backoffMax = opts.backoffMax !== undefined ? opts.backoffMax : 5000;
  if (maxQueue < 1) throw new TypeError("wsChannel: maxQueue must be ≥ 1");

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
  const queue: Uint8Array[] = [];
  let sock: WebSocketLike | null = null;
  let closed = false;
  /** True between a completed flush (socket usable) and the next down. */
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
      // Flush frames that provably never left, in order. A throw here means
      // the socket died mid-flush; the frame is spent (unknown outcome — do
      // not requeue), the remaining queue survives for the next reconnect,
      // and the close event will schedule it. In that case the channel never
      // went usably up — do NOT fire onUp (and onClose, seeing up === false,
      // will not fire onDown), so consumers see no spurious up/down pair.
      while (queue.length > 0) {
        const frame = queue.shift() as Uint8Array;
        try {
          s.send(frame);
        } catch {
          return;
        }
      }
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
      // `up` (set after flush) gates ordering: a socket can report OPEN
      // before our open handler flushed the queue — sending directly then
      // would reorder frames past the queued ones. `readyState` gates the
      // browser trap: send() on a CLOSED socket silently drops.
      if (s !== null && up && s.readyState === WS_OPEN) {
        s.send(data); // a sync throw here is a real send failure — propagate
        return;
      }
      // Transport down: never throw. Queue the frame (it provably never
      // left); drop the oldest on overflow.
      if (queue.length >= maxQueue) queue.shift();
      queue.push(data);
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
      queue.length = 0;
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
 * Plain single-socket channel. No reconnect, no queue — the caller owns the
 * socket lifecycle. Use on the server side
 * (`wss.on("connection", sock => server(router, socketChannel(sock), ...))`,
 * with `sock.on("close", destroy)`) or anywhere the socket is managed
 * externally.
 */
export function socketChannel(ws: WebSocketLike): Channel {
  try {
    ws.binaryType = "arraybuffer";
  } catch {
    // some implementations restrict when binaryType may be set
  }
  return {
    send(data: Uint8Array): void {
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
