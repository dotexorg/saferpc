/**
 * E2E for the shipped reconnecting WebSocket adapter (src/channels/ws.ts)
 * over a real socket on 127.0.0.1. Validates the v2 adapter contract:
 * send() throws while the transport is down and after close(); eager
 * reconnect surfaces via onDown/onUp; the core outbound queue re-sends
 * during the gap so a call issued while disconnected still resolves.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import { WebSocketServer, WebSocket as WsClient } from "ws";
import {
  chain,
  client,
  server,
  TAG_HELLO,
  type Channel,
  type Router,
} from "../../src/index.ts";
import { wsChannel, type WebSocketLike } from "../../src/channels/index.ts";

function pickPort(): number {
  return 30000 + Math.floor(Math.random() * 10000);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitFor(cond: () => boolean, ms = 4000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > ms) throw new Error("waitFor: condition timeout");
    await sleep(10);
  }
}

function toU8(data: unknown): Uint8Array {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (Buffer.isBuffer(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return data as Uint8Array;
}

/**
 * Long-lived server binding: one `server()` instance whose channel spans
 * connections — each new socket replaces the previous one (SessionDO-style
 * wiring). Returns the current-socket handle so tests can kill it.
 */
function startBridgedServer(
  router: Router,
  psk: Uint8Array,
  port: number,
): {
  currentSock: () => import("ws").WebSocket | null;
  stop: () => Promise<void>;
} {
  const wss = new WebSocketServer({ host: "127.0.0.1", port });
  let current: import("ws").WebSocket | null = null;
  const cbs = new Set<(data: Uint8Array) => void>();
  wss.on("connection", (sock) => {
    current = sock;
    sock.on("message", (data) => {
      const u8 = toU8(data);
      for (const cb of cbs) cb(u8);
    });
  });
  const bridge: Channel = {
    send(data) {
      current?.send(data);
    },
    receive(cb) {
      cbs.add(cb);
      return () => cbs.delete(cb);
    },
  };
  const s = server(router, bridge, { auth: { secret: () => psk } });
  return {
    currentSock: () => current,
    stop: () =>
      new Promise<void>((resolve) => {
        s.destroy();
        current?.terminate();
        wss.close(() => resolve());
      }),
  };
}

describe("ws channel / reconnecting adapter", () => {
  // ── Test 10: contract ────────────────────────────────────────────────────

  it("contract: send throws while down and after close()", async () => {
    const port = pickPort();
    let ups = 0;
    let downs = 0;

    // A blockable factory lets the test control when reconnects can land.
    // When blockConnect is true the factory throws, which the adapter treats
    // as a failed attempt and retries with backoff — keeping sock===null and
    // up===false for the duration of the block.
    let blockConnect = false;
    const wss = new WebSocketServer({ host: "127.0.0.1", port });
    const ch = wsChannel(
      () => {
        if (blockConnect) throw new Error("connect blocked by test");
        return new WsClient(
          `ws://127.0.0.1:${port}`,
        ) as unknown as WebSocketLike;
      },
      {
        backoffMin: 20,
        backoffMax: 200,
        onDown: () => downs++,
        onUp: () => ups++,
      },
    );
    try {
      await waitFor(() => ups === 1);

      // Block reconnects BEFORE killing the socket so the immediate retry
      // (delay=0) hits a factory throw and the adapter stays reliably down.
      blockConnect = true;
      for (const s of wss.clients) s.terminate();
      await waitFor(() => downs === 1);

      // Factory throws on every retry → sock===null, up===false.
      // The adapter MUST throw synchronously when it cannot hand the frame
      // to a live transport now.
      expect(() => ch.send(new Uint8Array([1]))).toThrow(
        "wsChannel: no open socket",
      );

      // Unblock: adapter reconnects on its own backoff schedule.
      blockConnect = false;
      await waitFor(() => ups === 2);

      // close() is terminal — throws forever regardless of socket state.
      ch.close();
      expect(() => ch.send(new Uint8Array([1]))).toThrow(
        "wsChannel: channel closed",
      );
      await sleep(50);
      expect(() => ch.send(new Uint8Array([1]))).toThrow(
        "wsChannel: channel closed",
      );
    } finally {
      ch.close(); // idempotent if already closed
      await new Promise<void>((resolve) => wss.close(() => resolve()));
    }
  });

  // ── Test 11: reconnect + core retry end-to-end ───────────────────────────

  it("call issued during a gap resolves after the adapter reconnects; TAG_HELLO == 1", async () => {
    const psk = randomBytes(32);
    const port = pickPort();
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
    };
    const srv = startBridgedServer(router, psk, port);

    let downs = 0;
    let ups = 0;
    const ch = wsChannel(
      () => new WsClient(`ws://127.0.0.1:${port}`) as unknown as WebSocketLike,
      {
        backoffMin: 20,
        backoffMax: 200,
        onDown: () => downs++,
        onUp: () => ups++,
      },
    );
    // Count hellos that actually left the adapter (count after a successful
    // ch.send, not before — a throw means the frame never left).
    let hellos = 0;
    const counting: Channel = {
      send(d) {
        const result = ch.send(d); // throws if socket not open
        if (d[0] === TAG_HELLO) hellos++; // only reached on success
        return result;
      },
      receive: (cb) => ch.receive(cb),
    };
    const { api, destroy } = client(counting, {
      auth: { secret: () => psk },
      timeout: 5000,
    }) as unknown as {
      api: Record<string, (i?: unknown) => Promise<unknown>>;
      destroy: () => void;
    };
    try {
      expect(await api.echo!("warm")).toBe("warm");
      expect(ups).toBe(1);

      srv.currentSock()!.terminate();
      await waitFor(() => downs === 1);

      // Call during gap (or right after the fast reconnect — either way the
      // call resolves and the session is continuous: no second hello).
      const p = api.echo!("during-gap");
      expect(await p).toBe("during-gap");

      expect(downs).toBe(1);
      expect(ups).toBe(2);
      expect(hellos).toBe(1); // same session — no re-handshake
    } finally {
      destroy();
      ch.close();
      await srv.stop();
    }
  });

  // ── Updated: close() is terminal ─────────────────────────────────────────

  it("close() is terminal: after close() the core cannot send and surfaces CHANNEL", async () => {
    const psk = randomBytes(32);
    const port = pickPort();
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
    };
    const srv = startBridgedServer(router, psk, port);
    let ups = 0;
    const ch = wsChannel(
      () => new WsClient(`ws://127.0.0.1:${port}`) as unknown as WebSocketLike,
      { onUp: () => ups++ },
    );
    // Small sendTimeout so the CHANNEL error arrives within one flush tick
    // (~250 ms) rather than waiting the 10 s default.
    const { api, destroy } = client(ch, {
      auth: { secret: () => psk },
      timeout: 2000,
      sendTimeout: 100,
    }) as unknown as {
      api: Record<string, (i?: unknown) => Promise<unknown>>;
      destroy: () => void;
    };
    try {
      await waitFor(() => ups === 1);
      expect(await api.echo!("warm")).toBe("warm");

      ch.close();
      // Adapter throws synchronously. The core queues the frame, retries for
      // sendTimeout (100 ms), then surfaces plain RPCError("CHANNEL").
      expect(() => ch.send(new Uint8Array([9]))).toThrow();
      await expect(api.echo!("x")).rejects.toMatchObject({ code: "CHANNEL" });
    } finally {
      destroy();
      ch.close(); // idempotent
      await srv.stop();
    }
  });
});
