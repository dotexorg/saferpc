/**
 * E2E for the shipped reconnecting WebSocket adapter (src/channels/ws.ts)
 * over a real socket on 127.0.0.1. Validates the adapter lifecycle contract:
 * eager reconnect, queue-while-down with drop-oldest overflow, terminal
 * close(). The server side mirrors a long-lived session binding (the same
 * `server()` instance re-attached to each incoming connection), which is the
 * wiring where a kept client session pays off.
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
  it("reconnects after socket death and a call issued during the gap resolves without re-handshake", async () => {
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
    // Count outbound hellos to prove the session survived the reconnect.
    let hellos = 0;
    const counting: Channel = {
      send(d) {
        if (d[0] === TAG_HELLO) hellos++;
        return ch.send(d);
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

      const p = api.echo!("during-gap"); // queues; flushes on reconnect
      expect(await p).toBe("during-gap");
      expect(downs).toBe(1);
      expect(ups).toBe(2);
      expect(hellos).toBe(1); // same session across sockets
    } finally {
      destroy();
      ch.close();
      await srv.stop();
    }
  });

  it("queue overflow drops the oldest frame", async () => {
    const port = pickPort();
    const received: number[] = [];
    let wss = new WebSocketServer({ host: "127.0.0.1", port });
    const record = (sock: import("ws").WebSocket): void => {
      sock.on("message", (data) => {
        received.push(toU8(data)[0] as number);
      });
    };
    wss.on("connection", record);

    let downs = 0;
    let ups = 0;
    const ch = wsChannel(
      () => new WsClient(`ws://127.0.0.1:${port}`) as unknown as WebSocketLike,
      {
        maxQueue: 2,
        backoffMin: 20,
        backoffMax: 100,
        onDown: () => downs++,
        onUp: () => ups++,
      },
    );
    try {
      await waitFor(() => ups === 1);

      // Take the listener fully away so the reconnect loop cannot succeed
      // while we overflow the queue.
      await new Promise<void>((resolve) => {
        for (const sock of wss.clients) sock.terminate();
        wss.close(() => resolve());
      });
      await waitFor(() => downs === 1);

      ch.send(new Uint8Array([1]));
      ch.send(new Uint8Array([2]));
      ch.send(new Uint8Array([3])); // overflow: frame [1] is dropped

      wss = new WebSocketServer({ host: "127.0.0.1", port });
      wss.on("connection", record);
      await waitFor(() => received.length >= 2);
      await sleep(50); // give a hypothetical third frame time to arrive

      expect(received).toEqual([2, 3]);
      expect(ups).toBe(2);
    } finally {
      ch.close();
      await new Promise<void>((resolve) => wss.close(() => resolve()));
    }
  });

  it("close() is terminal: send throws and the client surfaces CHANNEL", async () => {
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
    const { api, destroy } = client(ch, {
      auth: { secret: () => psk },
      timeout: 1000,
    }) as unknown as {
      api: Record<string, (i?: unknown) => Promise<unknown>>;
      destroy: () => void;
    };
    try {
      await waitFor(() => ups === 1);
      expect(await api.echo!("warm")).toBe("warm");

      ch.close();
      expect(() => ch.send(new Uint8Array([9]))).toThrow();
      // Through the client, the sync throw surfaces as a typed CHANNEL error.
      await expect(api.echo!("x")).rejects.toMatchObject({ code: "CHANNEL" });
    } finally {
      destroy();
      await srv.stop();
    }
  });
});
