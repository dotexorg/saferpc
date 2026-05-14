/**
 * E2E over a real WebSocket on 127.0.0.1.
 * Validates the channel adapter and that handshake/RPC work over a binary
 * frame transport with backpressure.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import { WebSocketServer, WebSocket } from "ws";
import { z } from "zod";
import {
  chain,
  client,
  server,
  RemoteRPCError,
  type Router,
} from "../../src/index.ts";
import { wsChannel } from "../helpers/channels.ts";

function pickPort(): number {
  return 30000 + Math.floor(Math.random() * 10000);
}

interface ServerHandle {
  port: number;
  stop: () => Promise<void>;
}

function startServer(
  router: Router,
  psk: Uint8Array,
  port: number,
): ServerHandle {
  const wss = new WebSocketServer({ host: "127.0.0.1", port });
  const sessions: Array<{ destroy: () => void }> = [];
  wss.on("connection", (sock: WebSocket) => {
    const ch = wsChannel(sock as never);
    const s = server(router, ch, { auth: { secret: () => psk } });
    sessions.push(s);
    sock.on("close", () => s.destroy());
  });
  return {
    port,
    stop: () =>
      new Promise<void>((resolve) => {
        for (const s of sessions) s.destroy();
        wss.close(() => resolve());
      }),
  };
}

interface ClientHandle {
  api: Record<string, (input: unknown) => Promise<unknown>>;
  close: () => void;
}

function connectClient(
  url: string,
  psk: Uint8Array,
  opts: Record<string, unknown> = {},
): Promise<ClientHandle> {
  return new Promise((resolve, reject) => {
    const sock = new WebSocket(url);
    sock.on("open", () => {
      const { api, destroy } = client(wsChannel(sock as never), {
        auth: { secret: () => psk },
        ...opts,
      });
      resolve({
        api: api as never,
        close: () => {
          destroy();
          sock.close();
        },
      });
    });
    sock.on("error", reject);
  });
}

describe("websocket / e2e", () => {
  it("completes a full RPC cycle over a real socket", async () => {
    const psk = randomBytes(32);
    const port = pickPort();
    const router: Router = {
      echo: chain()
        .input(z.object({ msg: z.string() }))
        .output(z.object({ msg: z.string() }))
        .handler(async ({ input }) => input as { msg: string }),
    };
    const srv = startServer(router, psk, port);
    const c = await connectClient(`ws://127.0.0.1:${port}`, psk, {
      timeout: 5000,
    });
    try {
      expect(await c.api.echo!({ msg: "ws-hello" })).toEqual({
        msg: "ws-hello",
      });
    } finally {
      c.close();
      await srv.stop();
    }
  });

  it("handles a burst of 50 concurrent calls", async () => {
    const psk = randomBytes(32);
    const port = pickPort();
    const router: Router = {
      add: chain().handler(async ({ input }) => {
        const i = input as { a: number; b: number };
        return i.a + i.b;
      }),
    };
    const srv = startServer(router, psk, port);
    const c = await connectClient(`ws://127.0.0.1:${port}`, psk, {
      timeout: 10000,
    });
    try {
      const N = 50;
      const calls: Array<Promise<unknown>> = [];
      for (let i = 0; i < N; i++) calls.push(c.api.add!({ a: i, b: 1 }));
      const results = await Promise.all(calls);
      for (let i = 0; i < N; i++) expect(results[i]).toBe(i + 1);
    } finally {
      c.close();
      await srv.stop();
    }
  });

  it("rejects mismatched secret with HANDSHAKE or TIMEOUT", async () => {
    const port = pickPort();
    const router: Router = {
      ping: chain().handler(async () => "pong"),
    };
    const srv = startServer(router, randomBytes(32), port);
    const c = await connectClient(`ws://127.0.0.1:${port}`, randomBytes(32), {
      timeout: 1500,
      handshakeTimeout: 1000,
    });
    try {
      try {
        await c.api.ping!({});
        throw new Error("should have thrown");
      } catch (err) {
        const code = (err as { code?: string }).code;
        expect(["HANDSHAKE", "TIMEOUT"]).toContain(code);
      }
    } finally {
      c.close();
      await srv.stop();
    }
  });

  it("propagates handler RPCError as RemoteRPCError", async () => {
    const psk = randomBytes(32);
    const port = pickPort();
    const router: Router = {
      ping: chain().handler(async () => "pong"),
    };
    const srv = startServer(router, psk, port);
    const c = await connectClient(`ws://127.0.0.1:${port}`, psk, {
      timeout: 1500,
    });
    try {
      try {
        await c.api.unknown!({});
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RemoteRPCError);
        expect((err as RemoteRPCError).code).toBe("NOT_FOUND");
      }
    } finally {
      c.close();
      await srv.stop();
    }
  });
});
