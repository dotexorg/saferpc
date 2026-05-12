/**
 * E2E over a real Node MessageChannel — the same primitive used by Web
 * Workers and iframes. Validates the eRPC channel adapter against a
 * structured-clone MessagePort transport.
 */
import { describe, it, expect } from "vitest";
import { MessageChannel } from "node:worker_threads";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";
import {
  chain,
  client,
  server,
  RemoteRPCError,
  type Router,
} from "../../src/index.ts";
import { portChannel } from "../helpers/channels.ts";

describe("message-port (worker_threads.MessageChannel)", () => {
  it("completes the handshake and calls procedures across MessagePorts", async () => {
    const psk = randomBytes(32);
    const { port1, port2 } = new MessageChannel();
    const router: Router = {
      ping: chain()
        .input(z.object({ msg: z.string() }))
        .output(z.object({ pong: z.string() }))
        .handler(async ({ input }) => ({
          pong: (input as { msg: string }).msg,
        })),
    };

    const srv = server(router, portChannel(port1 as never), {
      auth: { psk: () => psk },
    });
    const { api, destroy } = client(portChannel(port2 as never), {
      auth: { psk: () => psk },
      timeout: 2000,
    });
    try {
      const out = await api.ping({ msg: "hello" });
      expect(out).toEqual({ pong: "hello" });
    } finally {
      destroy();
      srv.destroy();
      port1.close();
      port2.close();
    }
  });

  it("handles 50 sequential calls without leaking handlers", async () => {
    const psk = randomBytes(32);
    const { port1, port2 } = new MessageChannel();
    const router: Router = {
      add: chain().handler(async ({ input }) => {
        const i = input as { a: number; b: number };
        return i.a + i.b;
      }),
    };
    const srv = server(router, portChannel(port1 as never), {
      auth: { psk: () => psk },
    });
    const { api, destroy } = client(portChannel(port2 as never), {
      auth: { psk: () => psk },
      timeout: 5000,
    });
    try {
      for (let i = 0; i < 50; i++) {
        expect(await api.add({ a: i, b: 1 })).toBe(i + 1);
      }
    } finally {
      destroy();
      srv.destroy();
      port1.close();
      port2.close();
    }
  });

  it("rejects an unknown procedure with RemoteRPCError(NOT_FOUND)", async () => {
    const psk = randomBytes(32);
    const { port1, port2 } = new MessageChannel();
    const srv = server({} as Router, portChannel(port1 as never), {
      auth: { psk: () => psk },
    });
    const { api, destroy } = client(portChannel(port2 as never), {
      auth: { psk: () => psk },
      timeout: 1000,
    });
    try {
      try {
        await api.does_not_exist({});
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RemoteRPCError);
        expect((err as RemoteRPCError).code).toBe("NOT_FOUND");
      }
    } finally {
      destroy();
      srv.destroy();
      port1.close();
      port2.close();
    }
  });
});
