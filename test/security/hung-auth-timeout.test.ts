/**
 * handshakeTimeout must bound the ENTIRE handshake attempt, starting at
 * hello receipt — including the async auth phase (auth.verify /
 * auth.secret / auth.sign). A slow or hung auth callback must not stretch
 * the attempt: on expiry the server reports a handshake timeout, and a
 * late-resolving callback must not install a candidate or send a reply.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  chain,
  client,
  server,
  RPCError,
  type CallOptions,
  type Channel,
  type Router,
} from "../../src/index.ts";
import { createChannelPair } from "../helpers/channels.ts";

type LooseApi = Record<
  string,
  (input?: unknown, opts?: CallOptions) => Promise<unknown>
>;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const router: Router = {
  ping: chain().handler(async () => "pong"),
};

/** Count outbound frames on a channel (server replies). */
function countSends(ch: Channel): { ch: Channel; sends: () => number } {
  let n = 0;
  return {
    ch: {
      send(data) {
        n++;
        return ch.send(data);
      },
      receive: (cb) => ch.receive(cb),
    },
    sends: () => n,
  };
}

describe("handshakeTimeout bounds the async auth phase", () => {
  it("a slow auth.secret overrunning hsTimeout fails the attempt at hsTimeout; the late result installs nothing", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const wrapped = countSends(b);
    const errors: unknown[] = [];

    const srv = server(router, wrapped.ch, {
      auth: {
        // Resolves at 300 ms — well past the 100 ms server budget.
        secret: async () => {
          await sleep(300);
          return psk;
        },
      },
      handshakeTimeout: 100,
      onError: (e) => {
        errors.push(e);
      },
    });
    const { api, destroy } = client(a, {
      auth: { secret: () => psk },
      handshakeTimeout: 500,
      timeout: 1000,
    }) as unknown as { api: LooseApi; destroy: () => void };

    try {
      const pCall = api["ping"]!();
      pCall.catch(() => {}); // settled below; avoid unhandled rejection

      // At 200 ms: budget (100 ms) expired, auth.secret (300 ms) has NOT
      // resolved yet — the timeout must have fired independently of it.
      await sleep(200);
      const timeoutErr = errors.find(
        (e) => e instanceof RPCError && e.code === "HANDSHAKE",
      );
      expect(timeoutErr).toBeDefined();
      expect((timeoutErr as RPCError).message).toMatch(/timeout/i);
      expect(wrapped.sends()).toBe(0); // no reply went out

      // At 400 ms: auth.secret resolved at 300 ms — on a DEAD attempt.
      // No candidate, no reply.
      await sleep(200);
      expect(wrapped.sends()).toBe(0);

      // The client's own handshakeTimeout (500 ms) fails the call.
      const err = await pCall.catch((e: unknown) => e);
      expect(err).toBeInstanceOf(RPCError);
      expect((err as RPCError).code).toBe("HANDSHAKE");
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("an auth.secret that never resolves still times out the attempt", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const wrapped = countSends(b);
    const errors: unknown[] = [];

    const srv = server(router, wrapped.ch, {
      auth: {
        secret: () => new Promise<Uint8Array>(() => {}), // hangs forever
      },
      handshakeTimeout: 100,
      onError: (e) => {
        errors.push(e);
      },
    });
    const { api, destroy } = client(a, {
      auth: { secret: () => psk },
      handshakeTimeout: 300,
      timeout: 1000,
    }) as unknown as { api: LooseApi; destroy: () => void };

    try {
      const pCall = api["ping"]!();
      pCall.catch(() => {});

      await sleep(200);
      const timeoutErr = errors.find(
        (e) => e instanceof RPCError && e.code === "HANDSHAKE",
      );
      expect(timeoutErr).toBeDefined();
      expect((timeoutErr as RPCError).message).toMatch(/timeout/i);
      expect(wrapped.sends()).toBe(0);

      const err = await pCall.catch((e: unknown) => e);
      expect(err).toBeInstanceOf(RPCError);
      expect((err as RPCError).code).toBe("HANDSHAKE");
    } finally {
      destroy();
      srv.destroy();
    }
  });
});
