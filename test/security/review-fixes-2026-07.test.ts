/**
 * Regression tests for the 2026-07 review fixes (findings #2, #3, #4, #6, #7).
 *
 * Each test is written to FAIL against the pre-fix code and pass after:
 *   #2 — a frame that passes Poly1305 but carries a junk inner payload still
 *        promotes the candidate (spec: promotion is proven by AEAD, not by
 *        the payload's shape). Pre-fix the decode error was conflated with a
 *        decrypt failure, so the candidate never promoted and expired.
 *   #3 — a SYNCHRONOUS auth callback that overruns handshakeTimeout installs
 *        nothing. Pre-fix the boolean expiry flag was still false when the
 *        microtask continuation resumed, so a candidate + reply went out.
 *   #4 — NaN/Infinity limits are rejected at construction.
 *   #6 — a failed handshake-reply send drops the candidate and reports ONE
 *        error, not a send-failure followed by a spurious timeout.
 *   #7 — middleware that returns without calling next() is rejected.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  chain,
  client,
  server,
  createJWTServerAuth,
  RPCError,
  RemoteRPCError,
  TAG_MSG,
  type Channel,
  type Router,
} from "../../src/index.ts";
import { createChannelPair } from "../helpers/channels.ts";
import { manualHandshake, forgeHello, encryptRaw } from "../helpers/protocol.ts";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const router: Router = { ping: chain().handler(async () => "pong") };

/** Wrap a channel so we can count outbound frames (server replies). */
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

const dummyChannel: Channel = {
  send() {},
  receive() {
    return () => {};
  },
};

describe("review-fixes 2026-07", () => {
  // ── #2 ────────────────────────────────────────────────────────────
  it("#2 a Poly1305-valid frame with a junk inner payload still promotes the candidate", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const errors: unknown[] = [];
    const srv = server(router, a, {
      auth: { secret: () => psk },
      handshakeTimeout: 100,
      onError: (e) => errors.push(e),
    });
    try {
      // Drive the client half manually: sends hello, server installs a
      // candidate armed with a ~<100 ms confirmation timer.
      const sess = await manualHandshake(b, psk);
      expect(sess.proofOk).toBe(true);

      // Immediately send an authenticated-but-junk frame (0xc1 = msgpack
      // "never used"). It must promote the candidate before the timer fires.
      b.send(encryptRaw(sess.sessionKey, new Uint8Array([0xc1])));

      // Capture RPC responses on the now-live session.
      const responses: unknown[] = [];
      b.receive((d) => {
        if (d[0] === TAG_MSG) responses.push(sess.decrypt(d));
      });

      // Past the handshake budget: if the junk frame promoted correctly, the
      // candidate timer was cleared and NO timeout fired.
      await sleep(150);
      const timeoutErr = errors.find(
        (e) => e instanceof RPCError && /timeout/i.test(e.message),
      );
      expect(timeoutErr).toBeUndefined();

      // Positive proof the session is live: a real request gets answered.
      b.send(sess.encrypt({ t: 1, id: "1", p: "ping", i: {} }));
      await sleep(50);
      expect(
        responses.some(
          (r) =>
            typeof r === "object" &&
            r !== null &&
            (r as Record<string, unknown>)["ok"] === true &&
            (r as Record<string, unknown>)["d"] === "pong",
        ),
      ).toBe(true);
    } finally {
      srv.destroy();
    }
  });

  // ── #3 ────────────────────────────────────────────────────────────
  it("#3 a synchronous auth.verify overrunning handshakeTimeout installs nothing", async () => {
    const { a, b } = createChannelPair();
    const wrapped = countSends(a);
    const errors: unknown[] = [];
    const srv = server(router, wrapped.ch, {
      auth: {
        // Blocks the event loop synchronously, well past the 100 ms budget.
        // The timer macrotask cannot fire during the block, so only the
        // absolute-deadline check can catch this.
        verify: () => {
          const end = Date.now() + 160;
          while (Date.now() < end) {
            /* busy-wait */
          }
          return {};
        },
      },
      handshakeTimeout: 100,
      onError: (e) => errors.push(e),
    });
    const { api, destroy } = client(b, {
      auth: { sign: async () => new Uint8Array([1]) },
      handshakeTimeout: 500,
      timeout: 1000,
    });
    try {
      const pCall = api.ping({});
      pCall.catch(() => {});
      await sleep(300);

      // The security property: the sync verify resumed AFTER the deadline, so
      // the deadline guard bailed BEFORE installing a candidate or sending a
      // reply — zero frames out. (Pre-fix the boolean flag was still false at
      // that point, so a candidate + reply went out: sends() === 1.)
      expect(wrapped.sends()).toBe(0);

      // With no server reply, the client's own handshakeTimeout fails the call.
      const err = await pCall.catch((e: unknown) => e);
      expect(err).toBeInstanceOf(RPCError);
      expect((err as RPCError).code).toBe("HANDSHAKE");
      // The server never reported success and never leaked crypto state.
      expect(errors.every((e) => !(e instanceof RPCError) || e.code === "HANDSHAKE")).toBe(true);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  // ── #4 ────────────────────────────────────────────────────────────
  it("#4 NaN / Infinity limits are rejected at construction", () => {
    expect(() =>
      client(dummyChannel, {
        auth: { secret: () => randomBytes(32) },
        maxPending: NaN,
      }),
    ).toThrow(/maxPending/);
    expect(() =>
      client(dummyChannel, {
        auth: { secret: () => randomBytes(32) },
        maxMessageBytes: NaN,
      }),
    ).toThrow(/maxMessageBytes/);
    expect(() =>
      server(router, dummyChannel, {
        auth: { secret: () => randomBytes(32) },
        maxMessageBytes: Infinity,
      }),
    ).toThrow(/maxMessageBytes/);
    expect(() =>
      createJWTServerAuth({ verifyToken: async () => ({}), maxAge: NaN }),
    ).toThrow(/maxAge/);
    expect(() =>
      createJWTServerAuth({ verifyToken: async () => ({}), maxAge: Infinity }),
    ).toThrow(/maxAge/);
  });

  // ── #6 ────────────────────────────────────────────────────────────
  it("#6 a failed handshake-reply send drops the candidate and reports exactly one error", async () => {
    const psk = randomBytes(32);
    const errors: RPCError[] = [];
    let serverCb: ((d: Uint8Array) => void) | null = null;
    const throwingChannel: Channel = {
      send() {
        throw new Error("link down");
      },
      receive(cb) {
        serverCb = cb;
        return () => {
          serverCb = null;
        };
      },
    };
    const srv = server(router, throwingChannel, {
      auth: { secret: () => psk },
      handshakeTimeout: 100,
      onError: (e) => errors.push(e as RPCError),
    });
    try {
      // A valid PSK hello (verify not configured → no auth needed). The server
      // derives a key, installs a candidate, then tries to send the reply,
      // which throws.
      serverCb!(forgeHello());
      await sleep(200); // well past handshakeTimeout

      // Exactly one error: the send failure. The candidate timer must have
      // been cleared by dropCandidate, so NO spurious "Handshake timeout"
      // follows.
      expect(errors.length).toBe(1);
      expect(errors[0]!.code).toBe("HANDSHAKE");
      expect(errors[0]!.message).toMatch(/send failed/i);
      // The ORIGINAL transport error object rides err.cause (constructor
      // options, 4th RPCError argument) — not err.data, not stringified.
      expect(errors[0]!.cause).toBeInstanceOf(Error);
      expect((errors[0]!.cause as Error).message).toBe("link down");
      expect(errors[0]!.data).toBeNull();
    } finally {
      srv.destroy();
    }
  });

  // ── #7 ────────────────────────────────────────────────────────────
  it("#7 middleware that returns without calling next() is rejected", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const noNextRouter: Router = {
      skip: chain()
        // Returns a value but never calls next() — the handler must not run
        // and the client must not observe a success.
        .use(async () => "skipped" as unknown as never)
        .handler(async () => "ok"),
    };
    const srv = server(noNextRouter, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      const err = await api.skip({}).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(RemoteRPCError);
      expect((err as RemoteRPCError).code).toBe("MIDDLEWARE");
    } finally {
      destroy();
      srv.destroy();
    }
  });
});
