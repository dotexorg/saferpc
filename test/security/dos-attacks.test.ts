/**
 * DoS-flavored attacks (within the documented threat model):
 *
 *   - oversized TAG_MSG: silently dropped at the framing layer.
 *   - too many concurrent client calls: maxPending guard, no memory blow-up.
 *   - depth-bomb input: rejected (sanitize throws in the decryptor path).
 *   - black-hole channel: client recovers via TIMEOUT/HANDSHAKE.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  chain,
  client,
  server,
  RPCError,
  type Router,
} from "../../src/index.ts";
import {
  createChannelPair,
  createMitmChannelPair,
} from "../helpers/channels.ts";

describe("security / DoS — framing limits", () => {
  it("server drops TAG_MSG larger than maxMessageBytes", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    let invocations = 0;
    const errors: unknown[] = [];
    const router: Router = {
      ping: chain().handler(async () => {
        invocations++;
        return "pong";
      }),
    };
    const srv = server(router, a, {
      auth: { secret: () => psk },
      maxMessageBytes: 1024,
      onError: (e) => errors.push(e),
    });

    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      expect(await api.ping({})).toBe("pong");
      expect(invocations).toBe(1);

      const huge = new Uint8Array(2048);
      huge[0] = 0x01;
      mitm.injectToA(huge);
      await new Promise((r) => setTimeout(r, 30));

      expect(invocations).toBe(1);
      expect(errors.length).toBe(0);
    } finally {
      destroy();
      srv.destroy();
    }
  });
});

describe("security / DoS — client backpressure", () => {
  it("client refuses new calls when maxPending is reached", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const router: Router = {
      slow: chain().handler(
        async () =>
          new Promise<string>((r) => setTimeout(() => r("done"), 200)),
      ),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 5000,
      maxPending: 4,
    });
    try {
      const inflight: Array<Promise<unknown>> = [];
      for (let i = 0; i < 4; i++) inflight.push(api.slow({}));
      await Promise.resolve();

      let blocked: unknown;
      try {
        await api.slow({});
        blocked = null;
      } catch (err) {
        blocked = err;
      }
      expect(blocked).toBeInstanceOf(RPCError);
      expect((blocked as RPCError).code).toBe("CLIENT");

      const all = await Promise.all(inflight);
      expect(all.every((v) => v === "done")).toBe(true);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  // C1 regression: a maxPending overflow is a CLIENT guardrail error, not a
  // transport failure. It must NOT trigger a session reset + re-handshake +
  // resend of the in-flight calls (the old auto-retry path did, silently
  // executing each of the 4 healthy calls twice while the caller saw one
  // clean success). Assert exec count == 4 and hello count == 1.
  it("maxPending overflow does not reset the session or double-execute", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    let execCount = 0;
    const router: Router = {
      slow: chain().handler(async () => {
        execCount++;
        return new Promise<string>((r) => setTimeout(() => r("done"), 150));
      }),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 5000,
      maxPending: 4,
    });
    try {
      const inflight: Array<Promise<unknown>> = [];
      for (let i = 0; i < 4; i++) inflight.push(api.slow({}));
      await Promise.resolve();

      let blocked: unknown;
      try {
        await api.slow({});
      } catch (err) {
        blocked = err;
      }
      expect((blocked as RPCError).code).toBe("CLIENT");

      const all = await Promise.all(inflight);
      expect(all).toEqual(["done", "done", "done", "done"]);

      // The 4 healthy calls each ran exactly once...
      expect(execCount).toBe(4);
      // ...and the good session was never torn down: a single handshake.
      const helloCount = mitm.state.captures.filter(
        (c) => c.dir === "BtoA" && c.data[0] === 0x00,
      ).length;
      expect(helloCount).toBe(1);
    } finally {
      destroy();
      srv.destroy();
    }
  });
});

describe("security / DoS — depth bomb input", () => {
  it("rejects deeply nested input at the protocol layer", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const router: Router = {
      sink: chain().handler(async ({ input }) => input),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1500,
    });
    try {
      let nested: { v?: number; n?: unknown } = { v: 1 };
      for (let i = 0; i < 60; i++) nested = { n: nested };

      let caught: unknown = null;
      try {
        await api.sink(nested);
      } catch (err) {
        caught = err;
      }
      expect(caught).not.toBeNull();
      expect(caught).toBeInstanceOf(RPCError);
    } finally {
      destroy();
      srv.destroy();
    }
  });
});

describe("security / DoS — black-hole channel", () => {
  it("client surfaces HANDSHAKE/TIMEOUT when nothing answers", async () => {
    const psk = randomBytes(32);
    const { b, mitm } = createMitmChannelPair();
    mitm.transformBtoA(() => null);
    mitm.transformAtoB(() => null);

    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 600,
      handshakeTimeout: 200,
    });
    try {
      try {
        await api.anything({});
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RPCError);
        const code = (err as RPCError).code;
        expect(["HANDSHAKE", "TIMEOUT"]).toContain(code);
      }
    } finally {
      destroy();
    }
  });
});
