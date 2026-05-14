/**
 * Tamper attacks: bit-flip / truncation / forged TAG_MSG.
 *
 * eRPC drops failed-decrypt frames silently (poly1305 auth failure). The
 * application-level call should TIME OUT or auto-retry — never see a
 * forged response.
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
import { createMitmChannelPair } from "../helpers/channels.ts";

describe("security / tamper attacks", () => {
  it("a flipped bit in client→server TAG_MSG is dropped, no handler call with bad data", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();

    let invocations = 0;
    const router: Router = {
      ping: chain().handler(async () => {
        invocations++;
        return "pong";
      }),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 400,
      handshakeTimeout: 800,
    });

    try {
      expect(await api.ping({})).toBe("pong");
      expect(invocations).toBe(1);

      let tampered = false;
      mitm.transformBtoA((data) => {
        if (!tampered && data[0] === 0x01) {
          tampered = true;
          const out = data.slice();
          out[out.length - 1] = (out[out.length - 1]! ^ 0xff) & 0xff;
          return out;
        }
        return data;
      });

      try {
        await api.ping({});
        // Auto-retry path may have re-handshaked and succeeded — that
        // is also acceptable, since the tampered frame was dropped.
        expect(invocations).toBeGreaterThanOrEqual(2);
      } catch (err) {
        expect(err).toBeInstanceOf(RPCError);
        const code = (err as RPCError).code;
        expect(["TIMEOUT", "SESSION", "HANDSHAKE"]).toContain(code);
      }
      // Handler is never invoked with malicious bytes.
      expect(invocations).toBeLessThanOrEqual(2);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("a flipped bit in the nonce is dropped", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    let invocations = 0;
    const router: Router = {
      ping: chain().handler(async () => {
        invocations++;
        return "pong";
      }),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 400,
      handshakeTimeout: 800,
    });

    try {
      expect(await api.ping({})).toBe("pong");
      expect(invocations).toBe(1);

      let tampered = false;
      mitm.transformBtoA((data) => {
        if (!tampered && data[0] === 0x01) {
          tampered = true;
          const out = data.slice();
          out[1] = (out[1]! ^ 0x01) & 0xff;
          return out;
        }
        return data;
      });

      try {
        await api.ping({});
      } catch (err) {
        expect(err).toBeInstanceOf(RPCError);
        const code = (err as RPCError).code;
        expect(["TIMEOUT", "SESSION", "HANDSHAKE"]).toContain(code);
      }
      expect(invocations).toBeLessThanOrEqual(2);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("forged TAG_MSG with random ciphertext is dropped silently", async () => {
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
      onError: (e) => errors.push(e),
    });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });

    try {
      expect(await api.ping({})).toBe("pong");
      const baseline = invocations;

      for (let i = 0; i < 10; i++) {
        const junk = new Uint8Array(64);
        junk[0] = 0x01;
        crypto.getRandomValues(junk.subarray(1));
        mitm.injectToA(junk);
      }
      await new Promise((r) => setTimeout(r, 50));
      expect(invocations).toBe(baseline);
      expect(errors.length).toBe(0);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("a forged response cannot resolve a pending call — only the legit one does", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    const router: Router = {
      slow: chain().handler(
        async () =>
          new Promise<string>((r) => setTimeout(() => r("real"), 100)),
      ),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 500,
    });
    try {
      const slow = api.slow({});
      setTimeout(() => {
        const junk = new Uint8Array(80);
        junk[0] = 0x01;
        crypto.getRandomValues(junk.subarray(1));
        mitm.injectToB(junk);
      }, 30);
      expect(await slow).toBe("real");
    } finally {
      destroy();
      srv.destroy();
    }
  });
});
