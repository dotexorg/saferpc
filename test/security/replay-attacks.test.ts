/**
 * Replay attacks:
 *   - cross-session replay (frame captured in session 1, replayed into
 *     session 2) does NOT decrypt — fresh ephemeral keys → fresh session key.
 *   - stale hello reply from a previous handshake is ignored by the
 *     epoch check on the client.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import { chain, client, server, type Router } from "../../src/index.ts";
import { createMitmChannelPair } from "../helpers/channels.ts";

describe("security / replay attacks", () => {
  it("a captured ciphertext from a previous session does NOT decrypt", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();

    let counter = 0;
    const router: Router = {
      bump: chain().handler(async () => ({ n: ++counter })),
    };
    const srv = server(router, a, { psk });

    // Session 1: one bump.
    const c1 = client(b, { psk, timeout: 1000 });
    expect(((await c1.api.bump({})) as { n: number }).n).toBe(1);

    const captured = mitm.state.captures
      .filter((c) => c.dir === "BtoA" && c.data[0] === 0x01)
      .pop();
    expect(captured).toBeDefined();

    c1.destroy();

    // Session 2: brand new client, fresh ephemeral keys.
    const c2 = client(b, { psk, timeout: 800 });
    expect(((await c2.api.bump({})) as { n: number }).n).toBe(2);

    const before = counter;
    mitm.injectToA(captured!.data);
    await new Promise((r) => setTimeout(r, 50));
    expect(counter).toBe(before);

    c2.destroy();
    srv.destroy();
  });

  it("a stale hello reply from a previous handshake is rejected by the epoch check", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    const router: Router = {
      ping: chain().handler(async () => "pong"),
    };
    const srv = server(router, a, { psk });

    const c1 = client(b, { psk, timeout: 1000 });
    expect(await c1.api.ping({})).toBe("pong");

    const oldReply = mitm.state.captures.find(
      (c) => c.dir === "AtoB" && c.data[0] === 0x00,
    )?.data;
    expect(oldReply).toBeDefined();

    c1.destroy();

    let injected = false;
    mitm.transformBtoA((d) => {
      if (!injected && d[0] === 0x00) {
        injected = true;
        queueMicrotask(() => mitm.injectToB(oldReply!));
      }
      return d;
    });

    const c2 = client(b, {
      psk,
      timeout: 1500,
      handshakeTimeout: 1000,
    });
    try {
      expect(await c2.api.ping({})).toBe("pong");
    } finally {
      c2.destroy();
      srv.destroy();
    }
  });
});
