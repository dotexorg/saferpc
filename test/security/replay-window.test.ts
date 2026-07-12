/**
 * D2 — bounded seen-nonce set (in-session replay defense).
 *
 * The server remembers the last `replayWindow` AEAD nonces it has accepted and
 * silently drops any frame whose nonce it has already seen — so a MITM cannot
 * replay a captured (valid) request frame to re-run a handler. The record is
 * written only after Poly1305 verifies, and the window is FIFO-bounded: a
 * replay older than `replayWindow` accepted messages executes again (the
 * window is narrowed to N, not closed). `replayWindow: 0` disables it.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import { chain, client, server, type Router } from "../../src/index.ts";
import { createMitmChannelPair } from "../helpers/channels.ts";

const lastRequestFrame = (
  captures: Array<{ dir: "AtoB" | "BtoA"; data: Uint8Array }>,
): Uint8Array | undefined =>
  captures.filter((c) => c.dir === "BtoA" && c.data[0] === 0x01).pop()?.data;

describe("security / D2 replay window", () => {
  it("drops a replayed request frame (handler runs exactly once)", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    let execCount = 0;
    const router: Router = {
      bump: chain().handler(async () => ({ n: ++execCount })),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      await api.bump({});
      expect(execCount).toBe(1);

      const frame = lastRequestFrame(mitm.state.captures);
      expect(frame).toBeDefined();

      mitm.injectToA(frame!);
      await new Promise((r) => setTimeout(r, 40));
      // Replay dropped — no re-execution.
      expect(execCount).toBe(1);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("replayWindow: 0 disables the defense (replay re-executes)", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    let execCount = 0;
    const router: Router = {
      bump: chain().handler(async () => ({ n: ++execCount })),
    };
    const srv = server(router, a, {
      auth: { secret: () => psk },
      replayWindow: 0,
    });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      await api.bump({});
      expect(execCount).toBe(1);

      const frame = lastRequestFrame(mitm.state.captures);
      mitm.injectToA(frame!);
      await new Promise((r) => setTimeout(r, 40));
      expect(execCount).toBe(2);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("a replay older than replayWindow executes again (honest FIFO boundary)", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    let execCount = 0;
    const router: Router = {
      bump: chain().handler(async () => ({ n: ++execCount })),
    };
    const srv = server(router, a, {
      auth: { secret: () => psk },
      replayWindow: 2,
    });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      await api.bump({}); // exec 1 — capture this frame's nonce
      const oldest = lastRequestFrame(mitm.state.captures)!;

      // Two more accepted messages evict the first nonce from a window of 2.
      await api.bump({}); // exec 2
      await api.bump({}); // exec 3
      const before = execCount;

      mitm.injectToA(oldest);
      await new Promise((r) => setTimeout(r, 40));
      // Evicted from the window → accepted and executed again.
      expect(execCount).toBe(before + 1);
    } finally {
      destroy();
      srv.destroy();
    }
  });
});
