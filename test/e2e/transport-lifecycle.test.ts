/**
 * Transport lifecycle — 0.7.0 retry semantics (F1 / Option A) + abortPending.
 *
 * The client no longer auto-retries. A lost reply (TIMEOUT, outcome unknown)
 * or a send failure (CHANNEL, request never left) surfaces to the caller with
 * a typed code and resets the session — but is NOT resent. The caller, the
 * only party that knows whether a procedure is idempotent, decides. This kills
 * the silent double-execution hazard the old auto-retry created for
 * fund-moving handlers.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  chain,
  client,
  server,
  RPCError,
  type Channel,
  type Router,
} from "../../src/index.ts";
import {
  createChannelPair,
  createMitmChannelPair,
} from "../helpers/channels.ts";

describe("transport lifecycle / retry semantics (F1 Option A)", () => {
  it("a lost reply surfaces TIMEOUT and the handler runs exactly once (no auto-resend)", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    let execCount = 0;
    const router: Router = {
      ping: chain().handler(async () => {
        execCount++;
        return "pong";
      }),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 300,
      handshakeTimeout: 600,
    });
    try {
      expect(await api.ping({})).toBe("pong");
      expect(execCount).toBe(1);

      // Drop the NEXT server→client reply frame. Both requests and replies
      // ride TAG_MSG (0x01) on the wire (t:1/t:2 is inside the ciphertext);
      // the transform only sees server→client (AtoB) traffic, and the first
      // reply already went out during the call above.
      let dropped = false;
      mitm.transformAtoB((d) => {
        if (!dropped && d[0] === 0x01) {
          dropped = true;
          return null;
        }
        return d;
      });

      await expect(api.ping({})).rejects.toMatchObject({ code: "TIMEOUT" });
      // Handler executed once for the lost-reply call; there was NO resend.
      expect(execCount).toBe(2);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("a send failure surfaces CHANNEL and the request never executes", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    let execCount = 0;
    const router: Router = {
      ping: chain().handler(async () => {
        execCount++;
        return "pong";
      }),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });

    // Wrap the client channel so send() throws for TAG_MSG once armed.
    let failSend = false;
    const bFail: Channel = {
      send(data) {
        if (failSend && data[0] === 0x01) throw new Error("socket dead");
        return b.send(data);
      },
      receive: (cb) => b.receive(cb),
    };
    const { api, destroy } = client(bFail, {
      auth: { secret: () => psk },
      timeout: 500,
    });
    try {
      expect(await api.ping({})).toBe("pong");
      expect(execCount).toBe(1);

      failSend = true;
      await expect(api.ping({})).rejects.toMatchObject({ code: "CHANNEL" });
      // Request provably never left — handler count unchanged.
      expect(execCount).toBe(1);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("a guardrail (RemoteRPCError) is passed through, session not reset", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    const router: Router = {
      boom: chain().handler(async () => {
        throw new RPCError("BUSINESS", "nope");
      }),
      ok: chain().handler(async () => "ok"),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      await expect(api.boom({})).rejects.toMatchObject({ code: "BUSINESS" });
      // Remote error must NOT tear down the session: next call needs no
      // re-handshake.
      expect(await api.ok({})).toBe("ok");
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

describe("transport lifecycle / abortPending (F3)", () => {
  it("rejects in-flight calls with CHANNEL and keeps the client usable", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    let execCount = 0;
    const router: Router = {
      slow: chain().handler(async () => {
        execCount++;
        return new Promise<string>((r) => setTimeout(() => r("done"), 400));
      }),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, abortPending, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 5000,
    });
    try {
      const p1 = api.slow({});
      // Let the handshake + request go out.
      await new Promise((r) => setTimeout(r, 60));
      abortPending();
      await expect(p1).rejects.toMatchObject({ code: "CHANNEL" });

      // Client object is still usable — the next call lazily re-handshakes.
      expect(await api.slow({})).toBe("done");
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("uses a caller-supplied error and fails an in-progress handshake", async () => {
    const psk = randomBytes(32);
    // Black-hole server side: never answers, so the client stays handshaking.
    const b: Channel = { send() {}, receive: () => () => {} };
    const { api, abortPending, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 5000,
      handshakeTimeout: 5000,
    });
    try {
      const p = api.anything({});
      await new Promise((r) => setTimeout(r, 30));
      // A hello-waiter must not hang to handshakeTimeout.
      abortPending(new RPCError("CHANNEL_DOWN", "dead"));
      await expect(p).rejects.toMatchObject({ code: "CHANNEL_DOWN" });
    } finally {
      destroy();
    }
  });

  it("is a no-op after destroy()", () => {
    const psk = randomBytes(32);
    const b: Channel = { send() {}, receive: () => () => {} };
    const { abortPending, destroy } = client(b, {
      auth: { secret: () => psk },
    });
    destroy();
    expect(() => abortPending()).not.toThrow();
  });
});
