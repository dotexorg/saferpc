/**
 * Transport lifecycle — 0.7.0 retry semantics (F1 / Option A).
 *
 * The client no longer auto-retries. A lost reply (TIMEOUT, outcome
 * unknown) surfaces as RPCAbortedError and resets the session. A send
 * failure (CHANNEL, request never left) surfaces as plain RPCError and
 * does NOT reset the session. The caller decides whether to retry.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  chain,
  client,
  server,
  RPCError,
  RPCAbortedError,
  type Channel,
  type Router,
} from "../../src/index.ts";
import {
  createChannelPair,
  createMitmChannelPair,
} from "../helpers/channels.ts";

describe("transport lifecycle / retry semantics (F1 Option A)", () => {
  it("a lost reply surfaces RPCAbortedError(TIMEOUT) and the handler runs exactly once (no auto-resend)", async () => {
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

      const timeoutErr = await api.ping({}).catch((e: unknown) => e);
      expect(timeoutErr).toBeInstanceOf(RPCAbortedError);
      expect((timeoutErr as RPCAbortedError).code).toBe("TIMEOUT");
      // Handler executed once for the lost-reply call; there was NO resend.
      expect(execCount).toBe(2);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("a send failure queues and retries until sendTimeout, then surfaces plain RPCError(CHANNEL); session not reset", async () => {
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
    let hellosSent = 0;
    const bFail: Channel = {
      send(data) {
        if (failSend && data[0] === 0x01) throw new Error("socket dead");
        const r = b.send(data);
        // Count hellos only on successful delivery (never fails for 0x00)
        if (data[0] === 0x00) hellosSent++;
        return r;
      },
      receive: (cb) => b.receive(cb),
    };
    const { api, destroy } = client(bFail, {
      auth: { secret: () => psk },
      timeout: 2000,
      sendTimeout: 150, // frame expires before global timeout
    });
    try {
      expect(await api.ping({})).toBe("pong");
      expect(execCount).toBe(1);
      expect(hellosSent).toBe(1);

      // With failSend=true, the frame is re-queued and retried by the core
      // until sendTimeout (150 ms) expires → definite plain RPCError(CHANNEL).
      failSend = true;
      const chanErr = await api.ping({}).catch((e: unknown) => e);
      expect(chanErr).toBeInstanceOf(RPCError);
      expect(chanErr).not.toBeInstanceOf(RPCAbortedError);
      expect((chanErr as RPCError).code).toBe("CHANNEL");
      // Request provably never left — handler count unchanged.
      expect(execCount).toBe(1);

      // Session NOT reset on CHANNEL: next call succeeds without re-handshake.
      failSend = false;
      expect(await api.ping({})).toBe("pong");
      expect(hellosSent).toBe(1); // still only the original hello
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
