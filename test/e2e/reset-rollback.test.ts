/**
 * Optimistic-sent rollback × reset() interaction.
 *
 * An async Channel.send counts as "sent" optimistically and is rolled back
 * to the outbound queue on rejection. If a reset() ran while the send
 * promise was in flight, the rollback must NOT resurrect the frame: its
 * ciphertext is under the zeroed key and can never succeed. The rejection
 * proves the frame never left, so the call must fail immediately with a
 * plain RPCError("CHANNEL") — not retry dead ciphertext, and never smuggle
 * old-key bytes past the epoch staleness check.
 *
 * Covers both rollback paths:
 *   - direct-send path (sendRequest's onAsyncSendFail)
 *   - flush path (flushOutbound's onFlushFail)
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  chain,
  client,
  server,
  RPCError,
  RPCAbortedError,
  type CallOptions,
  type Channel,
  type Router,
} from "../../src/index.ts";

type LooseApi = Record<
  string,
  (input?: unknown, opts?: CallOptions) => Promise<unknown>
>;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface Captured {
  data: Uint8Array;
  resolve: () => void;
  reject: (e: unknown) => void;
}

/**
 * In-memory pair whose client→server side can switch behavior:
 *   - "sync"    — deliver immediately (send returns undefined)
 *   - "throw"   — throw synchronously (channel-down contract)
 *   - "capture" — return a pending Promise the test settles manually;
 *                 the frame is NOT delivered (in-flight async send)
 * The server→client side always delivers synchronously.
 */
function controllableChannelPair(): {
  a: Channel;
  b: Channel;
  ctl: {
    setMode: (m: "sync" | "throw" | "capture") => void;
    captured: Captured[];
    sends: () => number;
  };
} {
  let aCb: ((data: Uint8Array) => void) | null = null;
  let bCb: ((data: Uint8Array) => void) | null = null;
  let mode: "sync" | "throw" | "capture" = "sync";
  const captured: Captured[] = [];
  let sends = 0;

  const a: Channel = {
    send(data) {
      sends++;
      if (mode === "throw") throw new Error("channel down");
      if (mode === "capture") {
        return new Promise<void>((resolve, reject) => {
          captured.push({ data: data.slice(), resolve, reject });
        });
      }
      if (bCb) bCb(data);
    },
    receive(cb) {
      aCb = cb;
      return () => {
        aCb = null;
      };
    },
  };
  const b: Channel = {
    send(data) {
      if (aCb) aCb(data);
    },
    receive(cb) {
      bCb = cb;
      return () => {
        bCb = null;
      };
    },
  };

  return {
    a,
    b,
    ctl: {
      setMode: (m) => {
        mode = m;
      },
      captured,
      sends: () => sends,
    },
  };
}

function makeRouter(): Router {
  return {
    echo: chain().handler(async ({ input }) => input),
    // Never resolves — used to drive a reply-timeout → auto-reset.
    gated: chain().handler(async () => new Promise(() => {})),
  };
}

describe("reset() vs optimistic-sent rollback", () => {
  it("direct async send rejected after reset fails plain CHANNEL immediately, frame is not retried", async () => {
    const psk = randomBytes(32);
    const { a, b, ctl } = controllableChannelPair();
    const srv = server(makeRouter(), b, { auth: { secret: () => psk } });
    const { api, destroy } = client(a, {
      auth: { secret: () => psk },
      timeout: 300,
      sendTimeout: 5000,
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      // Establish the session.
      expect(await api["echo"]!("warm")).toBe("warm");

      // Call A: delivered, server never replies → reply-timeout → reset.
      const pA = api["gated"]!();
      await sleep(10); // let A's frame leave on the sync channel

      // Call B: direct async send, promise held pending by the test.
      ctl.setMode("capture");
      const pB = api["echo"]!("b");

      // A times out → RPCAbortedError(TIMEOUT) → auto-reset fires.
      const errA = await pA.catch((e: unknown) => e);
      expect(errA).toBeInstanceOf(RPCAbortedError);
      expect((errA as RPCError).code).toBe("TIMEOUT");

      // B's in-flight send now rejects — AFTER the reset.
      expect(ctl.captured.length).toBe(1);
      const sendsBefore = ctl.sends();
      ctl.captured[0]!.reject(new Error("socket died"));

      // B fails NOW with the definite never-left error: plain RPCError,
      // not the aborted class, not a late TIMEOUT.
      const errB = await pB.catch((e: unknown) => e);
      expect(errB).toBeInstanceOf(RPCError);
      expect(errB).not.toBeInstanceOf(RPCAbortedError);
      expect((errB as RPCError).code).toBe("CHANNEL");
      expect((errB as RPCError).message).toContain("Session reset before send");

      // The dead frame must not be resurrected: no retry ticks re-send it.
      await sleep(600);
      expect(ctl.sends()).toBe(sendsBefore);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("queued frame whose flush-send rejects after reset fails plain CHANNEL, not retried under the dead session", async () => {
    const psk = randomBytes(32);
    const { a, b, ctl } = controllableChannelPair();
    const srv = server(makeRouter(), b, { auth: { secret: () => psk } });
    const { api, destroy } = client(a, {
      auth: { secret: () => psk },
      timeout: 800,
      sendTimeout: 5000,
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      expect(await api["echo"]!("warm")).toBe("warm");

      // Call A: delivered, will reply-timeout at ~800 ms.
      const pA = api["gated"]!();
      await sleep(10); // let A's frame leave on the sync channel

      // Call B: sync send throws → frame enters the core outbound queue.
      ctl.setMode("throw");
      const pB = api["echo"]!("b");

      // Flush tick (≤250 ms) picks B up as an in-flight async send.
      ctl.setMode("capture");
      await sleep(400);
      expect(ctl.captured.length).toBe(1); // B left the queue, promise pending

      // A times out → auto-reset. B is in flight: reset can't see it.
      const errA = await pA.catch((e: unknown) => e);
      expect(errA).toBeInstanceOf(RPCAbortedError);
      expect((errA as RPCError).code).toBe("TIMEOUT");

      const sendsBefore = ctl.sends();
      ctl.captured[0]!.reject(new Error("socket died"));

      const errB = await pB.catch((e: unknown) => e);
      expect(errB).toBeInstanceOf(RPCError);
      expect(errB).not.toBeInstanceOf(RPCAbortedError);
      expect((errB as RPCError).code).toBe("CHANNEL");
      expect((errB as RPCError).message).toContain("Session reset before send");

      await sleep(600);
      expect(ctl.sends()).toBe(sendsBefore);
    } finally {
      destroy();
      srv.destroy();
    }
  });
});
