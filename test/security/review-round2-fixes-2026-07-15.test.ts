/**
 * Regressions for porter-audit round 2 (2026-07-15).
 *
 *   #6a — candidate promotion checks the absolute deadline, not just the
 *         timer. A confirming frame arriving after the budget elapsed while
 *         the loop was busy must NOT promote an expired candidate.
 *   #6b — one handshake attempt reports at most one onError: a timeout
 *         followed by a late-rejecting async auth callback must not double up.
 *   #9  — a genuine server response reflected back to the server (same session
 *         key, passes Poly1305) is dropped by the direction guard BEFORE its
 *         nonce is recorded, so it cannot consume a replay-window slot.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  chain,
  client,
  server,
  RPCError,
  type CallOptions,
  type Router,
} from "../../src/index.ts";
import {
  createChannelPair,
  createMitmChannelPair,
} from "../helpers/channels.ts";
import { manualHandshake } from "../helpers/protocol.ts";

type LooseApi = Record<
  string,
  (input?: unknown, opts?: CallOptions) => Promise<unknown>
>;

const sleep = (ms: number): Promise<void> =>
  new Promise((r) => setTimeout(r, ms));

describe("round2 / #6a candidate promotion honours the absolute deadline", () => {
  it("a confirming frame that arrives after the budget (loop starved) does not promote an expired candidate", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    let invocations = 0;
    const errors: unknown[] = [];
    const router: Router = {
      starve: chain().handler(async () => {
        invocations++;
        return "ran";
      }),
    };
    const srv = server(router, a, {
      auth: { secret: () => psk },
      handshakeTimeout: 100,
      onError: (e) => {
        errors.push(e);
      },
    });
    try {
      // Drive the client side manually so we control WHEN the confirming
      // frame is delivered. After this resolves the server has installed a
      // candidate with deadline = hello-receipt + 100 ms.
      const start = Date.now();
      const session = await manualHandshake(b, psk);
      expect(session.proofOk).toBe(true);

      // Starve the event loop synchronously past the candidate deadline. The
      // candidate timer (a macrotask due at ~100 ms) cannot fire while we
      // block, so only the wall-clock check in the promotion path can catch
      // the expiry.
      const until = start + 160;
      while (Date.now() < until) {
        /* busy-wait — deliberately block the loop */
      }

      // Deliver the confirming request frame synchronously. The server's
      // trial-decrypt + deadline check run before any await, so promotion is
      // decided in this call.
      b.send(session.encrypt({ t: 1, id: "req1", p: "starve" }));
      await sleep(40);

      // Expired candidate must not be promoted → handler never runs.
      expect(invocations).toBe(0);
      // The overdue candidate timer still reports the timeout.
      expect(
        errors.some(
          (e) =>
            e instanceof RPCError &&
            e.code === "HANDSHAKE" &&
            /timeout/i.test(e.message),
        ),
      ).toBe(true);
    } finally {
      srv.destroy();
    }
  });
});

describe("round2 / #6b one onError per handshake attempt", () => {
  it("a timeout followed by a late-rejecting auth callback reports exactly once", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const errors: unknown[] = [];
    const router: Router = {
      ping: chain().handler(async () => "pong"),
    };
    const srv = server(router, b, {
      auth: {
        // Rejects at 300 ms — well past the 100 ms budget. Before the fix
        // this produced a second "Handshake failed" on top of the timeout.
        secret: async () => {
          await sleep(300);
          throw new Error("late auth failure");
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
      pCall.catch(() => {});

      await sleep(400); // past both the 100 ms timeout and the 300 ms rejection
      expect(errors.length).toBe(1);
      expect(errors[0]).toBeInstanceOf(RPCError);
      expect((errors[0] as RPCError).message).toMatch(/timeout/i);

      await pCall.catch(() => {});
    } finally {
      destroy();
      srv.destroy();
    }
  });
});

describe("round2 / #9 reflected server response cannot consume a replay slot", () => {
  it("reflecting a genuine server response does not evict a recorded request nonce", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    let execCount = 0;
    const router: Router = {
      bump: chain().handler(async () => ({ n: ++execCount })),
    };
    // Window of 1: a single spurious slot occupant would evict the request.
    const srv = server(router, a, {
      auth: { secret: () => psk },
      replayWindow: 1,
    });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      await api.bump({}); // exec 1; request nonce recorded (window full)

      const reqFrame = mitm.state.captures
        .filter((c) => c.dir === "BtoA" && c.data[0] === 0x01)
        .pop()!.data;
      const respFrame = mitm.state.captures
        .filter((c) => c.dir === "AtoB" && c.data[0] === 0x01)
        .pop()!.data;

      // Reflect the genuine server response back to the server. It passes
      // Poly1305 (shared key) but is a response, not a request (t !== 1).
      mitm.injectToA(respFrame);
      await sleep(40);
      expect(execCount).toBe(1); // a response never runs a handler

      // Replay the original request. If the reflected response had taken the
      // single slot, the request nonce would be evicted and this would
      // re-execute. With the fix the slot is intact → dropped.
      mitm.injectToA(reqFrame);
      await sleep(40);
      expect(execCount).toBe(1);
    } finally {
      destroy();
      srv.destroy();
    }
  });
});
