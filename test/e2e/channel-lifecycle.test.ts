/**
 * Channel lifecycle v2 — the session is bound to key material, not to a
 * transport instance. The core owns the outbound queue; channels implement
 * the send-or-throw contract. RPCAbortedError vs plain RPCError reflects
 * which side of the wire the request died on (spec §10, tests 1-9).
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  chain,
  client,
  server,
  RPCError,
  RPCAbortedError,
  TAG_HELLO,
  type CallOptions,
  type Channel,
  type Router,
} from "../../src/index.ts";
import { createFaultChannelPair } from "../helpers/channels.ts";

type LooseApi = Record<
  string,
  (input?: unknown, opts?: CallOptions) => Promise<unknown>
>;

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void } {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/**
 * Wrap a channel to count outbound hello frames that were successfully
 * delivered (send() returned without throwing). Frames rejected by a down
 * channel are not counted — they enter the core queue and may be retried.
 */
function countingChannel(ch: Channel): { ch: Channel; hellos: () => number } {
  let n = 0;
  return {
    ch: {
      send(data) {
        const result = ch.send(data) as void | Promise<void>;
        // Counted only when send did not throw (synchronous contract).
        if (data[0] === TAG_HELLO) n++;
        return result;
      },
      receive: (cb) => ch.receive(cb),
    },
    hellos: () => n,
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("channel lifecycle / core queue + send-or-throw contract", () => {
  // ── Test 1: call issued while channel is down completes after recovery ──
  it("a call issued while the channel is down completes after recovery, no re-handshake", async () => {
    const psk = randomBytes(32);
    const { a, b, link } = createFaultChannelPair();
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
    };
    const srv = server(router, b, { auth: { secret: () => psk } });
    const wrapped = countingChannel(a);
    const { api, destroy } = client(wrapped.ch, {
      auth: { secret: () => psk },
      timeout: 2000,
      sendTimeout: 500,
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      expect(await api.echo!("warm")).toBe("warm");
      expect(wrapped.hellos()).toBe(1);

      link.goDown();
      const p = api.echo!("during-gap"); // send throws → frame enters core queue
      await sleep(30);
      link.goUp(); // core retry tick re-sends within 250 ms

      expect(await p).toBe("during-gap");
      expect(wrapped.hellos()).toBe(1); // session survived — no re-handshake
    } finally {
      destroy();
      srv.destroy();
    }
  });

  // ── Test 2: pending call survives a gap that opens after send ──
  it("a pending call survives a channel gap that opens after the frame is sent", async () => {
    const psk = randomBytes(32);
    const { a, b, link } = createFaultChannelPair();
    const gate = deferred<string>();
    const router: Router = {
      gated: chain().handler(async () => gate.promise),
    };
    const srv = server(router, b, { auth: { secret: () => psk } });
    const { api, destroy } = client(a, {
      auth: { secret: () => psk },
      timeout: 2000,
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      const p = api.gated!(); // request delivered; handler awaiting gate
      await sleep(30);
      link.goDown(); // channel goes down after frame was sent
      await sleep(20);
      link.goUp(); // recover before handler resolves
      gate.resolve("late"); // reply goes out on a live channel

      expect(await p).toBe("late"); // reply-or-timeout, reply branch
    } finally {
      destroy();
      srv.destroy();
    }
  });

  // ── Test 3: lazy heal on lost server session ──
  it("a lost server session heals lazily: first call is RPCAbortedError(TIMEOUT), second re-handshakes", async () => {
    const psk = randomBytes(32);
    const { a, b } = createFaultChannelPair();
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
    };
    let srv = server(router, b, { auth: { secret: () => psk } });
    const wrapped = countingChannel(a);
    const { api, destroy } = client(wrapped.ch, {
      auth: { secret: () => psk },
      timeout: 300,
      sendTimeout: 500,
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      expect(await api.echo!("warm")).toBe("warm");
      expect(wrapped.hellos()).toBe(1);

      srv.destroy(); // server session gone
      srv = server(router, b, { auth: { secret: () => psk } });

      // Frame is SENT but the new server cannot decrypt → no reply → TIMEOUT
      const err = await api.echo!("stale").catch((e: unknown) => e);
      expect(err).toBeInstanceOf(RPCAbortedError);
      expect((err as RPCAbortedError).code).toBe("TIMEOUT");

      // Next call lazily re-handshakes and succeeds
      expect(await api.echo!("fresh")).toBe("fresh");
      expect(wrapped.hellos()).toBe(2);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  // ── Test 4: sendTimeout → definite failure, session NOT reset ──
  it("sendTimeout: definite failure is plain RPCError(CHANNEL), session not reset", async () => {
    const psk = randomBytes(32);
    const { a, b, link } = createFaultChannelPair();
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
    };
    const srv = server(router, b, { auth: { secret: () => psk } });
    const wrapped = countingChannel(a);
    const { api, destroy } = client(wrapped.ch, {
      auth: { secret: () => psk },
      timeout: 2000,
      sendTimeout: 150, // expires before global timeout
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      expect(await api.echo!("warm")).toBe("warm");
      expect(wrapped.hellos()).toBe(1);

      // Frame queues, retries until sendTimeout, expires → definite CHANNEL
      link.goDown();
      const err = await api.echo!("x").catch((e: unknown) => e);
      expect(err).toBeInstanceOf(RPCError);
      expect(err).not.toBeInstanceOf(RPCAbortedError);
      expect((err as RPCError).code).toBe("CHANNEL");

      link.goUp();
      // Session NOT reset: next call succeeds without re-handshake
      expect(await api.echo!("after")).toBe("after");
      expect(wrapped.hellos()).toBe(1); // still only the original hello
    } finally {
      destroy();
      srv.destroy();
    }
  });

  // ── Test 4b: global timeout beats sendTimeout → still definite CHANNEL ──
  it("global timeout on a still-queued frame is plain RPCError(CHANNEL), not the aborted class", async () => {
    const psk = randomBytes(32);
    const { a, b, link } = createFaultChannelPair();
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
    };
    const srv = server(router, b, { auth: { secret: () => psk } });
    const wrapped = countingChannel(a);
    const { api, destroy } = client(wrapped.ch, {
      auth: { secret: () => psk },
      timeout: 150, // fires while the frame is still queued
      sendTimeout: 5000, // deliberately above timeout — misconfig-proof path
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      expect(await api.echo!("warm")).toBe("warm");
      expect(wrapped.hellos()).toBe(1);

      // Frame queues; the global timer expires first. The frame provably
      // never left → same definite CHANNEL code as sendTimeout expiry,
      // and plain class — TIMEOUT is reserved for sent-no-reply.
      link.goDown();
      const err = await api.echo!("x").catch((e: unknown) => e);
      expect(err).toBeInstanceOf(RPCError);
      expect(err).not.toBeInstanceOf(RPCAbortedError);
      expect((err as RPCError).code).toBe("CHANNEL");

      link.goUp();
      // Session NOT reset: next call succeeds without re-handshake
      expect(await api.echo!("after")).toBe("after");
      expect(wrapped.hellos()).toBe(1);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  // ── Test 5: class split on abort ──
  it("abort while frame queued → plain RPCError(ABORTED); abort after send → RPCAbortedError(ABORTED)", async () => {
    const psk = randomBytes(32);
    const { a, b, link } = createFaultChannelPair();
    const gate = deferred<string>();
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
      gated: chain().handler(async () => gate.promise),
    };
    const srv = server(router, b, { auth: { secret: () => psk } });
    const { api, destroy } = client(a, {
      auth: { secret: () => psk },
      timeout: 5000,
      sendTimeout: 500,
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      expect(await api.echo!("warm")).toBe("warm");

      // (a) abort while frame is still queued → plain RPCError("ABORTED")
      link.goDown();
      const ac1 = new AbortController();
      const pA = api.echo!("queued", { signal: ac1.signal });
      await sleep(20);
      ac1.abort("cancelled");
      const errA = (await pA.catch((e: unknown) => e)) as RPCError;
      expect(errA).toBeInstanceOf(RPCError);
      expect(errA).not.toBeInstanceOf(RPCAbortedError);
      expect(errA.code).toBe("ABORTED");
      link.goUp();
      await sleep(10);

      // (b) abort after send → RPCAbortedError("ABORTED") + cause
      const ac2 = new AbortController();
      const pB = api.gated!(undefined, { signal: ac2.signal });
      await sleep(30); // frame sent; handler is running on server
      ac2.abort("user-cancelled");
      const errB = (await pB.catch((e: unknown) => e)) as RPCAbortedError;
      expect(errB).toBeInstanceOf(RPCAbortedError);
      expect(errB.code).toBe("ABORTED");
      expect(errB.cause).toBeDefined(); // signal.reason travels on .cause

      gate.resolve("late"); // late reply → no pending entry → silent drop
      await sleep(20);

      // Session untouched — no reset on ABORTED
      expect(await api.echo!("after")).toBe("after");
    } finally {
      destroy();
      srv.destroy();
    }
  });

  // ── Test 6: class split on destroy ──
  it("destroy: sent call → RPCAbortedError(SESSION); queued call → plain RPCError(SESSION)", async () => {
    const psk = randomBytes(32);
    const { a, b, link } = createFaultChannelPair();
    const gate = deferred<string>();
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
      gated: chain().handler(async () => gate.promise),
    };
    const srv = server(router, b, { auth: { secret: () => psk } });
    let destroyed = false;
    const { api, destroy } = client(a, {
      auth: { secret: () => psk },
      timeout: 5000,
      sendTimeout: 500,
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      expect(await api.echo!("warm")).toBe("warm");

      // Call 1: frame sent (gated handler keeps reply pending)
      const p1 = api.gated!();
      await sleep(30); // frame is in-flight on server

      // Call 2: channel down → frame queues in core
      link.goDown();
      const p2 = api.echo!("queued");
      await sleep(10);

      destroy();
      destroyed = true;

      const [e1, e2] = await Promise.all([
        p1.catch((e: unknown) => e),
        p2.catch((e: unknown) => e),
      ]);

      // Sent call → outcome unknown → RPCAbortedError
      expect(e1).toBeInstanceOf(RPCAbortedError);
      expect((e1 as RPCAbortedError).code).toBe("SESSION");

      // Queued call → provably never left → plain RPCError
      expect(e2).toBeInstanceOf(RPCError);
      expect(e2).not.toBeInstanceOf(RPCAbortedError);
      expect((e2 as RPCError).code).toBe("SESSION");
    } finally {
      if (!destroyed) destroy();
      srv.destroy();
      gate.resolve("done");
    }
  });

  // ── Test 7: reset predicate regression ──
  it("reset predicate: RPCAbortedError(TIMEOUT) resets; plain RPCError(CHANNEL) does not", async () => {
    const psk = randomBytes(32);
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
    };

    // (a) Reply-timeout on a SENT request → next call re-handshakes
    {
      const { a, b } = createFaultChannelPair();
      let srv = server(router, b, { auth: { secret: () => psk } });
      const wrapped = countingChannel(a);
      const { api, destroy } = client(wrapped.ch, {
        auth: { secret: () => psk },
        timeout: 300,
        sendTimeout: 500,
      }) as unknown as { api: LooseApi; destroy: () => void };
      try {
        expect(await api.echo!("warm")).toBe("warm");
        expect(wrapped.hellos()).toBe(1);

        // Server gone → frame sent but no reply → RPCAbortedError(TIMEOUT) → reset
        srv.destroy();
        srv = server(router, b, { auth: { secret: () => psk } });
        const err = await api.echo!("x").catch((e: unknown) => e);
        expect(err).toBeInstanceOf(RPCAbortedError);
        expect((err as RPCAbortedError).code).toBe("TIMEOUT");

        // Reset happened: next call re-handshakes
        expect(await api.echo!("fresh")).toBe("fresh");
        expect(wrapped.hellos()).toBe(2);
      } finally {
        destroy();
        srv.destroy();
      }
    }

    // (b) Plain CHANNEL (frame never sent) → next call does NOT re-handshake
    {
      const { a, b, link } = createFaultChannelPair();
      const srv = server(router, b, { auth: { secret: () => psk } });
      const wrapped = countingChannel(a);
      const { api, destroy } = client(wrapped.ch, {
        auth: { secret: () => psk },
        timeout: 5000,
        sendTimeout: 150,
      }) as unknown as { api: LooseApi; destroy: () => void };
      try {
        expect(await api.echo!("warm")).toBe("warm");
        expect(wrapped.hellos()).toBe(1);

        // Channel down → frame queues → sendTimeout → plain RPCError(CHANNEL) → no reset
        link.goDown();
        const err = await api.echo!("x").catch((e: unknown) => e);
        expect(err).toBeInstanceOf(RPCError);
        expect(err).not.toBeInstanceOf(RPCAbortedError);
        expect((err as RPCError).code).toBe("CHANNEL");

        link.goUp();
        // Session NOT reset: next call succeeds without re-handshake
        expect(await api.echo!("after")).toBe("after");
        expect(wrapped.hellos()).toBe(1);
      } finally {
        destroy();
        srv.destroy();
      }
    }
  });

  // ── Test 8: stale hello is revoked after handshakeTimeout ──
  it("stale hello is revoked after handshakeTimeout: goUp does not flush the dead hello", async () => {
    const psk = randomBytes(32);
    const { a, b, link } = createFaultChannelPair();
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
    };

    // Count hellos that actually arrive at the server
    let serverHellos = 0;
    const serverB: Channel = {
      send: (data) => b.send(data),
      receive(cb) {
        return b.receive((data) => {
          if (data[0] === TAG_HELLO) serverHellos++;
          cb(data);
        });
      },
    };

    const srv = server(router, serverB, { auth: { secret: () => psk } });
    const { api, destroy } = client(a, {
      auth: { secret: () => psk },
      timeout: 2000,
      sendTimeout: 500,
      handshakeTimeout: 100, // minimum allowed; fires quickly
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      // Channel down before any call — hello queues in core instead of sending.
      // Attach .catch() immediately so the rejection (at handshakeTimeout) is
      // never unhandled during the sleep below.
      link.goDown();
      const p = api.echo!("x").catch(() => {}); // triggers handshake; hello enters core queue

      // Wait beyond handshakeTimeout; the attempt is abandoned and epoch advances
      await sleep(150);

      link.goUp(); // core retry tick fires; dropStaleAndExpired revokes the stale hello
      await sleep(300); // one full retry tick (250 ms) plus margin

      // The dead hello must NOT have reached the server
      expect(serverHellos).toBe(0);
      await p; // catch already ran; just drain the promise

      // Fresh call: new handshake succeeds with a clean hello
      expect(await api.echo!("fresh")).toBe("fresh");
      expect(serverHellos).toBe(1); // only the fresh hello
    } finally {
      destroy();
      srv.destroy();
    }
  });

  // ── Test 9: shared-controller idiom replaces abortPending ──
  it("shared AbortController aborts two calls (class per sent status); third call succeeds", async () => {
    const psk = randomBytes(32);
    const { a, b, link } = createFaultChannelPair();
    const gate = deferred<string>();
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
      gated: chain().handler(async () => gate.promise),
    };
    const srv = server(router, b, { auth: { secret: () => psk } });
    const wrapped = countingChannel(a);
    const { api, destroy } = client(wrapped.ch, {
      auth: { secret: () => psk },
      timeout: 5000,
      sendTimeout: 500,
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      expect(await api.echo!("warm")).toBe("warm");
      expect(wrapped.hellos()).toBe(1);

      const ctl = new AbortController();

      // Call 1: gated → frame sent, awaiting reply
      const p1 = api.gated!(undefined, { signal: ctl.signal });
      await sleep(30); // frame reaches server

      // Call 2: channel down → frame queues in core
      link.goDown();
      const p2 = api.echo!("two", { signal: ctl.signal });
      await sleep(20);

      ctl.abort("bulk-cancel");

      const [e1, e2] = await Promise.all([
        p1.catch((e: unknown) => e),
        p2.catch((e: unknown) => e),
      ]);

      // Call 1 was sent → RPCAbortedError("ABORTED")
      expect(e1).toBeInstanceOf(RPCAbortedError);
      expect((e1 as RPCAbortedError).code).toBe("ABORTED");

      // Call 2 was queued → plain RPCError("ABORTED")
      expect(e2).toBeInstanceOf(RPCError);
      expect(e2).not.toBeInstanceOf(RPCAbortedError);
      expect((e2 as RPCError).code).toBe("ABORTED");

      gate.resolve("late"); // late reply silently dropped
      link.goUp();
      await sleep(20);

      // Session untouched: third call succeeds without re-handshake
      expect(await api.echo!("three")).toBe("three");
      expect(wrapped.hellos()).toBe(1);
    } finally {
      destroy();
      srv.destroy();
    }
  });
});
