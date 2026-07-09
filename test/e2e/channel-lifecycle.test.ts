/**
 * Channel lifecycle — 0.7.0: the session is bound to key material, not to a
 * transport instance. Transport death alone must not destroy the session or
 * reject calls; a call's outcome is decided by exactly two events — a reply
 * that decrypts, or the call's own timeout. Plus per-call AbortSignal.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  chain,
  client,
  server,
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

/** Wrap a channel to count outbound hello frames (handshake attempts). */
function countingChannel(ch: Channel): { ch: Channel; hellos: () => number } {
  let n = 0;
  return {
    ch: {
      send(data) {
        if (data[0] === TAG_HELLO) n++;
        return ch.send(data);
      },
      receive: (cb) => ch.receive(cb),
    },
    hellos: () => n,
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("channel lifecycle / session survives transport death", () => {
  it("a call issued while the channel is down completes after recovery, without a second handshake", async () => {
    const psk = randomBytes(32);
    const { a, b, link } = createFaultChannelPair();
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
    };
    const srv = server(router, b, { auth: { secret: () => psk } });
    const wrapped = countingChannel(a);
    const { api, destroy } = client(wrapped.ch, {
      auth: { secret: () => psk },
      timeout: 1000,
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      expect(await api.echo!("warm")).toBe("warm");

      link.goDown();
      const p = api.echo!("during-gap"); // frame queues at the sender
      await sleep(50);
      link.goUp();

      expect(await p).toBe("during-gap");
      expect(wrapped.hellos()).toBe(1); // session survived, no re-handshake
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("a reply produced while the channel is down is delivered after recovery", async () => {
    const psk = randomBytes(32);
    const { a, b, link } = createFaultChannelPair();
    const gate = deferred<string>();
    const router: Router = {
      gated: chain().handler(async () => gate.promise),
    };
    const srv = server(router, b, { auth: { secret: () => psk } });
    const { api, destroy } = client(a, {
      auth: { secret: () => psk },
      timeout: 1000,
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      const p = api.gated!(); // request delivered; handler awaiting the gate
      await sleep(20);
      link.goDown(); // reply will be produced into a dead link
      gate.resolve("late");
      await sleep(50);
      link.goUp(); // queued reply flushes

      expect(await p).toBe("late"); // reply-or-timeout rule, reply branch
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("a lost server session heals lazily: first call times out, second re-handshakes", async () => {
    const psk = randomBytes(32);
    const { a, b, link } = createFaultChannelPair();
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
    };
    let srv = server(router, b, { auth: { secret: () => psk } });
    const wrapped = countingChannel(a);
    const { api, destroy } = client(wrapped.ch, {
      auth: { secret: () => psk },
      timeout: 300,
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      expect(await api.echo!("warm")).toBe("warm");

      link.goDown();
      srv.destroy(); // peer restarted: server session is gone
      srv = server(router, b, { auth: { secret: () => psk } });
      link.goUp();

      // Kept client session is dead weight now: the frame doesn't decrypt,
      // the server stays silent, the call times out and resets the session.
      await expect(api.echo!("stale")).rejects.toMatchObject({
        code: "TIMEOUT",
      });
      // Next call lazily re-handshakes and succeeds.
      expect(await api.echo!("fresh")).toBe("fresh");
      expect(wrapped.hellos()).toBe(2);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("abortPending rejects pending calls but keeps the session", async () => {
    const psk = randomBytes(32);
    const { a, b, link } = createFaultChannelPair();
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
    };
    const srv = server(router, b, { auth: { secret: () => psk } });
    const wrapped = countingChannel(a);
    const { api, abortPending, destroy } = client(wrapped.ch, {
      auth: { secret: () => psk },
      timeout: 5000,
    }) as unknown as {
      api: LooseApi;
      abortPending: () => void;
      destroy: () => void;
    };
    try {
      expect(await api.echo!("warm")).toBe("warm");

      link.goDown();
      const p1 = api.echo!("one");
      const p2 = api.echo!("two");
      await sleep(20); // let both calls register as pending
      abortPending();
      await expect(p1).rejects.toMatchObject({ code: "ABORTED" });
      await expect(p2).rejects.toMatchObject({ code: "ABORTED" });

      link.goUp(); // stale queued requests flush; replies find no pending
      expect(await api.echo!("three")).toBe("three");
      expect(wrapped.hellos()).toBe(1); // keys were never zeroed
    } finally {
      destroy();
      srv.destroy();
    }
  });
});

describe("channel lifecycle / per-call AbortSignal", () => {
  it("a pre-aborted signal rejects immediately and triggers nothing", async () => {
    const psk = randomBytes(32);
    const { a, b } = createFaultChannelPair();
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
    };
    const srv = server(router, b, { auth: { secret: () => psk } });
    const wrapped = countingChannel(a);
    const { api, destroy } = client(wrapped.ch, {
      auth: { secret: () => psk },
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      const ac = new AbortController();
      ac.abort();
      await expect(api.echo!("x", { signal: ac.signal })).rejects.toMatchObject(
        { code: "ABORTED" },
      );
      expect(wrapped.hellos()).toBe(0); // no handshake was even started
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("abort mid-flight rejects with ABORTED, drops the late reply, and never resets the session", async () => {
    const psk = randomBytes(32);
    const { a, b } = createFaultChannelPair();
    const gate = deferred<string>();
    const router: Router = {
      gated: chain().handler(async () => gate.promise),
      echo: chain().handler(async ({ input }) => input),
    };
    const srv = server(router, b, { auth: { secret: () => psk } });
    const wrapped = countingChannel(a);
    const { api, destroy } = client(wrapped.ch, {
      auth: { secret: () => psk },
      timeout: 5000,
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      expect(await api.echo!("warm")).toBe("warm");

      const ac = new AbortController();
      const p = api.gated!(undefined, { signal: ac.signal });
      await sleep(20);
      ac.abort();
      const err = (await p.then(
        () => null,
        (e: unknown) => e,
      )) as { code: string; cause?: unknown };
      expect(err).not.toBeNull();
      expect(err.code).toBe("ABORTED");
      expect(err.cause).toBeDefined(); // signal.reason travels on .cause

      gate.resolve("late"); // late reply → no pending entry → silent drop
      await sleep(20);

      // Session untouched: no reset predicate fired on ABORTED.
      expect(await api.echo!("after")).toBe("after");
      expect(wrapped.hellos()).toBe(1);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("aborting one call during a shared handshake leaves the handshake for others", async () => {
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
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      link.goDown(); // hello will queue → handshake stays in progress
      const ac = new AbortController();
      const p1 = api.echo!("one", { signal: ac.signal });
      const p2 = api.echo!("two"); // joins the same handshake
      await sleep(20);
      ac.abort();
      await expect(p1).rejects.toMatchObject({ code: "ABORTED" });

      link.goUp(); // hello flushes; the shared handshake completes
      expect(await p2).toBe("two");
      expect(wrapped.hellos()).toBe(1);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("AbortSignal.timeout gives one call a shorter budget than the client default", async () => {
    const psk = randomBytes(32);
    const { a, b } = createFaultChannelPair();
    const gate = deferred<string>();
    const router: Router = {
      gated: chain().handler(async () => gate.promise),
      echo: chain().handler(async ({ input }) => input),
    };
    const srv = server(router, b, { auth: { secret: () => psk } });
    const wrapped = countingChannel(a);
    const { api, destroy } = client(wrapped.ch, {
      auth: { secret: () => psk },
      timeout: 60_000, // client default deliberately huge
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      expect(await api.echo!("warm")).toBe("warm");

      // The blessed per-call pattern: shorter budget via the platform's
      // AbortSignal.timeout — rejects with ABORTED, session untouched.
      const started = Date.now();
      await expect(
        api.gated!(undefined, { signal: AbortSignal.timeout(100) }),
      ).rejects.toMatchObject({ code: "ABORTED" });
      expect(Date.now() - started).toBeLessThan(2000);

      gate.resolve("late"); // late reply → silently dropped
      expect(await api.echo!("after")).toBe("after");
      expect(wrapped.hellos()).toBe(1); // no reset, no re-handshake
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("abort listeners are removed once the call settles", async () => {
    const psk = randomBytes(32);
    const { a, b } = createFaultChannelPair();
    const router: Router = {
      echo: chain().handler(async ({ input }) => input),
    };
    const srv = server(router, b, { auth: { secret: () => psk } });
    const { api, destroy } = client(a, {
      auth: { secret: () => psk },
    }) as unknown as { api: LooseApi; destroy: () => void };
    try {
      // Stub signal that counts registered listeners — a long-lived signal
      // reused across calls must not accumulate closures.
      const listeners = new Set<unknown>();
      const stub = {
        aborted: false,
        reason: undefined,
        addEventListener(_t: string, cb: unknown) {
          listeners.add(cb);
        },
        removeEventListener(_t: string, cb: unknown) {
          listeners.delete(cb);
        },
      } as unknown as AbortSignal;

      expect(await api.echo!("a", { signal: stub })).toBe("a");
      expect(listeners.size).toBe(0);
      expect(await api.echo!("b", { signal: stub })).toBe("b");
      expect(listeners.size).toBe(0);
    } finally {
      destroy();
      srv.destroy();
    }
  });
});
