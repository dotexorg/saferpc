import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";
import {
  chain,
  client,
  server,
  RPCError,
  RemoteRPCError,
  type Router,
} from "../../src/index.ts";
import {
  createChannelPair,
  createAsyncChannelPair,
  createMitmChannelPair,
} from "../helpers/channels.ts";

function buildRouter(): Router {
  return {
    greet: chain()
      .input(z.object({ name: z.string() }))
      .output(z.object({ message: z.string() }))
      .handler(async ({ input }) => ({
        message: `Hello, ${(input as { name: string }).name}!`,
      })),

    add: chain()
      .input(z.object({ a: z.number(), b: z.number() }))
      .output(z.object({ sum: z.number() }))
      .handler(async ({ input }) => {
        const i = input as { a: number; b: number };
        return { sum: i.a + i.b };
      }),

    echo: chain().handler(async ({ input }) => input),

    boom: chain().handler(async () => {
      throw new RPCError("CUSTOM_ERROR", "intentional", { detail: 42 });
    }),

    boomNative: chain().handler(async () => {
      throw new Error("native boom");
    }),

    auth: chain()
      .use(async ({ ctx, next }) => {
        if ((ctx as { token?: string }).token !== "secret") {
          throw new RPCError("UNAUTHORIZED", "bad token");
        }
        return next({ user: { id: "u1" } });
      })
      .handler(async ({ ctx }) => ({
        user: (ctx as { user: { id: string } }).user,
      })),
  };
}

describe("in-memory / handshake & basic RPC", () => {
  it("completes the handshake on the first call and returns the result", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const srv = server(buildRouter(), a, { psk });
    const { api, destroy } = client(b, { psk, timeout: 2000 });
    try {
      expect(await api.greet({ name: "world" })).toEqual({
        message: "Hello, world!",
      });
      expect(await api.add({ a: 3, b: 4 })).toEqual({ sum: 7 });
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("works over an async (microtask-deferred) channel", async () => {
    const psk = randomBytes(32);
    const { a, b } = createAsyncChannelPair();
    const srv = server(buildRouter(), a, { psk });
    const { api, destroy } = client(b, { psk, timeout: 2000 });
    try {
      expect(await api.add({ a: 1, b: 2 })).toEqual({ sum: 3 });
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("preserves Uint8Array round-trip through procedures", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const router: Router = {
      bin: chain().handler(async ({ input }) => ({
        blob: (input as { blob: Uint8Array }).blob,
      })),
    };
    const srv = server(router, a, { psk });
    const { api, destroy } = client(b, { psk, timeout: 2000 });
    try {
      const blob = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      const result = (await api.bin({ blob })) as { blob: Uint8Array };
      expect(result.blob).toBeInstanceOf(Uint8Array);
      expect(Array.from(result.blob)).toEqual([0xde, 0xad, 0xbe, 0xef]);
    } finally {
      destroy();
      srv.destroy();
    }
  });
});

describe("in-memory / errors", () => {
  it("raises RemoteRPCError(NOT_FOUND) for an unknown procedure", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const srv = server({} as Router, a, { psk });
    const { api, destroy } = client(b, { psk, timeout: 1000 });
    try {
      await expect(api.nonexistent({})).rejects.toThrow(RemoteRPCError);
      try {
        await api.nonexistent({});
      } catch (err) {
        expect((err as RemoteRPCError).code).toBe("NOT_FOUND");
      }
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("propagates RPCError code, message, and data from the handler", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const srv = server(buildRouter(), a, { psk });
    const { api, destroy } = client(b, { psk, timeout: 1000 });
    try {
      try {
        await api.boom({});
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RemoteRPCError);
        expect((err as RemoteRPCError).code).toBe("CUSTOM_ERROR");
        expect((err as RemoteRPCError).message).toBe("intentional");
        expect((err as RemoteRPCError).data).toEqual({ detail: 42 });
      }
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("masks non-RPCError throws as INTERNAL with no leaked detail", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const srv = server(buildRouter(), a, { psk });
    const { api, destroy } = client(b, { psk, timeout: 1000 });
    try {
      try {
        await api.boomNative({});
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RemoteRPCError);
        const e = err as RemoteRPCError;
        expect(e.code).toBe("INTERNAL");
        expect(e.message).not.toContain("native boom");
        expect(e.data).toBeNull();
      }
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("validates input via Zod and returns INPUT_VALIDATION", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const srv = server(buildRouter(), a, { psk });
    const { api, destroy } = client(b, { psk, timeout: 1000 });
    try {
      try {
        await api.add({ a: "not-a-number", b: 2 });
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RemoteRPCError);
        expect((err as RemoteRPCError).code).toBe("INPUT_VALIDATION");
      }
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("validates output via Zod and returns OUTPUT_VALIDATION", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const router: Router = {
      lying: chain()
        .output(z.object({ s: z.string() }))
        .handler(async () => ({ s: 42 } as unknown as { s: string })),
    };
    const srv = server(router, a, { psk });
    const { api, destroy } = client(b, { psk, timeout: 1000 });
    try {
      try {
        await api.lying({});
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RemoteRPCError);
        expect((err as RemoteRPCError).code).toBe("OUTPUT_VALIDATION");
      }
    } finally {
      destroy();
      srv.destroy();
    }
  });
});

describe("in-memory / context & middleware", () => {
  it("injects base ctx via context() and gates access via middleware", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const srv = server(buildRouter(), a, {
      psk,
      context: () => ({ token: "secret" }),
    });
    const { api, destroy } = client(b, { psk, timeout: 1000 });
    try {
      expect(await api.auth({})).toEqual({ user: { id: "u1" } });
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("rejects when middleware throws UNAUTHORIZED", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const srv = server(buildRouter(), a, {
      psk,
      context: () => ({ token: "wrong" }),
    });
    const { api, destroy } = client(b, { psk, timeout: 1000 });
    try {
      try {
        await api.auth({});
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RemoteRPCError);
        expect((err as RemoteRPCError).code).toBe("UNAUTHORIZED");
      }
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("calls context() per request", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    let count = 0;
    const router: Router = {
      counter: chain().handler(async ({ ctx }) => ({
        n: (ctx as { n: number }).n,
      })),
    };
    const srv = server(router, a, {
      psk,
      context: () => ({ n: ++count }),
    });
    const { api, destroy } = client(b, { psk, timeout: 1000 });
    try {
      expect(await api.counter({})).toEqual({ n: 1 });
      expect(await api.counter({})).toEqual({ n: 2 });
      expect(await api.counter({})).toEqual({ n: 3 });
    } finally {
      destroy();
      srv.destroy();
    }
  });
});

describe("in-memory / concurrency", () => {
  it("handles many concurrent calls without crossing wires", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const srv = server(buildRouter(), a, { psk });
    const { api, destroy } = client(b, { psk, timeout: 5000 });
    try {
      const N = 100;
      const calls: Array<Promise<unknown>> = [];
      for (let i = 0; i < N; i++) calls.push(api.add({ a: i, b: 1 }));
      const results = (await Promise.all(calls)) as Array<{ sum: number }>;
      for (let i = 0; i < N; i++) expect(results[i]!.sum).toBe(i + 1);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("shares a single handshake across concurrent first calls", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    const srv = server(buildRouter(), a, { psk });
    const { api, destroy } = client(b, { psk, timeout: 5000 });
    try {
      await Promise.all([
        api.add({ a: 1, b: 1 }),
        api.add({ a: 2, b: 2 }),
        api.add({ a: 3, b: 3 }),
      ]);

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

describe("in-memory / lifecycle", () => {
  it("rejects all in-flight calls on destroy()", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const router: Router = {
      slow: chain().handler(
        async () =>
          new Promise<string>((r) => setTimeout(() => r("done"), 100)),
      ),
    };
    const srv = server(router, a, { psk });
    const { api, destroy } = client(b, { psk, timeout: 5000 });
    const p = api.slow({});
    setTimeout(destroy, 10);
    try {
      await p;
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(RPCError);
      expect((err as RPCError).code).toBe("SESSION");
    } finally {
      srv.destroy();
    }
  });

  it("throws SESSION error after destroy()", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const srv = server(buildRouter(), a, { psk });
    const { api, destroy } = client(b, { psk, timeout: 1000 });
    try {
      await api.add({ a: 1, b: 1 });
      destroy();
      try {
        await api.add({ a: 1, b: 1 });
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RPCError);
        expect((err as RPCError).code).toBe("SESSION");
      }
    } finally {
      srv.destroy();
    }
  });

  it("server.destroy() leaves the client without a responder", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const srv = server(buildRouter(), a, { psk });
    const { api, destroy } = client(b, { psk, timeout: 500 });
    try {
      await api.add({ a: 1, b: 1 });
      srv.destroy();
      try {
        await api.add({ a: 2, b: 2 });
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RPCError);
        const code = (err as RPCError).code;
        expect(["TIMEOUT", "HANDSHAKE"]).toContain(code);
      }
    } finally {
      destroy();
    }
  });
});

describe("in-memory / construction guards", () => {
  it("throws if router is not an object", () => {
    const { a } = createChannelPair();
    expect(() =>
      server(null as unknown as Router, a, { psk: randomBytes(32) }),
    ).toThrow(TypeError);
    expect(() =>
      server("nope" as unknown as Router, a, { psk: randomBytes(32) }),
    ).toThrow(TypeError);
  });

  it("throws if channel is missing send or receive", () => {
    const psk = randomBytes(32);
    expect(() =>
      server(
        {} as Router,
        { send: () => {} } as never,
        { psk },
      ),
    ).toThrow(TypeError);
    expect(() =>
      server(
        {} as Router,
        { receive: () => () => {} } as never,
        { psk },
      ),
    ).toThrow(TypeError);

    expect(() =>
      client({ send: () => {} } as never, { psk }),
    ).toThrow(TypeError);
    expect(() =>
      client({ receive: () => () => {} } as never, { psk }),
    ).toThrow(TypeError);
  });

  it("throws on missing or short PSK", () => {
    const { a } = createChannelPair();
    expect(() => server({} as Router, a, {} as never)).toThrow(TypeError);
    expect(() => server({} as Router, a, { psk: randomBytes(16) })).toThrow(
      TypeError,
    );
    expect(() => client(a, { psk: randomBytes(16) })).toThrow(TypeError);
  });
});
