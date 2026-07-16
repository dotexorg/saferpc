/**
 * Middleware-pipeline misuse on the server side:
 *   - middleware that calls next() twice → MIDDLEWARE error
 *   - next(extra) with a non-object → MIDDLEWARE error
 *   - input validation runs *after* middleware (auth-then-validate)
 *   - middleware throwing RPCError surfaces faithfully (not as INTERNAL)
 */
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
import { createChannelPair } from "../helpers/channels.ts";

describe("security / middleware pipeline", () => {
  it("middleware calling next() twice yields MIDDLEWARE error", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const router: Router = {
      doubleNext: chain()
        .use(async ({ next }) => {
          await next();
          return next();
        })
        .handler(async () => "ok"),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      try {
        await api.doubleNext({});
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RemoteRPCError);
        expect((err as RemoteRPCError).code).toBe("MIDDLEWARE");
      }
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("middleware passing a non-object to next() yields MIDDLEWARE error", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const router: Router = {
      badNext: chain()
        .use(async ({ next }) => next(42 as unknown as Record<string, unknown>))
        .handler(async () => "ok"),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      try {
        await api.badNext({});
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RemoteRPCError);
        expect((err as RemoteRPCError).code).toBe("MIDDLEWARE");
      }
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("input validation runs after middleware (auth-then-validate)", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    let mwRan = false;
    const router: Router = {
      authValidate: chain()
        .use(async ({ next }) => {
          mwRan = true;
          return next();
        })
        .input(z.object({ id: z.string() }))
        .handler(async ({ input }) => (input as { id: string }).id),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      try {
        await api.authValidate({ id: 42 });
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RemoteRPCError);
        expect((err as RemoteRPCError).code).toBe("INPUT_VALIDATION");
        expect(mwRan).toBe(true);
      }
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("late next() cannot run the handler after middleware completion", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    let invocations = 0;
    const router: Router = {
      lateNext: chain()
        .use(({ next }) => {
          setTimeout(() => {
            void next();
          }, 10);
          return Promise.resolve("ignored" as never);
        })
        .handler(async () => {
          invocations++;
          return "must-not-run";
        }),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      await expect(api.lateNext({})).rejects.toMatchObject({
        code: "MIDDLEWARE",
      });
      await new Promise((resolve) => setTimeout(resolve, 30));
      expect(invocations).toBe(0);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("late next() cannot run the handler after a synchronous throw", async () => {
    // The sync-throw variant of the zombie-handler hole: `completed` must be
    // set even when the middleware never produces a promise at all.
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    let invocations = 0;
    const router: Router = {
      syncThrow: chain()
        .use((({ next }: { next: () => Promise<unknown> }) => {
          setTimeout(() => {
            void next().catch(() => {});
          }, 10);
          throw new Error("sync boom");
        }) as never)
        .handler(async () => {
          invocations++;
          return "must-not-run";
        }),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      await expect(api.syncThrow({})).rejects.toMatchObject({
        code: "INTERNAL",
      });
      await new Promise((resolve) => setTimeout(resolve, 30));
      expect(invocations).toBe(0);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("sync middleware returning a non-promise after fire-and-forget next() is rejected", async () => {
    // Spec: the next() promise must have settled before the middleware
    // completes. A middleware that returns its own value while the downstream
    // is still pending would hand the client a success and silently drop the
    // handler outcome — rejected as MIDDLEWARE (tRPC: “did you forget to
    // `return next()`?”). The handler delays so the downstream is genuinely
    // pending at middleware completion.
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const router: Router = {
      syncReturn: chain()
        .use((({ next }: { next: () => Promise<unknown> }) => {
          void next();
          return "sync-value";
        }) as never)
        .handler(async () => {
          await new Promise((resolve) => setTimeout(resolve, 20));
          return "handler-value";
        }),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      await expect(api.syncReturn({})).rejects.toMatchObject({
        code: "MIDDLEWARE",
      });
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("fire-and-forget next() is rejected and does not leak an unhandledRejection (#7)", async () => {
    // The regression scenario: middleware replies while the downstream is
    // still pending, and the downstream REJECTS LATER. The request must fail
    // closed with MIDDLEWARE, and the detached rejection must still be
    // observed by the runtime — otherwise it surfaces as an
    // unhandledRejection that can terminate the process.
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on("unhandledRejection", onUnhandled);
    const router: Router = {
      fireForget: chain()
        .use((({ next }: { next: () => Promise<unknown> }) => {
          void next(); // fire-and-forget: not awaited, not returned
          return "outer-success";
        }) as never)
        .handler(async () => {
          await new Promise((resolve) => setTimeout(resolve, 20));
          throw new Error("downstream-boom");
        }),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      await expect(api.fireForget({})).rejects.toMatchObject({
        code: "MIDDLEWARE",
      });
      // Let the delayed downstream rejection fire and get a chance to be
      // reported as unhandled.
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(
        unhandled.some((r) =>
          String((r as Error | undefined)?.message ?? r).includes(
            "downstream-boom",
          ),
        ),
      ).toBe(false);
    } finally {
      process.off("unhandledRejection", onUnhandled);
      destroy();
      srv.destroy();
    }
  });

  it("awaiting next() and returning a transformed value is accepted", async () => {
    // The supported forms: `return next()` and `await next()` + own return.
    // The downstream settled before the middleware completed, so the check
    // must not fire.
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const router: Router = {
      passThrough: chain()
        .use(async ({ next }) => next())
        .handler(async () => "plain"),
      transform: chain()
        // Type-illegal on purpose (the phantom MiddlewareResult requires
        // returning next()'s result) — this asserts the RUNTIME behavior:
        // downstream settled before completion, own value becomes the reply.
        .use((async ({ next }: { next: () => Promise<unknown> }) => {
          const inner = await next();
          return `wrapped:${String(inner)}`;
        }) as never)
        .handler(async () => "plain"),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      await expect(api.passThrough({})).resolves.toBe("plain");
      await expect(api.transform({})).resolves.toBe("wrapped:plain");
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("middleware catching a downstream rejection and returning a fallback is accepted", async () => {
    // Error-handling middleware: awaits next(), downstream rejects, the
    // middleware swallows it and answers with its own value. The downstream
    // HAS settled (rejected), so this remains a supported pattern.
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const router: Router = {
      recover: chain()
        // Type-illegal on purpose (see transform above) — asserts runtime
        // tolerance of the catch-fallback form.
        .use((async ({ next }: { next: () => Promise<unknown> }) => {
          try {
            return await next();
          } catch {
            return "fallback";
          }
        }) as never)
        .handler(async () => {
          throw new Error("handler-boom");
        }),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      await expect(api.recover({})).resolves.toBe("fallback");
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("middleware-thrown RPCError is not masked as INTERNAL", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const router: Router = {
      gated: chain()
        .use(async () => {
          throw new RPCError("FORBIDDEN", "access denied", { reason: "x" });
        })
        .handler(async () => "ok"),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      try {
        await api.gated({});
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RemoteRPCError);
        expect((err as RemoteRPCError).code).toBe("FORBIDDEN");
        expect((err as RemoteRPCError).message).toBe("access denied");
      }
    } finally {
      destroy();
      srv.destroy();
    }
  });
});
