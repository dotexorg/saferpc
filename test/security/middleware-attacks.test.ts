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
    const srv = server(router, a, { auth: { psk: () => psk } });
    const { api, destroy } = client(b, { auth: { psk: () => psk }, timeout: 1000 });
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
    const srv = server(router, a, { auth: { psk: () => psk } });
    const { api, destroy } = client(b, { auth: { psk: () => psk }, timeout: 1000 });
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
    const srv = server(router, a, { auth: { psk: () => psk } });
    const { api, destroy } = client(b, { auth: { psk: () => psk }, timeout: 1000 });
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
    const srv = server(router, a, { auth: { psk: () => psk } });
    const { api, destroy } = client(b, { auth: { psk: () => psk }, timeout: 1000 });
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
