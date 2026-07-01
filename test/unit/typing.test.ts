/**
 * Typing suite — proves the builder/client types are correct AND ergonomic.
 *
 * Runtime `it()` blocks exercise `saferpc()` behaviour and one real typed
 * round-trip; `expectTypeOf` assertions are checked by `tsc`
 * (`npm run test:typecheck`) and are inert at runtime. The `_typeErrors`
 * function is never called — it only has to *type-check*, so its
 * `@ts-expect-error` lines assert that misuse is rejected.
 */
import { describe, it, expect, expectTypeOf } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import { z } from "zod";
import {
  saferpc,
  chain,
  client,
  server,
  RPCError,
  type Client,
  type Router,
  type Procedure,
  type ProcedureBuilder,
  type Channel,
  type inferInput,
  type inferOutput,
} from "../../src/index.ts";
import { createChannelPair } from "../helpers/channels.ts";
import { rpc, type AppContext } from "./_typing-rpc.ts";
import {
  greet,
  add,
  parseId,
  me,
  appRouter,
  type AppRouter,
} from "./_typing-router.ts";

describe("saferpc() — runtime shape", () => {
  it("returns the procedure builder itself, plus router & middleware", () => {
    const r = saferpc<AppContext>();
    // r IS the builder
    expect(r.input).toBeTypeOf("function");
    expect(r.use).toBeTypeOf("function");
    expect(r.output).toBeTypeOf("function");
    expect(r.handler).toBeTypeOf("function");
    // ...and namespaces the helpers
    expect(r.router).toBeTypeOf("function");
    expect(r.middleware).toBeTypeOf("function");
  });

  it("rpc.handler() builds the same frozen Procedure shape as chain()", () => {
    const proc = rpc.handler(async ({ input }) => input);
    expect(proc._handler).toBeTypeOf("function");
    expect(Array.isArray(proc._steps)).toBe(true);
    expect(Object.isFrozen(proc._steps)).toBe(true);
  });

  it("rpc.router() is an identity guard over the procedure map", () => {
    const routes = { greet };
    expect(rpc.router(routes)).toBe(routes);
    expect(() => rpc.router(null as unknown as Router)).toThrow(TypeError);
    expect(() => rpc.router("nope" as unknown as Router)).toThrow(TypeError);
  });

  it("rpc.middleware() returns the function and rejects non-functions", () => {
    const fn = async ({ next }: { next: () => Promise<never> }) => next();
    expect(rpc.middleware(fn as never)).toBe(fn);
    expect(() => rpc.middleware(null as never)).toThrow(TypeError);
  });
});

describe("procedure builder — context typing", () => {
  it("binds the initialised context type in a separate file", () => {
    // greet lives in _typing-router.ts and never annotates ctx by hand.
    // The 3rd param records the base context the server must supply.
    expectTypeOf(greet).toEqualTypeOf<
      Procedure<{ name: string }, { message: string }, AppContext>
    >();
  });

  it("accumulates middleware context via next({...})", () => {
    const proc = rpc
      .use(async ({ ctx, next }) => {
        expectTypeOf(ctx).toEqualTypeOf<AppContext>();
        return next({ requestId: "abc" });
      })
      .use(async ({ ctx, next }) => {
        // second middleware already sees the key the first one added
        expectTypeOf(ctx.requestId).toEqualTypeOf<string>();
        return next({ traceId: 7 });
      })
      .handler(async ({ ctx }) => {
        expectTypeOf(ctx.requestId).toEqualTypeOf<string>();
        expectTypeOf(ctx.traceId).toEqualTypeOf<number>();
        expectTypeOf(ctx.user).toEqualTypeOf<AppContext["user"]>();
        return null;
      });
    expect(proc._steps.length).toBe(2);
  });

  it("a reusable middleware narrows the context (user: non-null)", () => {
    // `me` uses the `authed` middleware from another file. Middleware grows
    // the handler ctx but NOT the base context recorded on the procedure.
    expectTypeOf(me).toEqualTypeOf<
      Procedure<unknown, { id: string; name: string }, AppContext>
    >();
  });
});

describe("procedure builder — zod input/output inference", () => {
  it("input(): caller sends z.input, handler receives z.output", () => {
    const proc = rpc
      .input(z.object({ page: z.number().default(1) }))
      .handler(async ({ input }) => {
        // parsed → page is required
        expectTypeOf(input).toEqualTypeOf<{ page: number }>();
        return input.page;
      });
    // caller side → page is optional (has a default)
    expectTypeOf<inferInput<typeof proc>>().toEqualTypeOf<{ page?: number }>();
    expectTypeOf<inferOutput<typeof proc>>().toEqualTypeOf<number>();
  });

  it("output(): handler returns pre-transform, caller sees post-transform", () => {
    // The exact case that used to error: handler returns { id: string },
    // the coerced schema turns it into a number for callers.
    expectTypeOf<inferInput<typeof parseId>>().toEqualTypeOf<{ raw: string }>();
    expectTypeOf<inferOutput<typeof parseId>>().toEqualTypeOf<{ id: number }>();
  });

  it("no output schema → caller output is inferred from the handler", () => {
    expectTypeOf<inferOutput<typeof add>>().toEqualTypeOf<{ sum: number }>();
    expectTypeOf<inferInput<typeof add>>().toEqualTypeOf<{
      a: number;
      b: number;
    }>();
  });
});

describe("procedure builder — sync or async handlers", () => {
  it("accepts a synchronous handler and infers its (awaited) output", () => {
    const sync = rpc
      .input(z.object({ x: z.number() }))
      .handler(({ input }) => ({ doubled: input.x * 2 })); // no async
    expectTypeOf<inferOutput<typeof sync>>().toEqualTypeOf<{
      doubled: number;
    }>();
    expect(sync._handler).toBeTypeOf("function");
  });

  it("accepts a sync handler under an output schema (pre-transform)", () => {
    const sync = rpc
      .output(z.object({ id: z.coerce.number() }))
      .handler(() => ({ id: "7" })); // sync + pre-transform string
    expectTypeOf<inferOutput<typeof sync>>().toEqualTypeOf<{ id: number }>();
    expect(sync._steps.length).toBe(1);
  });
});

describe("Client<Router> — end-to-end inference", () => {
  it("maps each procedure to a typed call", () => {
    type Api = Client<AppRouter>;
    expectTypeOf<Api["greet"]>().toEqualTypeOf<
      (input: { name: string }) => Promise<{ message: string }>
    >();
    expectTypeOf<Api["parseId"]>().toEqualTypeOf<
      (input: { raw: string }) => Promise<{ id: number }>
    >();
    expectTypeOf<Api["me"]>().toEqualTypeOf<
      (input: unknown) => Promise<{ id: string; name: string }>
    >();
  });

  it("a loose Router stays callable as (unknown) => Promise<unknown>", () => {
    type Loose = Client<Router>;
    expectTypeOf<Loose[string]>().toEqualTypeOf<
      (input: unknown) => Promise<unknown>
    >();
  });

  it("a precise router is assignable to the loose Router type", () => {
    const loose: Router = appRouter;
    expect(loose).toBe(appRouter);
  });
});

describe("chain() — backward-compatible alias", () => {
  it("still builds procedures with an empty context", () => {
    const proc = chain()
      .input(z.object({ x: z.number() }))
      .handler(async ({ input }) => input.x);
    expect(proc._steps.length).toBe(1);
    expectTypeOf(chain()).toEqualTypeOf<ProcedureBuilder>();
  });
});

describe("end-to-end — a typed client over a real handshake", () => {
  it("infers input & output through server + client", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const srv = server(appRouter, a, {
      auth: { secret: () => psk },
      context: () => ({
        user: { id: "u1", name: "Ada" },
        db: { now: () => 0 },
      }),
    });
    const { api, destroy } = client<AppRouter>(b, {
      auth: { secret: () => psk },
      timeout: 2000,
    });
    try {
      const greeting = await api.greet({ name: "world" });
      expectTypeOf(greeting).toEqualTypeOf<{ message: string }>();
      expect(greeting).toEqual({ message: "Hello, Ada!" });

      const parsed = await api.parseId({ raw: "42" });
      expectTypeOf(parsed).toEqualTypeOf<{ id: number }>();
      expect(parsed).toEqual({ id: 42 });
    } finally {
      destroy();
      srv.destroy();
    }
  });
});

/**
 * Never called — its only purpose is to make `tsc` reject misuse. Each
 * `@ts-expect-error` fails the type-check if the following line stops
 * being an error, which keeps the guarantees honest.
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function _typeErrors(): void {
  const api = {} as Client<AppRouter>;

  // wrong input shape
  // @ts-expect-error name must be a string
  void api.greet({ name: 123 });

  // procedure that does not exist on a precise router
  // @ts-expect-error unknown procedure
  void api.doesNotExist({});

  // handler must satisfy the output schema (id must be number-coercible input)
  rpc
    .output(z.object({ id: z.number() }))
    // @ts-expect-error handler returns a string, schema wants a number
    .handler(async () => ({ id: "not-a-number" }));

  // next() rejects a non-object extension
  rpc.use(async ({ next }) =>
    // @ts-expect-error 42 is not an object context extension
    next(42),
  );

  // a sync handler must still satisfy the output schema
  rpc
    .output(z.object({ n: z.number() }))
    // @ts-expect-error sync handler returns a string, schema wants a number
    .handler(() => ({ n: "nope" }));

  // ctx keys not added by a middleware are not visible
  rpc.handler(async ({ ctx }) => {
    // @ts-expect-error `requestId` was never added to the context
    void ctx.requestId;
    return null;
  });

  // ── server() demands a context() matching the router's base context ──
  const chan = {} as Channel;
  const auth = { secret: () => new Uint8Array(32) };

  // correct: context() returns the full AppContext
  server(appRouter, chan, {
    auth,
    context: () => ({ user: null, db: { now: () => 0 } }),
  });

  // @ts-expect-error appRouter needs AppContext, so `context` is required
  server(appRouter, chan, { auth });

  server(appRouter, chan, {
    auth,
    // @ts-expect-error context must return the full AppContext (db missing)
    context: () => ({ user: null }),
  });

  // a loose Router keeps `context` optional — this must NOT error
  server({} as Router, chan, { auth });
}
