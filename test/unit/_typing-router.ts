/**
 * Type-test fixture — procedures authored in a *separate file* from the
 * `saferpc()` init. This is the scenario from the bug report: writing the
 * router elsewhere must still give a fully-typed `ctx` and Zod-inferred
 * input/output, with no manual `ctx as ...` casts.
 */
import { z } from "zod";
import { rpc, authed } from "./_typing-rpc.ts";

export const greet = rpc
  .input(z.object({ name: z.string() }))
  .output(z.object({ message: z.string() }))
  .handler(async ({ ctx, input }) => {
    // `ctx` is AppContext (typed across the file boundary), `input` is parsed.
    const who = ctx.user ? ctx.user.name : input.name;
    return { message: `Hello, ${who}!` };
  });

export const add = rpc
  .input(z.object({ a: z.number(), b: z.number() }))
  .handler(async ({ input }) => ({ sum: input.a + input.b }));

// Output transform: handler returns the pre-parse (INPUT) type; callers
// observe the post-parse (OUTPUT) type. Previously this failed to compile.
export const parseId = rpc
  .input(z.object({ raw: z.string() }))
  .output(z.object({ id: z.coerce.number() }))
  .handler(async ({ input }) => ({ id: input.raw })); // id: string here, number for callers

// Reusable middleware from another file narrows the context.
export const me = rpc
  .use(authed)
  .handler(async ({ ctx }) => ({ id: ctx.user.id, name: ctx.user.name }));

export const appRouter = rpc.router({ greet, add, parseId, me });
export type AppRouter = typeof appRouter;
