/**
 * Type-test fixture — the app's saferpc init file (like a `trpc.ts`).
 *
 * Mirrors the recommended real-world layout: initialise once, bind the
 * context type, and export the instance so *other* files can author
 * procedures with a fully-typed `ctx`. `rpc` IS the procedure builder;
 * `rpc.router` / `rpc.middleware` hang off it.
 */
import { saferpc, RPCError } from "../../src/index.ts";

/** A context described with an `interface` — the exact shape that used to
 *  break, because interfaces are not assignable to `Record<string, unknown>`. */
export interface AppContext {
  user: { id: string; name: string } | null;
  db: { now(): number };
}

export const rpc = saferpc<AppContext>();

/** A reusable middleware that narrows `user` to non-null for downstream steps. */
export const authed = rpc.middleware(async ({ ctx, next }) => {
  if (ctx.user === null) {
    throw new RPCError("UNAUTHORIZED", "login required");
  }
  return next({ user: ctx.user });
});
