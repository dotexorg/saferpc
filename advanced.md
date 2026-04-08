# Advanced Usage

## Middleware & Context

Middleware lets you add logic before the handler runs — authentication, logging, data transformation. Chain middleware with `.use()`. Each middleware can extend the context.

```typescript
import { chain, RPCError } from "@dotex/erpc/common";

const d = chain();

const authProcedure = d.use(async ({ ctx, input, next }) => {
  const user = await getUser(ctx.token);
  if (!user) throw new RPCError("UNAUTHORIZED", "Bad token");
  return next({ user }); // merges { user } into ctx
});

const router = {
  getProfile: authProcedure
    .input(z.object({ id: z.string() }))
    .handler(async ({ ctx, input }) => {
      // ctx.user is available here
      return db.getProfile(input.id);
    }),
};
```

Set the base context on the server via `context`:

```typescript
server(router, channel, {
  psk,
  context: () => ({ token: getCurrentToken() }),
});
```

The `context` factory is called **on every request**, so the context is always fresh.

## Auto-Retry

When an RPC call fails due to a timeout or send error, the client automatically retries once with a fresh handshake:

```
api.foo("x")
  │
  ├─ sendRequest() → timeout (server died)
  │
  ├─ epoch === sentEpoch? → YES → reset() (zero keys, state → idle)
  ├─ ensureHandshake() → new handshake (epoch++)
  │   └─ hello → reply → ready
  └─ sendRequest() again → success → api.foo() resolves
```

Concurrent calls that fail at the same time **share a single handshake** via epoch check — reset happens only once.

### Retry Rules

- `RemoteRPCError` (server responded with an error) — **no retry**, thrown immediately
- `destroy()` was called — **no retry**, thrown immediately
- Retry happens **exactly once** per call — no infinite loops
- Only the first failed call triggers reset; others piggyback on the new handshake

## Re-Handshake

The server accepts a new hello even when already in `ready` state. This enables transparent session refresh:

```
Client (ready)         Server (ready)
    │                      │
    │  Session dies         │
    │                      │
    │  reset()             │
    │  state → idle        │
    │                      │
    │  ── new hello ──►    │
    │                      │  resetHandshake()
    │                      │  state → waiting → pending
    │                      │
    │  ◄── reply ────      │
    │  state → ready       │
    │                      │
    │  ── retry RPC ──►    │
    │                      │  state → ready (confirmed)
    │  ◄── response ──     │
    │  Call resolves        │
```

## Cleanup

Always call `destroy()` when you're done:

```typescript
const { destroy: destroyServer } = server(router, channel, { psk });
const { api, destroy: destroyClient } = client<typeof router>(channel, { psk });

// When shutting down:
destroyClient(); // rejects all pending calls, zeros keys
destroyServer(); // zeros keys, unsubscribes from channel
```

After `destroy()`, any call throws `RPCError("SESSION", "Session destroyed")`.

## Edge Runtime Compatibility

Both `server()` and `client()` return **synchronously**. No top-level `await`. Pure JavaScript dependencies. This means eRPC works in environments with async initialization restrictions:

- Cloudflare Workers / Durable Objects
- Deno Deploy
- Vercel Edge Functions
- Service Workers
- React Native
