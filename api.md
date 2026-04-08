# API Reference

## `chain()` — Procedure Builder

```typescript
import { chain } from "@dotex/erpc/common";
```

`chain()` creates a builder for defining procedures: input, output, middleware, and handler. All methods are chainable.

```typescript
const d = chain();

const procedure = d
  .use(middlewareFn)          // add middleware
  .input(zodSchema)           // validate and type input
  .output(zodSchema)          // validate and type output
  .handler(async ({ ctx, input }) => result);  // terminal handler
```

`.handler()` terminates the chain and returns a frozen `Procedure` object.

## `server(router, channel, options)`

Creates a server that listens on the given channel. Returns `{ destroy }`.

```typescript
import { server } from "@dotex/erpc/server";

const { destroy } = server(router, channel, {
  psk,
  context: () => ({ token: getCurrentToken() }),
  onError: console.error,
});
```

### Server Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `psk` | `Uint8Array` | **required** | Pre-shared key, minimum 32 bytes |
| `context` | `() => Ctx \| Promise<Ctx>` | — | Per-request context factory |
| `handshakeTimeout` | `number` | `5000` | Handshake timeout (ms) |
| `maxMessageBytes` | `number` | `1048576` | Max message size (1 MB) |
| `onError` | `(err: unknown) => void` | — | Callback for handshake/send errors |

## `client<Router>(channel, options)`

Creates a client. Returns `{ api, destroy }`.

```typescript
import { client } from "@dotex/erpc/client";

const { api, destroy } = client<typeof router>(clientChannel, {
  psk,
  timeout: 10000,
});
```

### Client Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `psk` | `Uint8Array` | **required** | Pre-shared key, minimum 32 bytes |
| `timeout` | `number` | `10000` | Per-call timeout (ms) |
| `maxPending` | `number` | `256` | Max concurrent in-flight calls |
| `handshakeTimeout` | `number` | `5000` | Handshake timeout (ms) |
| `maxMessageBytes` | `number` | `1048576` | Max message size (1 MB) |

The `api` proxy triggers the handshake lazily on first call. Client creation is synchronous — no `await` needed.

## `Channel` Interface

Any transport must implement this interface:

```typescript
interface Channel {
  send(data: Uint8Array): void | Promise<void>;
  receive(cb: (data: Uint8Array) => void): () => void; // returns unsubscribe
}
```

`send` transmits binary data. `receive` subscribes to incoming data and returns an unsubscribe function. See [Integrations](integrations.md) for ready-made adapters.

## Errors

```typescript
import { RPCError, RemoteRPCError } from "@dotex/erpc/common";
```

Two error types:

- **`RPCError`** — local error (timeout, session lost, client/handshake failure)
- **`RemoteRPCError`** — error from the remote peer (extends `RPCError`). Contains `code`, `message`, `data`

### Error Handling

```typescript
try {
  await api.foo(input);
} catch (err) {
  if (err instanceof RemoteRPCError) {
    // Server returned an error — err.code, err.message, err.data
  } else if (err instanceof RPCError) {
    // Local failure — timeout, session lost, etc.
  }
}
```
