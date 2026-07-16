# SafeRPC review findings — 2026-07-14

Reviewed `src/` and the current specs:

- `spec/protocol.md`
- `spec/security.md`
- `spec/api.md`
- `spec/integrations.md`

No `CLAUDE.md` exists in the current tree or in git history — only
`.claude/commands/release-notes.md`.

## 1. Multifactor helper does not bind factors to a single principal

**Priority:** high
**Code:** `src/auth/server.ts:277-300`

Both factors are verified independently, then their auth data is combined with a
shallow merge:

```ts
{
  ...primaryAuth,
  ...secondaryAuth,
  multifactor: true,
}
```

As a result, a valid JWT from one user plus a valid device key from a *different*
user produce a combined result like:

```ts
{
  sub: "user-a",
  deviceId: "device-of-user-b",
  multifactor: true,
}
```

If downstream authorization keys only on `sub`, the system treats this
combination as genuine MFA even though the factors belong to different
principals.

**Fix:** drop the default merge or make `combineAuth` mandatory. The combination
must check that both factors belong to the same principal. Alternative: feed the
first factor's result into the second factor's verification.

## 2. Successful AEAD does not confirm the candidate on inner-payload error

**Priority:** medium
**Code:** `src/common.ts:249-265`, `src/server.ts:741-758`
**Spec:** `spec/protocol.md:186,203`

`createDecryptor()` does three things in one block:

1. Poly1305 verification;
2. msgpack decode;
3. sanitize.

The server treats a failure of any step as a single decrypt failure. So a
correctly authenticated frame with invalid inner msgpack:

- does not promote the candidate;
- does not clear the candidate timer;
- does not record the nonce in the replay window.

The spec requires promoting the candidate immediately after a successful AEAD
check, regardless of the inner RPC payload's shape.

Verified with a dedicated probe: correctly encrypted plaintext `0xc1` passed
Poly1305, but the candidate was not promoted and `handshakeTimeout` fired.

**Fix:** separate AEAD decrypt from decode/sanitize. Promote the candidate and
record the nonce right after Poly1305 succeeds. Handle the inner-payload error
after that.

## 3. Synchronous auth callbacks can outrun `handshakeTimeout`

**Priority:** medium
**Server:** `src/server.ts:469-477,546,611,631-640`
**Client:** `src/client.ts:560-570,708,718`

Timing is bounded by a timer plus a boolean flag. A synchronous callback blocks
the event loop, and the continuation after `await` runs as a microtask before the
timeout callback. There is no actual-deadline check via `Date.now()`.

Probe:

- `handshakeTimeout: 100`;
- synchronous `auth.verify` runs for 160 ms;
- the server still installs the candidate and sends the reply afterward.

**Fix:** compute an absolute deadline. Check it after every auth callback and
immediately before candidate install, session publish, and reply send.

## 4. Some protective limits accept `NaN` and `Infinity`

**Priority:** medium
**Code:** `src/client.ts:191-214`, `src/server.ts:272-273`, `src/auth/server.ts:63-84`

Not validated:

- `client.maxPending`;
- client/server `maxMessageBytes`;
- JWT `maxAge`.

Example consequences:

```ts
maxMessageBytes: NaN
```

The `data.length > maxBytes` check always returns `false`, so the size limit
stops working.

```ts
maxPending: NaN
```

The pending-call cap stops working.

```ts
maxAge: NaN // or Infinity
```

The JWT auth-payload age check stops dropping stale values.

Such values are easy to get from config read via `Number(process.env.VALUE)`.

**Fix:** require a finite positive integer for sizes and limits; a finite
non-negative integer for `maxAge`.

## 5. Puppeteer is in production optional dependencies

**Priority:** medium
**Code:** `package.json:52-54`

`puppeteer` is used only in `test/e2e/browser.test.ts` but sits in
`optionalDependencies`. Optional dependencies install for package consumers by
default.

The current `npm audit --omit=dev` reports, through this branch:

- `ws@8.20.0` — high and moderate advisories;
- `js-yaml@4.1.1` — moderate advisory.

Excluding optional dependencies leaves the production audit clean.

**Fix:** move Puppeteer to `devDependencies`, update the lockfile, and bump `ws`
to the patched version.

## 6. Failed handshake-reply send leaves the candidate until its timer

**Priority:** low
**Code:** `src/server.ts:649-684,701-710`

The candidate is installed before `await channel.send(reply)`. If the send
fails:

- the candidate stays installed until the remaining budget expires;
- `onError` first gets `Handshake failed`;
- then the candidate timer may additionally report `Handshake timeout`.

**Fix:** on send failure, drop the candidate if `candidateEpoch` still matches
this handshake attempt. Keep the original transport error as the cause.

## 7. Middleware can complete without calling `next()`

**Priority:** low
**Code:** `src/server.ts:174-201`
**Spec:** `spec/api.md:90,403`

Only a double `next()` call is currently checked. A middleware can return a value
without ever calling `next()`: the handler is skipped but the client gets a
success.

The API contract requires calling `next()` exactly once.

**Fix:** after the middleware completes, check `called === true`; otherwise
return `RPCError("MIDDLEWARE", ...)`.

## Assessment doc needs a sync

**File:** `spec/assessment.md`

- Line 42 claims `CHANNEL` resets the session. The current implementation resets
  only for a sent call with `RPCAbortedError("TIMEOUT")`.
- Line 58 lists a default `sendTimeout` of 10 seconds; the actual value is 3
  seconds.
- Line 10 lists 266 tests; there are now 280.

## Checks performed

- Full test suite: **280/280**.
- Build: passes.
- Lint: passes.
- Low-order X25519 inputs: `@noble/curves` rejects them correctly; the claimed
  protection works.
- Two separate behavioral probes confirmed findings #2 and #3.
- The working tree stayed clean after review; temporary probe files were removed.
