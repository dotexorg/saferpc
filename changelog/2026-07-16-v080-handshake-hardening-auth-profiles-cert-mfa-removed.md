# 2026-07-16 — v0.8.0: client/transport rework + handshake hardening, auth profiles, cert/MFA removal

The 0.7 and 0.8 work, read as one set of changes. 0.7.x was cut in a hurry to
unblock an external review and was never checked against the spec end to end —
treat those tags as pre-release. **0.8.0 is the first release to pass a full
conformance pass against `spec/protocol.md`**; the hardening landed across several
independent review rounds (auth-surface design review, cross-language port audit,
two neutral security passes), every finding re-verified in shipped code and pinned
by a regression test.

Do **not** assume wire compatibility with pre-0.8.0 tags — only 0.8.0 is
spec-conformant. Test suite grown to 295.

## Client & transport semantics (0.7)

Behavioural rework of the client and channel layer — separate from the 0.8
security pass below.

- **BREAKING — auto-retry removed.** The client no longer silently re-sends a
  call. A sent request that times out rejects with `RPCAbortedError` and leaves
  the outcome **UNKNOWN** — the caller decides whether replaying is safe. A plain
  local `RPCError` means the request provably never left.
- **BREAKING — deferred reset.** The session resets only on a *sent* call that
  gets `RPCAbortedError("TIMEOUT")`; guardrail rejections (`CHANNEL`, `ABORTED`,
  queued-frame failures) no longer tear down and re-handshake the session.
- **Replay window.** Server keeps a bounded seen-nonce set (configurable
  `replayWindow`, default 4096) so a captured frame can't be replayed within the
  window.
- **`abortPending`.** New client API to abort all in-flight calls at once (each
  rejects by its sent-status class), on top of per-call `AbortSignal`.
- **Make-before-break session continuity.** A new handshake is negotiated as a
  candidate while the live session keeps serving; the old session is only
  replaced once the candidate is confirmed, so a re-handshake doesn't drop
  in-flight work. Handshake states are resilient across transient channel gaps.
- **Reconnecting channel adapters.** WebSocket and socket adapters reconnect and
  the session survives transport loss — a call issued while the channel is down
  completes after recovery without a re-handshake.
- **BREAKING — default `sendTimeout` 10s → 3s** for faster failure detection of an
  unsent frame.
- **Port-complete spec + first KAT vectors.** `spec/protocol.md`,
  `spec/security.md` assessment, and the initial known-answer test vectors landed
  here — the groundwork the 0.8.0 conformance pass later verified end to end.

## Security

### Handshake

- **High — candidate phase now has its own absolute deadline.** A candidate
  session could be promoted after its confirmation window elapsed. Server stamps
  `candidateDeadline` on install and checks it before `promoteCandidate()`;
  companion fix drops a double-`onError` report on one failed attempt (`reported`
  flag).
- **Synchronous auth callbacks can no longer overrun `handshakeTimeout`.** Timer +
  boolean let a synchronous `verify`/`secret`/`sign` win the race (post-`await`
  continuation is a microtask, runs before the timer). Now an absolute `Date.now()`
  deadline is checked after every auth callback and before candidate install,
  session publish, and reply send — both peers.
- **Candidate promotion split from payload decoding.** An AEAD-authenticated frame
  with malformed inner msgpack used to fail the whole decrypt — candidate not
  promoted, timer not cleared, nonce not recorded — stalling a valid peer to
  timeout. AEAD opening (`createAeadOpener`) is now separate from
  `decodePlaintext`; candidate is promoted and nonce recorded the moment Poly1305
  verifies, regardless of inner payload shape.
- **`maxPendingHandshakes` caps concurrent in-flight handshakes** so a peer with
  never-settling auth callbacks can't accumulate unbounded pending work.
- **Failed handshake-reply send drops the candidate** immediately (when
  `candidateEpoch` still matches) instead of lingering to its timer; exactly one
  error reported.
- **Low — handshake epoch exhaustion is a terminal client error.** No ceiling
  guard on the client epoch counter; past `0xffffffff` every hello would be
  silently dropped server-side as `Invalid epoch`, surfacing only as opaque
  timeouts. `startHandshake` now rejects with `RPCError("CLIENT", "Handshake epoch
  exhausted; destroy and recreate client")`. Unreachable in practice
  (~4.3 × 10⁹ handshakes); no wire/reuse impact.

### Crypto / secrets

- **Medium-High — all-zero secret rejected at any length.** Guard only covered 32
  bytes. `isEmptySecret` now rejects any-length all-zero buffers;
  `deriveSessionSecret` throws `TypeError("secret must not be all-zero")`.

### Replay / framing

- **Reflected `t: 2` frames no longer consume replay slots.** A direction guard
  runs before the nonce is recorded, closing a replay-window-narrowing reflection.
- Response-framing size limits tightened in the same pass.

### Input validation

- **Bigints beyond 64 bits rejected** (`INVALID_DATA`) instead of round-tripping a
  corrupted value; `BIGINT_MIN` / `BIGINT_MAX` exported.
- **Cyclic outbound graphs rejected** (`WeakSet` detection) instead of recursing to
  a stack overflow; non-cyclic repeated references still rebuilt independently.
- **`NaN` / `Infinity` no longer disable limits.** `maxPending`,
  `maxMessageBytes`, JWT `maxAge` validated as finite integers at construction.
  `maxMessageBytes: NaN` used to make `len > max` always false — trivially reached
  via `Number(process.env.X)`.

### Middleware

- **Middleware returning without calling `next()` fails closed** (`RPCError
  ("MIDDLEWARE", ...)`) — previously skipped the handler but returned success.
  Completion guarded on synchronous throw and bare return.
- **Unhandled rejection from fire-and-forget `next()` closed** (`void
  Promise.resolve(downstream).catch(() => {})`).

### Auth payloads

- Auth payloads pass the full `sanitize()` gate and are version-checked; malformed
  or unversioned payloads rejected as `UNAUTHORIZED` before reaching app `verify`.

## Added

- **Normative auth profiles: JWT, Ed25519, ECDSA (P-256).** Each has a versioned
  wire schema (`v` field, unknown version rejected server-side) and published KAT
  vectors in `spec/protocol.md` / `test/unit/vectors.test.ts` — cross-language
  ports interoperate byte-for-byte.
- **`maxPendingHandshakes`** server option.
- **`BIGINT_MIN` / `BIGINT_MAX`** exports.
- **Port-complete spec + KAT vectors** — 44-item implementation checklist and full
  vectors (keys, proof, both transcripts, three auth-profile payloads) cross-checked
  spec ↔ tests ↔ implementation.

## Changed

- **BREAKING — Node floor `>=20.19.0`.** `package.json` declared a range the build
  and `@noble/hashes` 2.x never supported; declaration now matches reality. Node
  < 20.19.0 unsupported, not CI-tested.
- Spec/docs realigned with code: JWT credential visibility in the opening frame
  called out, asymmetric examples authenticate both directions, `protocol.md`
  context-error contract matches `server.ts`, malformed-envelope /
  stale-and-unknown-response-id handling pinned, sent-boundary for async adapters
  clarified.

## Removed

- **BREAKING — certificate + multifactor auth helpers deleted**
  (`createCertificateServerAuth`, `createMultifactorServerAuth`) with tests. The
  certificate helper was ECDSA verification under a name promising
  chain/expiry/revocation it never did (all in the app callback). The multifactor
  helper couldn't enforce same-principal binding — default `{ ...primary,
  ...secondary }` merge passed two different principals as MFA, and spread order
  could let an issuer-signed JWT claim overwrite a cryptographically verified
  field. Use JWT/Ed25519/ECDSA profiles or a custom `verify`; `spec/security.md`
  documents certificate and two-factor-with-binding recipes.

## Fixed

- Nested `undefined` in outbound values no longer diverges from the declared type
  contract.
- Reserved route/middleware names can no longer be registered.
- Malformed RPC responses (bad `ok`, absent/garbage `c`/`m`) dropped or coerced
  strictly per spec.

## Dependencies

- **`puppeteer` moved to `devDependencies`** — was in `optionalDependencies`
  (installs by default for consumers), dragging `ws` (high/moderate) and `js-yaml`
  (moderate) into production `npm audit`. Production audit now clean.
- `ws` bumped to `^8.21.0`.

## Verification

- Full gate green: 39 files, 295 tests; lint, typecheck, ESM+CJS build clean
  (Node 22.22.1).
- Every finding re-verified in shipped code (not on commit-message trust) and
  mapped to a regression test; KAT vectors byte-identical across spec/tests/impl.
- Full audit trail: `review-release-verdict-0.8.0.md`.
