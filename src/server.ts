/**
 * drpc/server — Resilient RPC server
 *
 * LIFECYCLE: Survives handshake failures and re-handshakes (make-before-break).
 * A new hello opens a handshake ATTEMPT on attempt-local state; a fully
 * validated attempt is installed as a CANDIDATE that runs alongside the live
 * session. The live session keeps serving and is retired ONLY when a frame
 * decrypts under the candidate key — proof the counterparty holds the key
 * material. A garbage / unauthenticated / replayed hello therefore cannot
 * displace an established session: it can at most create a candidate that
 * expires unconfirmed. An unconfirmed candidate is dropped on its confirmation
 * timeout, leaving the live session intact. Only explicit destroy() is
 * permanent.
 */

import {
  x25519,
  concatBytes,
  TAG_HELLO,
  TAG_MSG,
  KEY_LEN,
  NONCE_LEN,
  MAX_HELLO_BYTES,
  MAX_MSG_BYTES,
  MAX_AUTH_BYTES,
  HANDSHAKE_TIMEOUT,
  zero,
  sanitize,
  isPlainBytes,
  isEmptySecret,
  toPlainBytes,
  mpEncode,
  mpDecode,
  deriveSessionKey,
  computeProof,
  createEncryptor,
  createAeadOpener,
  decodePlaintext,
  validateAuthConfig,
  EMPTY_SECRET,
  buildHelloTranscript,
  buildReplyTranscript,
  RPCError,
  type Step,
  type HandlerFn,
  type Ctx,
  type Router,
  type RouterContext,
  type Channel,
  type AuthOptions,
} from "./common.ts";

const MAX_ID_LEN = 64;
const DEFAULT_REPLAY_WINDOW = 4096;
const DEFAULT_MAX_PENDING_HANDSHAKES = 16;

// ─── Server types ─────────────────────────────────────────

/**
 * Per-request context factory. Runs after auth verification, receiving
 * `{ auth }` with whatever `auth.verify` returned so the application can
 * merge it however it wants. MUST NOT hang — there is no server-side
 * per-request timeout (consistent with tRPC/oRPC); a blocking factory
 * accumulates hanging closures until the client-side timeout fires.
 *
 * Its return type must match the router's base context (the type passed to
 * `saferpc<Ctx>()`). When that context is empty the factory is optional, and
 * omitting it uses the verified auth data directly as the request context.
 */
export type ContextFactory<TCtx> = (ctx: {
  auth?: Ctx;
}) => TCtx | Promise<TCtx>;

/** Options common to every `server()` call, independent of context. */
export interface ServerOptionsBase {
  /**
   * Authentication configuration. At least one of `secret` OR asymmetric
   * auth (`sign`/`verify`) MUST be configured.
   */
  auth: AuthOptions;
  /**
   * Max time (ms) to complete a handshake AFTER a client hello arrives.
   * The server waits indefinitely for a client to connect — this timeout
   * only governs the exchange once a hello is received. The budget covers
   * the WHOLE attempt: the async auth callbacks (`verify`/`secret`/`sign`)
   * and the wait for the first frame that decrypts under the candidate.
   * On timeout the unconfirmed candidate is dropped; the live session,
   * if any, keeps serving (make-before-break). Never destroys.
   * Default: 5000ms.
   */
  handshakeTimeout?: number;
  /**
   * Maximum full TAG_MSG frame size accepted inbound and emitted outbound.
   * Oversized inbound frames are silently dropped; oversized responses are
   * reported through `onError` and never handed to the channel. Default:
   * 1 MiB.
   */
  maxMessageBytes?: number;
  /**
   * Maximum number of handshake attempts whose async work has not settled.
   * A timed-out attempt remains counted until its auth callback settles,
   * because JavaScript cannot cancel an arbitrary Promise. New hellos are
   * silently dropped at the cap. Default: 16.
   */
  maxPendingHandshakes?: number;
  /**
   * Size of the per-session replay window: how many recently-seen AEAD
   * nonces the server remembers so it can drop duplicate (replayed)
   * request frames within a single session. FIFO-evicted — a replay older
   * than the last `replayWindow` accepted messages still executes, so this
   * narrows the window to N rather than closing it. Cleared on every
   * re-handshake. `0` disables the defense. Default: 4096.
   */
  replayWindow?: number;
  /**
   * Called on handshake failures and non-fatal internal errors.
   * The server does NOT destroy on handshake failure — a failed attempt
   * simply installs no candidate; an established live session (if any)
   * is untouched, and the next hello is accepted as usual. Use this for
   * logging/monitoring.
   */
  onError?: (err: unknown) => void;
}

/** `context` becomes mandatory exactly when `TCtx` has required members. */
type ContextOption<TCtx> = {} extends TCtx
  ? { context?: ContextFactory<TCtx> }
  : { context: ContextFactory<TCtx> };

/**
 * Options for `server()`. `TCtx` is the router's base context, inferred from
 * the router value: if its procedures require a non-empty context, `context`
 * is **mandatory** here and must return that type.
 */
export type ServerOptions<TCtx = Ctx> = ServerOptionsBase & ContextOption<TCtx>;

// ─── Pipeline executor ───────────────────────────────────

function execute(
  steps: ReadonlyArray<Step>,
  handler: HandlerFn,
  baseCtx: Ctx,
  rawInput: unknown,
): Promise<unknown> {
  let ctx: Ctx = Object.assign(Object.create(null), baseCtx);
  let input: unknown = rawInput;

  let tip: () => Promise<unknown> = function runHandler() {
    return handler({ ctx, input });
  };

  for (let i = steps.length - 1; i >= 0; i--) {
    const step = steps[i]!;
    const next = tip;

    switch (step.t) {
      case "i": {
        const schema = step.schema;
        tip = function runInput() {
          const r = schema.safeParse(input);
          if (!r.success) {
            throw new RPCError(
              "INPUT_VALIDATION",
              "Input validation failed",
              r.error.flatten(),
            );
          }
          input = r.data;
          return next();
        };
        break;
      }
      case "o": {
        const schema = step.schema;
        tip = async function runOutput() {
          const result = await next();
          const r = schema.safeParse(result);
          if (!r.success) {
            throw new RPCError(
              "OUTPUT_VALIDATION",
              "Output validation failed",
              r.error.flatten(),
            );
          }
          return r.data;
        };
        break;
      }
      case "m": {
        const mw = step.fn;
        tip = async function runMiddleware() {
          let called = false;
          let completed = false;
          let downstreamSettled = false;
          let result: unknown;
          try {
            // try/finally (not `.finally()` on the returned value) so that
            // `completed` is set on EVERY exit: async settle, sync throw,
            // and a sync non-promise return. Attaching `.finally()` to the
            // return value would miss a synchronous throw — a late next()
            // scheduled before the throw could then run the handler after
            // the error response — and would TypeError on a sync middleware
            // that returns a plain value after calling next().
            result = await mw({
              ctx,
              input,
              next(extra?: Ctx) {
                // A continuation that arrives after the middleware has
                // completed (settled, returned, or thrown) cannot be part of
                // this request anymore. Ignore it rather than launching the
                // handler after an error response.
                if (completed) return Promise.resolve(undefined);
                if (called) {
                  throw new RPCError(
                    "MIDDLEWARE",
                    "next() called more than once",
                  );
                }
                called = true;
                if (extra !== undefined) {
                  if (typeof extra !== "object" || extra === null) {
                    throw new RPCError(
                      "MIDDLEWARE",
                      "next() extra must be an object",
                    );
                  }
                  ctx = Object.assign(Object.create(null), ctx, extra);
                }
                const downstream = Promise.resolve(next());
                // Observe downstream settlement (fulfil OR reject) for two
                // reasons. (1) The flag feeds the completion check below:
                // a middleware that settles before its next() settled did a
                // fire-and-forget — the client would receive the middleware's
                // own value while the handler outcome is silently dropped —
                // so the request is rejected (tRPC does the same: "did you
                // forget to `return next()`?"). (2) The reaction observes a
                // rejection, so a dropped downstream promise can never
                // surface as an unhandledRejection and terminate the process.
                // Attached before `downstream` is handed to the middleware,
                // so the flag is set before any await on it resumes (promise
                // reactions run FIFO) — a middleware that awaits/returns
                // next() always passes the check deterministically. The
                // enforced invariant is "no reply while downstream is still
                // pending": a fire-and-forget whose downstream happened to
                // settle before the middleware completed is observationally
                // identical to the supported catch-fallback form and is
                // accepted — whether user code looked at the settled value
                // is not detectable without a tRPC-style envelope API.
                downstream.then(
                  function markDownstreamSettled() {
                    downstreamSettled = true;
                  },
                  function markDownstreamSettled() {
                    downstreamSettled = true;
                  },
                );
                return downstream;
              },
            });
          } finally {
            completed = true;
          }
          // Contract: middleware must call next() exactly once. A middleware
          // that returns without calling next() would silently skip the
          // handler while the client still receives a success reply — reject
          // it instead of forwarding its return value.
          if (!called) {
            throw new RPCError(
              "MIDDLEWARE",
              "Middleware completed without calling next()",
            );
          }
          // Contract: the downstream chain must have settled before the
          // middleware itself completed — i.e. next() was awaited or
          // returned. A fire-and-forget next() leaves the handler running
          // detached while the client already received the middleware's own
          // value; that pattern is not supported (the detached rejection is
          // still observed above, so it cannot crash the process).
          if (!downstreamSettled) {
            throw new RPCError(
              "MIDDLEWARE",
              "Middleware completed before next() settled — return or await next()",
            );
          }
          return result;
        };
        break;
      }
      default:
        throw new RPCError("INTERNAL", "Unknown step type");
    }
  }

  return tip();
}

// ─── Server ───────────────────────────────────────────────
// RESILIENT HANDSHAKE (make-before-break): The server survives handshake
// failures AND handshake replays. State is described by two key slots:
//
//   waiting — no live session, no candidate. Accepting hellos.
//   pending — a validated hello installed a CANDIDATE; reply sent. If a
//             live session exists it keeps serving throughout.
//   ready   — live session confirmed, no candidate pending.
//
// Transitions:
//   hello validates        → install candidate (live, if any, untouched)
//   TAG_MSG decrypts under candidate → promote (retire old live key)
//   candidate timeout / attempt error → drop candidate only; live intact
//
// A failed, replayed, or forged hello can at most create a candidate that
// expires unconfirmed — it can never displace the live session. Epoch
// counters guard against stale async operations from previous attempts
// (see the three-counter comment inside server()).

export function server<T extends Router>(
  router: T,
  channel: Channel,
  opts: ServerOptions<RouterContext<T>>,
): { destroy: () => void };
export function server(
  router: Router,
  channel: Channel,
  // Loose implementation signature: a required, interface-typed `context`
  // (from the strict overload) must remain assignable here, so the factory
  // is optional and its return is widened. The public overload above keeps
  // callers honest.
  opts: ServerOptionsBase & { context?: (ctx: { auth?: Ctx }) => unknown },
): { destroy: () => void } {
  if (typeof router !== "object" || router === null) {
    throw new TypeError("server() requires a router object");
  }
  if (typeof channel.send !== "function") {
    throw new TypeError("channel.send must be a function");
  }
  if (typeof channel.receive !== "function") {
    throw new TypeError("channel.receive must be a function");
  }

  validateAuthConfig(opts.auth);
  const auth = opts.auth;

  const frozen: Router = Object.freeze(
    Object.assign(Object.create(null) as Router, router),
  );
  const hsTimeout =
    opts.handshakeTimeout !== undefined
      ? opts.handshakeTimeout
      : HANDSHAKE_TIMEOUT;
  if (
    typeof hsTimeout !== "number" ||
    !Number.isFinite(hsTimeout) ||
    hsTimeout < 100
  ) {
    throw new TypeError("server() handshakeTimeout must be ≥ 100 ms");
  }
  const maxBytes =
    opts.maxMessageBytes !== undefined ? opts.maxMessageBytes : MAX_MSG_BYTES;
  // Reject NaN/Infinity/non-integers outright: `data.length > NaN` is false
  // for every length, which would silently disable the size limit.
  if (!Number.isInteger(maxBytes) || maxBytes <= 0) {
    throw new TypeError("server() maxMessageBytes must be an integer > 0");
  }
  const maxPendingHandshakes =
    opts.maxPendingHandshakes !== undefined
      ? opts.maxPendingHandshakes
      : DEFAULT_MAX_PENDING_HANDSHAKES;
  if (!Number.isInteger(maxPendingHandshakes) || maxPendingHandshakes <= 0) {
    throw new TypeError("server() maxPendingHandshakes must be an integer > 0");
  }
  const replayWindow =
    opts.replayWindow !== undefined ? opts.replayWindow : DEFAULT_REPLAY_WINDOW;
  if (
    typeof replayWindow !== "number" ||
    !Number.isInteger(replayWindow) ||
    replayWindow < 0
  ) {
    throw new TypeError("server() replayWindow must be an integer ≥ 0");
  }
  const onError = opts.onError ?? null;

  // There is no explicit `state` enum: the session state is fully described
  // by the two key slots — waiting = neither set, pending = candidate set
  // (live may still be serving), ready = live set with no candidate. The
  // TAG_MSG handler keys on slot nullness directly.
  // Three counters, three jobs (make-before-break):
  //   `epoch`         — advances on every PROMOTION; TAG_MSG responses are
  //                     guarded by it so a re-handshake drops stale in-flight
  //                     replies.
  //   `attemptEpoch`  — advances on every incoming hello (D1); concurrent
  //                     handshake attempts self-cancel at their await guards
  //                     WITHOUT touching the live session.
  //   `candidateEpoch`— advances only when a candidate is INSTALLED; guards
  //                     the candidate confirmation timer so a later hello that
  //                     bumps `attemptEpoch` but fails validation cannot disarm
  //                     an existing candidate's timeout.
  let epoch = 0;
  let attemptEpoch = 0;
  let candidateEpoch = 0;
  // A timed-out auth callback cannot be cancelled. Keep its attempt counted
  // until the callback settles, so a hello flood can retain only a bounded
  // number of attempt closures. New hellos are dropped at the configured cap.
  let pendingHandshakes = 0;
  // Server ephemeral keys are attempt-local (generated per hello inside the
  // handshake coroutine) and never held at module scope — a failed attempt
  // cannot corrupt an established session's state.

  // ── LIVE slot ── the confirmed session. Serves all traffic (encrypt out,
  // decrypt in). May be null before the first handshake completes.
  // Decrypt slots hold AEAD-only openers (Poly1305 → plaintext); msgpack
  // decoding happens separately in the TAG_MSG handler, AFTER promotion and
  // nonce recording, so a junk inner payload cannot mask a proven key.
  let liveKey: Uint8Array | null = null;
  let liveEncrypt: ((data: unknown) => Uint8Array) | null = null;
  let liveDecrypt: ((payload: Uint8Array) => Uint8Array) | null = null;
  // Verified auth data from auth.verify (server-only), bound to the live
  // session. Promoted from the candidate; cleared on teardown.
  let liveAuthData: Ctx | null = null;

  // ── CANDIDATE slot ── a session proven by a hello attempt but NOT yet
  // confirmed. Used only to TRY decrypting inbound frames; never encrypts.
  // Make-before-break: installing a candidate does not touch the live
  // session — the live key is retired only when a frame decrypts under the
  // candidate (proof the counterparty holds the key material).
  let candidateKey: Uint8Array | null = null;
  let candidateDecrypt: ((payload: Uint8Array) => Uint8Array) | null = null;
  let candidateAuthData: Ctx | null = null;

  let destroyed = false;
  // Confirmation timer for the pending candidate. On expiry the candidate is
  // dropped; the live session (if any) is untouched.
  let candidateTimer: ReturnType<typeof setTimeout> | null = null;
  // Absolute wall-clock deadline for the pending candidate (hello receipt +
  // hsTimeout). The candidate timer is only a wakeup and may fire late if the
  // loop was busy; the promotion path checks this deadline directly so an
  // overdue confirming frame cannot promote an expired candidate.
  let candidateDeadline = 0;

  // ── D2: bounded seen-nonce set (in-session replay defense) ────────
  // Ring buffer of the last `replayWindow` accepted nonce keys + a Set for
  // O(1) membership. Nonces are inserted ONLY after Poly1305 verifies (see
  // the TAG_MSG handler), so an attacker who cannot forge ciphertexts
  // cannot pump the set and force eviction churn. Lifetime is tied to the
  // session key: cleared on every reset / re-handshake.
  const seenSet: Set<string> | null = replayWindow > 0 ? new Set() : null;
  let seenRing: string[] = [];
  let seenHead = 0;

  function nonceKey(nonce: Uint8Array): string {
    let s = "";
    for (let i = 0; i < nonce.length; i++) {
      s += String.fromCharCode(nonce[i]!);
    }
    return s;
  }
  function seenHas(key: string): boolean {
    return seenSet !== null && seenSet.has(key);
  }
  function seenAdd(key: string): void {
    if (seenSet === null || seenSet.has(key)) return;
    if (seenRing.length >= replayWindow) {
      const evicted = seenRing[seenHead];
      seenRing[seenHead] = key;
      seenHead = (seenHead + 1) % replayWindow;
      if (evicted !== undefined) seenSet.delete(evicted);
    } else {
      seenRing.push(key);
    }
    seenSet.add(key);
  }
  function seenClear(): void {
    if (seenSet !== null) {
      seenSet.clear();
      seenRing = [];
      seenHead = 0;
    }
  }

  function clearCandidateTimer(): void {
    if (candidateTimer !== null) {
      clearTimeout(candidateTimer);
      candidateTimer = null;
    }
  }

  /**
   * Promote the pending candidate to the live session. Called ONLY from the
   * TAG_MSG handler, when a frame decrypts under the candidate key — that
   * ciphertext is proof the counterparty holds the key material, which is
   * exactly the authority required to retire the old live session
   * (make-before-break). Advances `epoch` so in-flight responses from the
   * retired session self-drop at the response guard, and clears the replay
   * window (new key → old nonces are irrelevant).
   */
  function promoteCandidate(): void {
    if (candidateKey === null) return; // defensive — never expected
    clearCandidateTimer();
    if (liveKey !== null) zero(liveKey);
    liveKey = candidateKey;
    liveEncrypt = createEncryptor(liveKey);
    liveDecrypt = candidateDecrypt;
    liveAuthData = candidateAuthData;
    epoch++;
    seenClear();
    candidateKey = null; // ownership moved to liveKey — do NOT zero it
    candidateDecrypt = null;
    candidateAuthData = null;
  }

  /**
   * Drop the pending candidate without touching the live session. Called on
   * candidate confirmation timeout. If a live session exists it keeps serving
   * (make-before-break); otherwise we fall back to waiting.
   */
  function dropCandidate(): void {
    clearCandidateTimer();
    if (candidateKey !== null) {
      zero(candidateKey);
      candidateKey = null;
    }
    candidateDecrypt = null;
    candidateAuthData = null;
  }

  function destroy(): void {
    if (destroyed) return;
    destroyed = true;
    clearCandidateTimer();
    if (liveKey !== null) {
      zero(liveKey);
      liveKey = null;
    }
    if (candidateKey !== null) {
      zero(candidateKey);
      candidateKey = null;
    }
    liveEncrypt = null;
    liveDecrypt = null;
    liveAuthData = null;
    candidateDecrypt = null;
    candidateAuthData = null;
    seenClear();
    if (unsubscribe !== null) {
      unsubscribe();
      unsubscribe = null;
    }
  }

  const rawUnsubscribe = channel.receive(function onMessage(raw: Uint8Array) {
    if (destroyed || raw.length === 0) return;
    // Normalize so the inbound buffer is a plain Uint8Array; Node's
    // `Buffer` propagates its subclass through `subarray()` into msgpack
    // `bin` fields, which would defeat downstream `isPlainBytes` checks.
    const data = toPlainBytes(raw);
    const tag = data[0];

    // Make-before-break: a hello opens a handshake ATTEMPT. The live session
    // (if any) keeps serving on its own key throughout. A fully validated
    // attempt is installed as a CANDIDATE (below), NOT swapped in; the live
    // key is retired only when a frame decrypts under the candidate. A garbage
    // or bad-signature hello therefore cannot displace an established session.
    // `attemptEpoch` bumps per hello so a newer attempt cancels this one at
    // its await guards without touching the session or the candidate.
    if (tag === TAG_HELLO) {
      if (data.length > MAX_HELLO_BYTES) return;
      if (pendingHandshakes >= maxPendingHandshakes) return;
      pendingHandshakes++;

      attemptEpoch++;
      const myAttempt = attemptEpoch;

      // The hsTimeout budget starts NOW, at hello receipt — not after the
      // async auth callbacks. A slow/hung `auth.verify` / `auth.secret` /
      // `auth.sign` must not stretch the attempt: on expiry the flag kills
      // the attempt at its await guards (a pending await itself cannot be
      // cancelled, but nothing past it can install a candidate or reply).
      // Whatever budget validation leaves over goes to the candidate
      // confirmation timer below, so hello → first-decrypted-frame is
      // bounded by ONE hsTimeout total.
      const attemptStart = Date.now();
      // Absolute deadline twin of the timer below. The timer alone is not
      // enough: a SYNCHRONOUS auth callback that blocks past the budget
      // resumes as a microtask BEFORE the timer macrotask fires, so the
      // `attemptExpired` flag is still false when the continuation runs.
      // Every guard therefore also checks wall-clock time.
      const attemptDeadline = attemptStart + hsTimeout;
      let attemptExpired = false;
      // One attempt reports at most one onError. The attempt timer, the
      // candidate timer, and the failure catch all gate on this flag so a
      // timeout followed by a late async rejection (or reply-send failure)
      // cannot emit two errors for the same handshake.
      let reported = false;
      const attemptDead = (): boolean =>
        attemptExpired || Date.now() >= attemptDeadline;
      const attemptTimer = setTimeout(function onAttemptTimeout() {
        attemptExpired = true;
        if (attemptEpoch !== myAttempt || destroyed || reported) return;
        reported = true;
        if (onError !== null) {
          onError(new RPCError("HANDSHAKE", "Handshake timeout"));
        }
      }, hsTimeout);

      (async function handleHello() {
        // Attempt-local ephemeral pair — never published to module scope
        // until the final synchronous publish, so a failed attempt leaves
        // the established session untouched.
        const myPriv = x25519.utils.randomSecretKey();
        const myPub = x25519.getPublicKey(myPriv);

        // Local accumulators — only published to module-level state under
        // the FINAL attempt guard below. Cleaned up in finally on any exit.
        let rawShared: Uint8Array | null = null;
        let localSessionKey: Uint8Array | null = null;
        let localProof: Uint8Array | null = null;
        let localAuthData: Ctx | null = null;
        let localServerAuth: Uint8Array | null = null;

        try {
          const raw = sanitize(mpDecode(data.subarray(1)));
          if (typeof raw !== "object" || raw === null) {
            throw new RPCError("HANDSHAKE", "Invalid hello");
          }
          const hello = raw as Record<string, unknown>;

          const clientPub = hello["pub"];
          if (!isPlainBytes(clientPub) || clientPub.length !== KEY_LEN) {
            throw new RPCError("HANDSHAKE", "Invalid public key");
          }

          const nonce = hello["nonce"];
          if (!isPlainBytes(nonce) || nonce.length !== KEY_LEN) {
            throw new RPCError("HANDSHAKE", "Invalid nonce");
          }

          // Strict epoch validation on the wire. `encodeEpoch` enforces
          // the same predicate inside transcript building, but secret-only
          // paths never reach it — validate here so every path is strict.
          const clientEpoch = hello["epoch"];
          if (
            typeof clientEpoch !== "number" ||
            !Number.isInteger(clientEpoch) ||
            clientEpoch < 0 ||
            clientEpoch > 0xffffffff
          ) {
            throw new RPCError("HANDSHAKE", "Invalid epoch");
          }

          // ── Client-side auth verification ─────────────────
          // If `verify` is configured, the client MUST embed an `auth`
          // payload bound to the canonical hello transcript. Reject the
          // handshake otherwise — and reject if the payload fails
          // verification — BEFORE deriving any session state, so a failed
          // verification does not silently leak ECDH artifacts.
          if (auth.verify !== undefined) {
            const helloAuth = hello["auth"];
            if (!isPlainBytes(helloAuth)) {
              throw new RPCError(
                "HANDSHAKE",
                "auth.verify configured but hello.auth missing or invalid",
              );
            }
            if (helloAuth.length === 0 || helloAuth.length > MAX_AUTH_BYTES) {
              throw new RPCError("HANDSHAKE", "hello.auth size out of range");
            }
            const transcript = buildHelloTranscript(
              clientEpoch,
              clientPub,
              nonce,
            );
            const verifyResult = await auth.verify(helloAuth, transcript);
            if (attemptEpoch !== myAttempt || destroyed || attemptDead()) {
              return;
            }
            if (verifyResult && typeof verifyResult === "object") {
              const a = (verifyResult as { auth?: unknown }).auth;
              if (a !== undefined) {
                if (typeof a !== "object" || a === null) {
                  throw new RPCError(
                    "HANDSHAKE",
                    "auth.verify result must be an object",
                  );
                }
                localAuthData = sanitize(a) as Ctx;
              }
            }
          }
          // If `verify` is not configured, hello.auth is ignored even
          // if the client embedded one. This preserves backward
          // compatibility with secret-only deployments.

          rawShared = x25519.getSharedSecret(myPriv, clientPub);
          // Private key no longer needed; zero our copy immediately.
          zero(myPriv);

          const secretBytes =
            auth.secret !== undefined ? await auth.secret() : EMPTY_SECRET;
          if (attemptEpoch !== myAttempt || destroyed || attemptDead()) {
            return;
          }

          if (
            !(secretBytes instanceof Uint8Array) ||
            secretBytes.length < KEY_LEN
          ) {
            throw new RPCError(
              "HANDSHAKE",
              `secret must be a Uint8Array of at least ${KEY_LEN} bytes`,
            );
          }
          if (auth.secret !== undefined && isEmptySecret(secretBytes)) {
            throw new RPCError(
              "HANDSHAKE",
              "Application returned an all-zero secret",
            );
          }

          // The caller owns the secret buffer's lifecycle — do NOT mutate it.
          // A `() => sharedSecret` pattern would break on the next handshake.
          localSessionKey = deriveSessionKey(rawShared, secretBytes);
          localProof = computeProof(localSessionKey, myPub, clientPub, nonce);

          // ── Server-side auth production ──────────────────
          // If `sign` is configured, sign over the canonical reply
          // transcript (which binds BOTH ephemeral pubs) so the client
          // can authenticate the server beyond what the secret alone provides.
          // Computed BEFORE the candidate install below, so a failure here
          // installs nothing and leaves the live session untouched.
          if (auth.sign !== undefined) {
            const replyTranscript = buildReplyTranscript(
              clientEpoch,
              clientPub,
              nonce,
              myPub,
            );
            const signed = await auth.sign(replyTranscript);
            if (attemptEpoch !== myAttempt || destroyed || attemptDead()) {
              return;
            }
            if (
              !(signed instanceof Uint8Array) ||
              signed.length === 0 ||
              signed.length > MAX_AUTH_BYTES
            ) {
              throw new RPCError(
                "HANDSHAKE",
                "auth.sign returned invalid payload",
              );
            }
            localServerAuth = signed;
          }

          // FINAL install guard. The block below is fully synchronous: it
          // installs the newly-proven session as a CANDIDATE without racing a
          // newer attempt or a request.
          if (attemptEpoch !== myAttempt || destroyed || attemptDead()) {
            return;
          }

          // Validation finished within budget — the attempt timer's job is
          // done; the candidate timer takes over with the REMAINING budget.
          clearTimeout(attemptTimer);
          const remainingBudget = Math.max(
            1,
            hsTimeout - (Date.now() - attemptStart),
          );

          // Make-before-break: install as CANDIDATE, do NOT touch the live
          // session. The live key (if any) keeps serving until a frame
          // decrypts under this candidate (see promoteCandidate). A newer
          // unconfirmed candidate replaces an older one (latest wins). The
          // candidate is decrypt-only — its encryptor is created on promotion,
          // never before, since we never encrypt under an unconfirmed key.
          clearCandidateTimer();
          if (candidateKey !== null) zero(candidateKey);
          candidateEpoch++;
          candidateKey = localSessionKey;
          localSessionKey = null; // ownership transferred — skip finally zero
          candidateDecrypt = createAeadOpener(candidateKey);
          candidateAuthData = localAuthData;
          // Absolute twin of the confirmation timer below: total budget is
          // hello receipt + hsTimeout, so the candidate expires at the same
          // wall-clock instant the timer is scheduled for.
          candidateDeadline = attemptStart + hsTimeout;

          // Arm the confirmation timer for this candidate. On expiry the
          // candidate is dropped and the live session is untouched. Keyed on
          // `candidateEpoch` so a later install (or a validated newer
          // candidate) cancels this timer cleanly, while a later hello that
          // merely bumps `attemptEpoch` and then fails cannot disarm it.
          const myCandEpoch = candidateEpoch;
          candidateTimer = setTimeout(function onCandidateTimeout() {
            if (candidateEpoch !== myCandEpoch || destroyed) return;
            dropCandidate();
            if (reported) return;
            reported = true;
            if (onError !== null) {
              onError(new RPCError("HANDSHAKE", "Handshake timeout"));
            }
          }, remainingBudget);

          const replyMsg: Record<string, unknown> = {
            pub: myPub,
            proof: localProof,
            epoch: clientEpoch,
          };
          if (localServerAuth !== null) replyMsg["auth"] = localServerAuth;

          const replyPayload = mpEncode(replyMsg);
          const reply = concatBytes(new Uint8Array([TAG_HELLO]), replyPayload);
          zero(replyPayload);
          zero(localProof);
          localProof = null;

          try {
            await channel.send(reply);
          } catch (sendErr: unknown) {
            // The reply never reached the wire — this candidate can never be
            // confirmed. Drop it NOW (if it is still ours) instead of letting
            // it linger until the confirmation timer fires a second, spurious
            // "Handshake timeout" on top of the send failure below.
            if (candidateEpoch === myCandEpoch && !destroyed) {
              dropCandidate();
            }
            // 4th argument: `cause` is constructor options, not `data` —
            // the original error object rides err.cause per the protocol
            // ("carrying the transport error as its cause").
            throw new RPCError(
              "HANDSHAKE",
              "Handshake reply send failed",
              undefined,
              { cause: sendErr },
            );
          }
          if (candidateEpoch !== myCandEpoch || destroyed) return;

          // Timer continues running — waiting for first valid TAG_MSG that
          // decrypts under the candidate to promote it. Total budget =
          // hsTimeout.
        } finally {
          // Harmless double-clear on the success path; on every failure /
          // stale-attempt path this stops a pending spurious timeout report.
          clearTimeout(attemptTimer);
          if (rawShared !== null) zero(rawShared);
          if (localSessionKey !== null) zero(localSessionKey);
          if (localProof !== null) zero(localProof);
          // myPriv may already be zeroed (after ECDH); harmless to repeat.
          zero(myPriv);
          zero(myPub);
        }
      })()
        .catch(function onHsError(err: unknown) {
          // The attempt failed. Under D1 the live session (if any) was never
          // touched, so there is nothing to reset — only report the failure.
          if (attemptEpoch !== myAttempt || destroyed || reported) return;
          reported = true;
          if (onError !== null) {
            onError(
              err instanceof RPCError
                ? err
                : new RPCError("HANDSHAKE", "Handshake failed"),
            );
          }
        })
        .then(
          function onHsSettled() {
            pendingHandshakes--;
          },
          function onHsReportError() {
            // An application onError callback is allowed to throw. The
            // attempt slot must still be released without creating an
            // unhandled rejection.
            pendingHandshakes--;
          },
        );
      return;
    }

    if (
      tag === TAG_MSG &&
      (liveDecrypt !== null || candidateDecrypt !== null)
    ) {
      if (data.length > maxBytes) return;

      // D2: cheap replay reject BEFORE decrypt, against the LIVE replay
      // window. The AEAD nonce is the NONCE_LEN bytes right after the tag. If
      // a frame with this nonce was already accepted in the current session,
      // it is a duplicate/replay — drop it silently. The membership record
      // itself is only written AFTER Poly1305 verifies (below), so unforgeable
      // frames can never pollute the window.
      const nKey =
        data.length >= 1 + NONCE_LEN
          ? nonceKey(data.subarray(1, 1 + NONCE_LEN))
          : null;
      if (nKey !== null && seenHas(nKey)) return;

      (async function handleRequest() {
        // Trial decrypt: LIVE first (steady-state cost = one decrypt), then
        // CANDIDATE. A frame that decrypts under the candidate is proof the
        // counterparty holds the key material — the authority required to
        // retire the live session (make-before-break). AEAD verification
        // ONLY — the inner payload is decoded later, so a junk payload under
        // a proven key still promotes and still lands in the replay window.
        let plain: Uint8Array | null = null;
        let decryptedUnder: "live" | "candidate" | null = null;
        if (liveDecrypt !== null) {
          try {
            plain = liveDecrypt(data);
            decryptedUnder = "live";
          } catch {
            /* fall through to candidate */
          }
        }
        if (decryptedUnder === null && candidateDecrypt !== null) {
          try {
            plain = candidateDecrypt(data);
            decryptedUnder = "candidate";
          } catch {
            /* neither key */
          }
        }
        if (decryptedUnder === null || plain === null) {
          return; // poly1305 failure → silently drop (nonce NOT recorded)
        }

        // Promotion advances `epoch`; capture reqEpoch AFTER it so the reply
        // to THIS confirming frame survives the response guard below. The
        // confirming frame is not an in-flight leftover — it is the promoter.
        if (decryptedUnder === "candidate") {
          // Absolute-deadline check: the candidate timer is only a wakeup and
          // may fire late if the loop was busy past the budget. If this
          // confirming frame arrives after the candidate expired, do NOT
          // promote — leave the (now overdue) candidate timer to drop it and
          // report the timeout. The nonce is not recorded and the handler is
          // not run, so an expired candidate cannot execute a request.
          if (Date.now() >= candidateDeadline) return;
          promoteCandidate();
        }
        const reqEpoch = epoch;

        // Decode the authenticated plaintext. A malformed inner payload is
        // dropped silently — the session promotion above stands: the key was
        // proven by Poly1305, not by the payload's shape (spec § Step 4).
        // It still consumes a replay-window slot: otherwise an attacker who
        // has obtained one authenticated malformed frame can make the server
        // repeat decode/sanitize work indefinitely without the normal replay
        // bound. This happens before any await, so duplicate delivery cannot
        // race the membership check at the channel boundary.
        let raw: unknown;
        try {
          raw = decodePlaintext(plain);
        } catch {
          if (nKey !== null) seenAdd(nKey);
          return;
        }

        if (typeof raw !== "object" || raw === null) {
          if (nKey !== null) seenAdd(nKey);
          return;
        }
        const msg = raw as Record<string, unknown>;

        // Direction guard: t === 1 marks a REQUEST. Both directions share one
        // session key, so a genuine server RESPONSE reflected back to the
        // server also passes Poly1305 — dropping it BEFORE recording its
        // nonce keeps opposite-direction frames from consuming replay-window
        // slots (which would shrink the effective window against real
        // request replays). Other authenticated malformed envelopes consume
        // their nonce even though they are not dispatched.
        if (msg["t"] !== 1) {
          if (msg["t"] !== 2 && nKey !== null) seenAdd(nKey);
          return;
        }

        // Request-direction frame, Poly1305-verified — record its nonce in
        // the (now-current) live window so a later duplicate is rejected.
        // Still synchronous (no await since decrypt), so back-to-back
        // duplicates cannot both slip through.
        if (nKey !== null) seenAdd(nKey);
        const rawId = msg["id"];
        if (
          typeof rawId !== "string" ||
          rawId.length === 0 ||
          rawId.length > MAX_ID_LEN
        ) {
          return;
        }
        const rawProc = msg["p"];
        if (typeof rawProc !== "string" || rawProc.length === 0) {
          return;
        }

        const id = rawId;
        const procedure = rawProc;
        let res: Record<string, unknown>;

        try {
          if (!(procedure in frozen)) {
            throw new RPCError("NOT_FOUND", "Procedure not found");
          }
          const proc = frozen[procedure]!;
          // Snapshot auth data at request time so re-handshake mid-flight
          // does not race against an in-flight handler. The session is
          // bound to one handshake; if it resets, the response is dropped
          // by the epoch guard below.
          const ctxArg = liveAuthData !== null ? { auth: liveAuthData } : {};
          let ctx: Ctx;
          if (opts.context !== undefined) {
            // Return type is widened to `unknown` on the loose impl
            // signature; the application owns the concrete shape.
            ctx = (await opts.context(ctxArg)) as Ctx;
          } else if ("auth" in ctxArg && ctxArg.auth !== undefined) {
            ctx = Object.assign(Object.create(null), ctxArg.auth);
          } else {
            ctx = Object.create(null);
          }
          const result = await execute(
            proc._steps,
            proc._handler,
            ctx,
            msg["i"],
          );
          // Sanitise handler output before encoding. Catches accidental
          // `Date`/`Map`/`Set`/host-object returns at a place where the
          // error becomes a typed `INVALID_DATA`, not an opaque `INTERNAL`.
          res = { t: 2, id, ok: true, d: sanitize(result), e: null };
        } catch (err: unknown) {
          if (err instanceof RPCError) {
            res = {
              t: 2,
              id,
              ok: false,
              d: null,
              e: { c: err.code, m: err.message, d: sanitize(err.data) },
            };
          } else {
            res = {
              t: 2,
              id,
              ok: false,
              d: null,
              e: { c: "INTERNAL", m: "Internal error", d: null },
            };
          }
        }

        // Epoch guard: if a promotion/re-handshake happened while the
        // handler was running, this response belongs to a superseded session.
        // Drop it — the client already timed out and retried.
        if (epoch !== reqEpoch || destroyed) return;

        const enc = liveEncrypt;
        if (enc === null) return;
        const encrypted = enc(res);
        if (encrypted.length > maxBytes) {
          // The response is local until handed to the adapter. Never emit an
          // oversized frame that the peer is required to drop; otherwise a
          // large handler result turns into an opaque client timeout and also
          // defeats the server-side framing bound on outbound traffic.
          zero(encrypted);
          if (onError !== null) {
            onError(
              new RPCError("INVALID_DATA", "Response exceeds maxMessageBytes"),
            );
          }
          return;
        }
        await channel.send(encrypted);
      })().catch(function onSendError(err: unknown) {
        if (onError !== null) onError(err);
      });
    }
  });
  let unsubscribe: (() => void) | null = rawUnsubscribe ?? null;

  return { destroy };
}
