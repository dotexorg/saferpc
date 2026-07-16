/**
 * drpc/client — Lazy RPC client (no auto-retry)
 *
 * LIFECYCLE: Handshake triggers lazily on first RPC call. The session
 * auto-resets only on RPCAbortedError(TIMEOUT) — a sent request that got
 * no reply — but the failed call is NOT resent; the error surfaces to the
 * caller, who alone knows whether the procedure is idempotent. The reset
 * only ensures the NEXT call lazily re-handshakes. Concurrent calls
 * coordinate via epoch to avoid redundant resets.
 *
 * Transport death is NOT a session event: the session is bound to key
 * material, not to a transport instance. Channel liveness (reconnect) is
 * the adapter's job — see the Channel jsdoc in common.ts and the shipped
 * adapters in channels/. Delivery bookkeeping is OURS: a frame whose
 * `channel.send` throws enters the core outbound queue and is retried
 * until `sendTimeout`; the sent boundary (handoff to `channel.send`, not
 * promise resolution) decides every rejection's class — `RPCAbortedError` = the
 * request left, outcome UNKNOWN; plain local `RPCError` = it provably
 * never left, safe to resend. Per-call AbortSignal cancels waiting
 * without touching the session.
 */

import { randomBytes } from "@noble/ciphers/utils.js";

import {
  x25519,
  concatBytes,
  constTimeEqual,
  TAG_HELLO,
  TAG_MSG,
  KEY_LEN,
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
  createDecryptor,
  validateAuthConfig,
  EMPTY_SECRET,
  buildHelloTranscript,
  buildReplyTranscript,
  RPCError,
  RPCAbortedError,
  type Router,
  type Procedure,
  type Channel,
  type AuthOptions,
} from "./common.ts";

// ─── Client constants ─────────────────────────────────────

const PROOF_LEN = 32;
const MAX_PENDING = 256;
const DEFAULT_TIMEOUT = 30_000;
const DEFAULT_SEND_TIMEOUT = 3_000;
// Outbound retry tick. Internal, not a caller lever — `sendTimeout` is the
// contract; the tick only bounds how fast a revived channel is noticed.
const SEND_RETRY_MS = 250;
const MAX_KNOWN_PROCEDURES = 1024;

// ─── Client types ─────────────────────────────────────────

/**
 * Error received from the remote peer. Distinct from local RPCError
 * so callers can distinguish local failures (TIMEOUT, SESSION, CLIENT)
 * from remote failures. Remote error codes and messages are UNTRUSTED —
 * the remote peer can send arbitrary strings.
 */
export class RemoteRPCError extends RPCError {
  constructor(code: string, message: string, data?: unknown) {
    super(code, message, data);
  }
}

/**
 * Per-call options, fetch-style. Passed as the optional second argument of
 * every generated method.
 */
export interface CallOptions {
  /**
   * Abort THIS call (code `ABORTED`, the signal's reason on `.cause`).
   * Client-local: the session is never touched; a shared in-progress
   * handshake continues for other callers. The rejection's class tells
   * you whether the request had already left: `RPCAbortedError` = sent,
   * outcome on the server UNKNOWN; plain `RPCError` = provably never
   * sent, safe to resend.
   */
  signal?: AbortSignal;
}

/**
 * A procedure's call signature. The input argument is optional when it
 * isn't actually required to call the procedure — no `.input()` schema was
 * set (`TInput` is `unknown`) or the schema itself accepts `undefined`
 * (e.g. `.optional()`/`.default()`, where `undefined` is part of `TInput`).
 * Otherwise the argument is mandatory.
 */
type ClientMethod<TInput, TOutput> = unknown extends TInput
  ? (input?: TInput, opts?: CallOptions) => Promise<TOutput>
  : undefined extends TInput
    ? (input?: TInput, opts?: CallOptions) => Promise<TOutput>
    : (input: TInput, opts?: CallOptions) => Promise<TOutput>;

/**
 * The caller-facing API for a router, inferred end-to-end. Each procedure
 * becomes a call whose argument is that procedure's input type and whose
 * result is its output type. A loose `Router` (e.g. `Record<string,
 * Procedure>`) collapses to `(input?: unknown) => Promise<unknown>`, so
 * untyped usage keeps working; pass a precise router
 * (`client<typeof appRouter>(...)`) to get real inference.
 */
export type Client<T extends Router> = {
  [K in keyof T & string]: T[K] extends Procedure<
    infer TInput,
    infer TOutput,
    unknown
  >
    ? ClientMethod<TInput, TOutput>
    : (input?: unknown, opts?: CallOptions) => Promise<unknown>;
};

export interface ClientOptions {
  /**
   * Authentication configuration. At least one of `secret` OR asymmetric
   * auth (`sign`/`verify`) MUST be configured.
   */
  auth: AuthOptions;
  /**
   * Per-RPC-call timeout, client-wide. Default: 30000ms. Set it generously
   * — it is the safety net that heals a dead session (a TIMEOUT resets and
   * the next call re-handshakes). For a SHORTER budget on a single call,
   * pass `{ signal: AbortSignal.timeout(ms) }` — that rejects with ABORTED
   * and does not touch the session.
   */
  timeout?: number;
  /** Max concurrent pending RPC calls. Default: 256. */
  maxPending?: number;
  /**
   * How long (ms) a frame may wait for a live channel before the call
   * fails with a definite never-sent error (plain `RPCError("CHANNEL")`).
   * A `send` that throws does not fail the call — the frame enters the
   * core outbound queue and is retried until this expires. An unsent
   * frame always fails with the definite `CHANNEL` code — even when the
   * global `timeout` fires first. Default: 3000ms.
   */
  sendTimeout?: number;
  /**
   * Max time (ms) to complete the handshake from when the client hello
   * is sent. Triggered lazily by the first RPC call, or on retry after
   * a previous handshake failure / reset. Default: 5000ms.
   */
  handshakeTimeout?: number;
  maxMessageBytes?: number;
}

// ─── Client ──────────────────────────────────────────────

export function client<T extends Router>(
  channel: Channel,
  opts: ClientOptions,
): {
  api: Client<T>;
  destroy: () => void;
} {
  if (typeof channel.send !== "function") {
    throw new TypeError("client() channel.send must be a function");
  }
  if (typeof channel.receive !== "function") {
    throw new TypeError("client() channel.receive must be a function");
  }

  validateAuthConfig(opts.auth);
  const auth = opts.auth;
  const timeout = opts.timeout !== undefined ? opts.timeout : DEFAULT_TIMEOUT;
  if (
    typeof timeout !== "number" ||
    !Number.isFinite(timeout) ||
    timeout <= 0
  ) {
    throw new TypeError("client() timeout must be a number > 0 ms");
  }
  const maxPending =
    opts.maxPending !== undefined ? opts.maxPending : MAX_PENDING;
  // Reject NaN/Infinity/non-integers outright: `pending.size >= NaN` is
  // false for every size, which would silently disable the cap.
  if (!Number.isInteger(maxPending) || maxPending <= 0) {
    throw new TypeError("client() maxPending must be an integer > 0");
  }
  const sendTimeout =
    opts.sendTimeout !== undefined ? opts.sendTimeout : DEFAULT_SEND_TIMEOUT;
  if (
    typeof sendTimeout !== "number" ||
    !Number.isFinite(sendTimeout) ||
    sendTimeout < 0
  ) {
    throw new TypeError("client() sendTimeout must be a number ≥ 0 ms");
  }
  const hsTimeout =
    opts.handshakeTimeout !== undefined
      ? opts.handshakeTimeout
      : HANDSHAKE_TIMEOUT;
  if (
    typeof hsTimeout !== "number" ||
    !Number.isFinite(hsTimeout) ||
    hsTimeout < 100
  ) {
    throw new TypeError("client() handshakeTimeout must be ≥ 100 ms");
  }
  const maxBytes =
    opts.maxMessageBytes !== undefined ? opts.maxMessageBytes : MAX_MSG_BYTES;
  // Same NaN guard as maxPending: `data.length > NaN` is always false.
  if (!Number.isInteger(maxBytes) || maxBytes <= 0) {
    throw new TypeError("client() maxMessageBytes must be an integer > 0");
  }

  // ── State machine: idle → handshaking → ready, or closed ──
  // idle:        no session. Next RPC call triggers handshake.
  // handshaking: hello sent, waiting for server reply.
  //              All RPC calls await the same handshakePromise.
  // ready:       session key established. RPC calls go through.
  // closed:      destroyed. All calls throw.
  //
  // On handshake failure, state → idle; the next call re-handshakes.
  // AUTO-RESET: Only an RPCAbortedError(TIMEOUT) — a sent request with no
  //   reply — while ready zeros crypto and goes idle WITHOUT resending.
  //   Plain RPCError (frame never left: CHANNEL, unsent TIMEOUT) never
  //   resets — transport failure is not a session event. Other pending
  //   calls keep their timers; the next call re-handshakes lazily. Epoch
  //   prevents redundant resets. Guardrail (CLIENT) errors never reset.
  let state: "idle" | "handshaking" | "ready" | "closed" = "idle";

  // Ephemeral keys — regenerated per handshake attempt
  let privateKey: Uint8Array | null = null;
  let publicKey: Uint8Array | null = null;
  let clientNonce: Uint8Array | null = null;
  let sessionKey: Uint8Array | null = null;
  let encrypt: ((data: unknown) => Uint8Array) | null = null;
  let decrypt: ((payload: Uint8Array) => unknown) | null = null;

  // Epoch — incremented per handshake attempt, prevents stale replies
  let epoch = 0;

  // Handshake coordination — multiple calls share one promise
  let handshakePromise: Promise<void> | null = null;
  let handshakeResolve: (() => void) | null = null;
  let handshakeReject: ((err: unknown) => void) | null = null;
  let hsTimer: ReturnType<typeof setTimeout> | null = null;
  // Absolute wall-clock deadline of the current handshake attempt. Twin of
  // hsTimer: the timer alone cannot bound a SYNCHRONOUS auth callback that
  // blocks past the budget — its continuation resumes as a microtask BEFORE
  // the timer macrotask fires. Guards after every await also check this.
  let hsDeadline = 0;

  // Pending RPC responses. `sent` is the wire boundary: true once
  // `channel.send` returned without throwing (or its promise was handed
  // off — optimistic, see enqueue comment). It decides the class of every
  // terminal rejection: sent → RPCAbortedError (outcome UNKNOWN), unsent →
  // plain RPCError (provably never left).
  interface PendingEntry {
    resolve: (v: unknown) => void;
    reject: (e: unknown) => void;
    timer: ReturnType<typeof setTimeout>;
    sent: boolean;
  }
  const pending = new Map<string, PendingEntry>();
  let counter = 0;

  // ── Outbound queue: frames whose send failed, retried until sendTimeout ─
  // The channel contract (common.ts) forbids adapter queues — the core is
  // the only owner of undelivered frames, so "never left" is a fact it
  // knows, not an inference. Frames are already encrypted; `epoch` stales
  // them on reset (ciphertext under a zeroed key can never succeed).
  type OutboundEntry =
    | { kind: "hello"; frame: Uint8Array; epoch: number }
    | {
        kind: "msg";
        frame: Uint8Array;
        id: string;
        prop: string;
        epoch: number;
        expiresAt: number;
        cause?: unknown;
      };
  const outbound: OutboundEntry[] = [];
  let flushTimer: ReturnType<typeof setInterval> | null = null;
  // True while an async `send` of a queued frame is unresolved — blocks
  // concurrent flush passes so order is preserved.
  let flushInflight = false;

  function isThenable(v: unknown): v is Promise<void> {
    return (
      v !== null &&
      typeof v === "object" &&
      typeof (v as { then?: unknown }).then === "function"
    );
  }

  function startFlushTimer(): void {
    if (flushTimer === null) {
      flushTimer = setInterval(flushOutbound, SEND_RETRY_MS);
    }
  }

  function stopFlushTimerIfIdle(): void {
    if (flushTimer !== null && outbound.length === 0 && !flushInflight) {
      clearInterval(flushTimer);
      flushTimer = null;
    }
  }

  function enqueueMsg(
    id: string,
    prop: string,
    frame: Uint8Array,
    cause?: unknown,
  ): void {
    outbound.push({
      kind: "msg",
      frame,
      id,
      prop,
      epoch,
      expiresAt: Date.now() + sendTimeout,
      cause,
    });
    startFlushTimer();
  }

  function removeOutboundMsg(
    id: string,
  ): (OutboundEntry & { kind: "msg" }) | undefined {
    let removed: (OutboundEntry & { kind: "msg" }) | undefined;
    for (let i = 0; i < outbound.length; i++) {
      const e = outbound[i];
      if (e !== undefined && e.kind === "msg" && e.id === id) {
        outbound.splice(i, 1);
        removed = e;
        break;
      }
    }
    stopFlushTimerIfIdle();
    return removed;
  }

  // Reject a still-queued call with a plain (never-left) error and drop
  // its frame. Used by expiry, reset staling, and destroy.
  function failQueued(e: OutboundEntry & { kind: "msg" }, err: RPCError): void {
    const p = pending.get(e.id);
    if (p === undefined) return;
    pending.delete(e.id);
    clearTimeout(p.timer);
    p.reject(err);
  }

  // Drop entries that can no longer be sent meaningfully:
  // • hellos of a dead attempt (state/epoch mismatch) — silently; this is
  //   what revokes a stale hello after handshakeTimeout, no residual flush;
  // • msgs whose call already settled — silently;
  // • msgs staled by a reset (epoch mismatch) — plain CHANNEL (belt for
  //   reset()'s own purge);
  // • msgs past their sendTimeout — plain CHANNEL, the definite failure.
  function dropStaleAndExpired(): void {
    const now = Date.now();
    for (let i = outbound.length - 1; i >= 0; i--) {
      const e = outbound[i];
      if (e === undefined) continue;
      if (e.kind === "hello") {
        if (state !== "handshaking" || epoch !== e.epoch) {
          outbound.splice(i, 1);
        }
        continue;
      }
      const p = pending.get(e.id);
      if (p === undefined || p.sent) {
        outbound.splice(i, 1);
        continue;
      }
      if (epoch !== e.epoch) {
        outbound.splice(i, 1);
        failQueued(
          e,
          new RPCError(
            "CHANNEL",
            "Session reset before send: " + e.prop,
            undefined,
            { cause: e.cause },
          ),
        );
        continue;
      }
      if (now >= e.expiresAt) {
        outbound.splice(i, 1);
        failQueued(
          e,
          new RPCError(
            "CHANNEL",
            "Not sent within sendTimeout: " + e.prop,
            undefined,
            { cause: e.cause },
          ),
        );
      }
    }
  }

  function markSent(e: OutboundEntry): void {
    if (e.kind !== "msg") return;
    const p = pending.get(e.id);
    if (p !== undefined) p.sent = true;
  }

  function flushOutbound(): void {
    if (flushInflight) return;
    dropStaleAndExpired();
    while (outbound.length > 0) {
      const e = outbound[0];
      if (e === undefined) break;
      let res: unknown;
      try {
        res = channel.send(e.frame) as unknown;
      } catch (err: unknown) {
        // Channel still down — head-of-line: if it can't take this frame
        // it can't take the next. Keep the freshest cause for diagnostics.
        if (e.kind === "msg") e.cause = err;
        break;
      }
      if (isThenable(res)) {
        // Optimistic sent: an unconfirmed frame counts as "left" — a false
        // "unknown outcome" is safe, a false "never left" is not. Rolled
        // back on rejection.
        outbound.shift();
        markSent(e);
        flushInflight = true;
        res.then(
          function onFlushSent() {
            flushInflight = false;
            flushOutbound();
          },
          function onFlushFail(err: unknown) {
            flushInflight = false;
            if (e.kind === "msg") {
              const p = pending.get(e.id);
              if (p !== undefined && p.sent) {
                p.sent = false;
                if (state === "ready" && epoch === e.epoch) {
                  e.cause = err;
                  outbound.unshift(e);
                  startFlushTimer();
                } else {
                  // The session was reset (or replaced) while this frame's
                  // async send was in flight. The rejection proves it never
                  // left, and its ciphertext is under the zeroed key — it
                  // can never succeed. Fail NOW (reset invalidates the
                  // queue); resurrecting it would retry dead ciphertext.
                  failQueued(
                    e,
                    new RPCError(
                      "CHANNEL",
                      "Session reset before send: " + e.prop,
                      undefined,
                      { cause: err },
                    ),
                  );
                }
              }
            } else if (state === "handshaking" && epoch === e.epoch) {
              outbound.unshift(e);
              startFlushTimer();
            }
            stopFlushTimerIfIdle();
          },
        );
        return;
      }
      outbound.shift();
      markSent(e);
    }
    stopFlushTimerIfIdle();
  }

  const knownProcedures = new Set<string>();

  function clearHsTimer(): void {
    if (hsTimer !== null) {
      clearTimeout(hsTimer);
      hsTimer = null;
    }
  }

  function zeroKeys(): void {
    if (privateKey !== null) {
      zero(privateKey);
      privateKey = null;
    }
    if (publicKey !== null) {
      zero(publicKey);
      publicKey = null;
    }
    if (clientNonce !== null) {
      zero(clientNonce);
      clientNonce = null;
    }
    if (sessionKey !== null) {
      zero(sessionKey);
      sessionKey = null;
    }
    encrypt = null;
    decrypt = null;
  }

  function rejectPending(err: RPCError): void {
    for (const [, entry] of pending) {
      clearTimeout(entry.timer);
      entry.reject(err);
    }
    pending.clear();
  }

  function failHandshake(err: unknown): void {
    clearHsTimer();
    const rej = handshakeReject;
    handshakePromise = null;
    handshakeResolve = null;
    handshakeReject = null;
    zeroKeys();
    state = "idle";
    if (rej !== null) {
      rej(
        err instanceof RPCError
          ? err
          : new RPCError("HANDSHAKE", "Handshake failed"),
      );
    }
  }

  function startHandshake(): Promise<void> {
    privateKey = x25519.utils.randomSecretKey();
    publicKey = x25519.getPublicKey(privateKey);
    clientNonce = randomBytes(KEY_LEN);
    epoch++;
    state = "handshaking";

    const currentEpoch = epoch;
    const myPub = publicKey;
    const myNonce = clientNonce;

    // Hold the promise locally — over a synchronous transport, channel.send
    // may run the entire handshake round-trip and call failHandshake() before
    // we return. failHandshake() nulls `handshakePromise`, so we'd otherwise
    // return null. Returning a local reference keeps the rejected promise
    // reachable for the awaiter.
    const promise = new Promise<void>(function hsExecutor(resolve, reject) {
      handshakeResolve = resolve;
      handshakeReject = reject;
    });
    handshakePromise = promise;
    // Pre-attach a noop catch so a synchronous rejection (sync transports)
    // does not surface as an unhandled rejection before the caller's
    // `await` can attach its own handler.
    promise.catch(() => {});

    hsDeadline = Date.now() + hsTimeout;
    hsTimer = setTimeout(function onHsTimeout() {
      if (state !== "handshaking" || epoch !== currentEpoch) return;
      failHandshake(new RPCError("HANDSHAKE", "Handshake timeout"));
    }, hsTimeout);

    // auth.sign can be async (e.g. WebCrypto.sign). Wrap the
    // remainder of hello construction in a coroutine and route any failure
    // through failHandshake so the API surface stays the same.
    (async function buildAndSendHello() {
      let authPayload: Uint8Array | null = null;
      if (auth.sign !== undefined) {
        const transcript = buildHelloTranscript(currentEpoch, myPub, myNonce);
        const signed = await auth.sign(transcript);
        if (
          state !== "handshaking" ||
          epoch !== currentEpoch ||
          Date.now() >= hsDeadline
        ) {
          return;
        }
        if (
          !(signed instanceof Uint8Array) ||
          signed.length === 0 ||
          signed.length > MAX_AUTH_BYTES
        ) {
          throw new RPCError("HANDSHAKE", "auth.sign returned invalid payload");
        }
        authPayload = signed;
      }

      const helloMsg: Record<string, unknown> = {
        pub: myPub,
        nonce: myNonce,
        epoch: currentEpoch,
      };
      if (authPayload !== null) helloMsg["auth"] = authPayload;

      const helloPayload = mpEncode(helloMsg);
      const hello = concatBytes(new Uint8Array([TAG_HELLO]), helloPayload);
      zero(helloPayload);
      try {
        await channel.send(hello);
      } catch {
        if (state !== "handshaking" || epoch !== currentEpoch) return;
        // Channel down — not a handshake failure. Queue the hello and let
        // the flush tick retry; the attempt stays bounded by hsTimer. If
        // the attempt dies first, the queued hello is revoked by the
        // state/epoch check in dropStaleAndExpired — it never flushes
        // late. The send error is intentionally not surfaced:
        // transport-down is the queue's normal input, not a failure.
        outbound.push({ kind: "hello", frame: hello, epoch: currentEpoch });
        startFlushTimer();
      }
    })().catch(function onProduceError(err: unknown) {
      if (state !== "handshaking" || epoch !== currentEpoch) return;
      failHandshake(err);
    });

    return promise;
  }

  function ensureHandshake(): Promise<void> {
    if (state === "ready") return Promise.resolve();
    if (state === "closed") {
      return Promise.reject(new RPCError("SESSION", "Session destroyed"));
    }
    if (state === "handshaking" && handshakePromise !== null) {
      return handshakePromise;
    }
    return startHandshake();
  }

  // ── Persistent message listener ───────────────────────────

  const unsubscribe = channel.receive(function onMessage(raw: Uint8Array) {
    if (state === "closed" || raw.length === 0) return;
    // Normalize so the inbound buffer is a plain Uint8Array; Node's
    // `Buffer` propagates its subclass through `subarray()` into msgpack
    // `bin` fields, which would defeat downstream `isPlainBytes` checks.
    const data = toPlainBytes(raw);
    const tag = data[0];

    // ── Handshake response ──
    if (tag === TAG_HELLO && state === "handshaking") {
      if (data.length > MAX_HELLO_BYTES) return;
      if (privateKey === null || publicKey === null || clientNonce === null) {
        return;
      }

      // Snapshot ephemeral state by value. reset() zeros the live buffers
      // in place; owning copies means a concurrent reset cannot corrupt
      // our derivation. Zero our copies in the finally block.
      const currentEpoch = epoch;
      const priv = privateKey.slice();
      const pub = publicKey.slice();
      const nonce = clientNonce.slice();

      // auth.verify can be async (e.g. WebCrypto.verify) so
      // run the entire reply path in a coroutine. The epoch guard
      // makes sure a stale reply doesn't promote a destroyed/reset
      // session.
      (async function processReply() {
        let rawShared: Uint8Array | null = null;
        let localSessionKey: Uint8Array | null = null;

        try {
          const raw = sanitize(mpDecode(data.subarray(1)));
          if (typeof raw !== "object" || raw === null) {
            throw new RPCError("HANDSHAKE", "Invalid hello");
          }
          const hello = raw as Record<string, unknown>;

          // Strict epoch validation. Stale replies are silently dropped;
          // malformed epochs fail the handshake.
          const replyEpoch = hello["epoch"];
          if (
            typeof replyEpoch !== "number" ||
            !Number.isInteger(replyEpoch) ||
            replyEpoch < 0 ||
            replyEpoch > 0xffffffff
          ) {
            throw new RPCError("HANDSHAKE", "Invalid epoch");
          }
          if (replyEpoch !== currentEpoch) return; // stale, silently drop

          const serverPub = hello["pub"];
          if (!isPlainBytes(serverPub) || serverPub.length !== KEY_LEN) {
            throw new RPCError("HANDSHAKE", "Invalid public key");
          }

          const proof = hello["proof"];
          if (!isPlainBytes(proof) || proof.length !== PROOF_LEN) {
            throw new RPCError("HANDSHAKE", "Invalid proof");
          }

          // ── Server-side auth verification ─────────────────
          // If `verify` is configured, the server MUST embed an `auth`
          // payload bound to the canonical reply transcript. Run BEFORE
          // accepting the session — a failed verification never reaches
          // the encryption-state transition.
          if (auth.verify !== undefined) {
            const replyAuth = hello["auth"];
            if (!isPlainBytes(replyAuth)) {
              throw new RPCError(
                "HANDSHAKE",
                "auth.verify configured but reply.auth missing or invalid",
              );
            }
            if (replyAuth.length === 0 || replyAuth.length > MAX_AUTH_BYTES) {
              throw new RPCError("HANDSHAKE", "reply.auth size out of range");
            }
            const transcript = buildReplyTranscript(
              currentEpoch,
              pub,
              nonce,
              serverPub,
            );
            await auth.verify(replyAuth, transcript);
            // Epoch guard: handshake might have been reset / destroyed
            // while verify was awaiting (e.g. user destroy()). Deadline
            // guard: a sync verify that blocked past the budget must not
            // publish a session the timer already condemned.
            if (
              state !== "handshaking" ||
              epoch !== currentEpoch ||
              Date.now() >= hsDeadline
            ) {
              return;
            }
          }

          rawShared = x25519.getSharedSecret(priv, serverPub);
          zero(priv);

          const secretBytes =
            auth.secret !== undefined ? await auth.secret() : EMPTY_SECRET;
          if (
            state !== "handshaking" ||
            epoch !== currentEpoch ||
            Date.now() >= hsDeadline
          ) {
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

          const expected = computeProof(localSessionKey, serverPub, pub, nonce);
          const proofOk = constTimeEqual(proof, expected);
          zero(expected);
          if (!proofOk) {
            throw new RPCError("HANDSHAKE", "Authentication failed");
          }

          // Final guard before publishing module-level state. The block
          // below is synchronous; no further awaits can race against us.
          if (
            state !== "handshaking" ||
            epoch !== currentEpoch ||
            Date.now() >= hsDeadline
          ) {
            return;
          }

          sessionKey = localSessionKey;
          localSessionKey = null; // ownership transferred — finally won't zero
          encrypt = createEncryptor(sessionKey);
          decrypt = createDecryptor(sessionKey);

          clearHsTimer();
          const res = handshakeResolve;
          handshakePromise = null;
          handshakeResolve = null;
          handshakeReject = null;
          state = "ready";
          if (res !== null) res();
        } finally {
          if (rawShared !== null) zero(rawShared);
          if (localSessionKey !== null) zero(localSessionKey);
          zero(priv);
          zero(pub);
          zero(nonce);
        }
      })().catch(function onReplyError(err: unknown) {
        // Only fail the handshake if we're STILL actively handshaking this
        // attempt. A reply coroutine that rejects after the attempt already
        // completed (state "ready") or was reset ("idle") is a stale or
        // MITM-injected frame carrying the current epoch — drop it silently
        // instead of tearing down the session a concurrent valid reply just
        // established. (Client-side analog of the server's D1 deferred reset.)
        if (state !== "handshaking" || epoch !== currentEpoch) return;
        failHandshake(err);
      });
      return;
    }

    // ── RPC response ──
    if (tag === TAG_MSG && state === "ready" && decrypt !== null) {
      if (data.length > maxBytes) return;

      let raw: unknown;
      try {
        raw = decrypt(data);
      } catch {
        return; // poly1305 auth failed → silent drop
      }

      try {
        if (typeof raw !== "object" || raw === null) return;
        const msg = raw as Record<string, unknown>;

        if (msg["t"] !== 2) return;
        const rawId = msg["id"];
        if (typeof rawId !== "string" || rawId.length === 0) return;

        // Strict discriminator and envelope shape: the protocol defines
        // exactly two response forms. Validate all required outer fields
        // BEFORE touching the pending entry, so malformed frames cannot
        // consume a call that is still waiting for a valid response.
        const has = Object.prototype.hasOwnProperty;
        const ok = msg["ok"];
        if (ok !== true && ok !== false) return;
        if (!has.call(msg, "d") || !has.call(msg, "e")) return;
        if (ok === true) {
          if (msg["e"] !== null) return;
        } else {
          const error = msg["e"];
          if (
            msg["d"] !== null ||
            typeof error !== "object" ||
            error === null ||
            Array.isArray(error) ||
            error instanceof Uint8Array
          ) {
            return;
          }
        }

        const entry = pending.get(rawId);
        if (entry === undefined) return;

        pending.delete(rawId);
        clearTimeout(entry.timer);

        if (ok === true) {
          entry.resolve(msg["d"]);
        } else {
          const e = msg["e"];
          if (typeof e !== "object" || e === null) {
            entry.reject(new RemoteRPCError("UNKNOWN", "Unknown error"));
          } else {
            // Coerce defensively — remote can send anything, even after
            // sanitize. `String(undefined)` yields "undefined" which is
            // a misleading code; require a non-empty string instead.
            const ec = (e as Record<string, unknown>)["c"];
            const em = (e as Record<string, unknown>)["m"];
            const ed = (e as Record<string, unknown>)["d"];
            const code =
              typeof ec === "string" && ec.length > 0 ? ec : "UNKNOWN";
            const message = typeof em === "string" ? em : "";
            entry.reject(new RemoteRPCError(code, message, ed));
          }
        }
      } catch {
        // Unexpected processing error — silent drop, call times out
      }
    }
  });

  // ── Per-call abort ───────────────────────────────────────

  function abortError(prop: string, reason: unknown): RPCError {
    return new RPCError("ABORTED", "Call aborted: " + prop, undefined, {
      cause: reason,
    });
  }

  /**
   * Await `p`, but reject early with ABORTED if the signal fires. The
   * underlying promise is left running — a shared handshake must complete
   * for its other awaiters (it already carries a noop catch, so a later
   * rejection cannot surface as unhandled).
   */
  function raceAbort<T>(
    p: Promise<T>,
    signal: AbortSignal,
    prop: string,
  ): Promise<T> {
    return new Promise<T>(function raceExec(resolve, reject) {
      function onAbort(): void {
        reject(abortError(prop, signal.reason));
      }
      signal.addEventListener("abort", onAbort, { once: true });
      p.then(
        function onOk(v: T) {
          signal.removeEventListener("abort", onAbort);
          resolve(v);
        },
        function onErr(e: unknown) {
          signal.removeEventListener("abort", onAbort);
          reject(e);
        },
      );
    });
  }

  // ── Send a single RPC request, returns promise for the response ──

  function sendRequest(
    prop: string,
    input: unknown,
    signal?: AbortSignal,
  ): Promise<unknown> {
    const enc = encrypt;
    if (state === "closed" || enc === null) {
      return Promise.reject(new RPCError("SESSION", "Session destroyed"));
    }
    if (signal !== undefined && signal.aborted) {
      // Covers the microtask gap between the handshake race resolving and
      // this call — a listener added to an already-aborted signal never fires.
      return Promise.reject(abortError(prop, signal.reason));
    }
    if (pending.size >= maxPending) {
      return Promise.reject(
        new RPCError("CLIENT", "Too many pending requests"),
      );
    }

    if (counter >= Number.MAX_SAFE_INTEGER - 1) {
      return Promise.reject(
        new RPCError(
          "CLIENT",
          "Request id counter exhausted; destroy and recreate client",
        ),
      );
    }
    const id = String(++counter);
    // The frame below is encrypted under THIS epoch's key. Captured so the
    // async-send rollback can tell a live session from one that was reset
    // (and possibly re-established) while the send promise was in flight.
    const sendEpoch = epoch;
    // Omit `i` entirely for `undefined` input rather than encoding it —
    // msgpack has no `undefined` primitive and would round-trip it as
    // `null`, which a `.optional()` (as opposed to `.nullish()`) Zod schema
    // rejects. A dropped key decodes back to `undefined` on the server.
    // `input` is already sanitized by the proxy (before the handshake, so a
    // non-plain value never even emits TAG_HELLO) — do not re-sanitize the
    // rebuilt tree here.
    const req: Record<string, unknown> = { t: 1, id, p: prop };
    if (input !== undefined) req["i"] = input;
    const encrypted = enc(req);
    if (encrypted.length > maxBytes) {
      // The frame is still local: do not hand an oversized ciphertext to the
      // adapter, where it would become a sent request that the peer must
      // silently drop and the caller would only discover by timeout.
      zero(encrypted);
      return Promise.reject(
        new RPCError("CLIENT", "Message exceeds maxMessageBytes"),
      );
    }

    return new Promise(function rpcExec(res, rej) {
      // Listener hygiene: every settle path (resolve, reject, timeout,
      // abort, send error) detaches the abort listener, or long-lived
      // signals reused across calls would accumulate closures.
      let onAbort: (() => void) | null = null;
      function settle(): void {
        if (onAbort !== null && signal !== undefined) {
          signal.removeEventListener("abort", onAbort);
          onAbort = null;
        }
      }

      const entry: PendingEntry = {
        resolve: function resolveSettled(v: unknown) {
          settle();
          res(v);
        },
        reject: function rejectSettled(e: unknown) {
          settle();
          rej(e);
        },
        timer: setTimeout(function onRpcTimeout() {
          pending.delete(id);
          settle();
          if (entry.sent) {
            // The request left; a reply never came. Outcome UNKNOWN —
            // this is the one signal that the session may be desynced,
            // and the only trigger of the auto-reset (proxy catch).
            rej(new RPCAbortedError("TIMEOUT", "Timed out: " + prop));
          } else {
            // Global timer beat sendTimeout (timeout < sendTimeout
            // config) while the frame was still queued — it never left,
            // so the definite CHANNEL code applies regardless of which
            // timer fired first. Plain TIMEOUT thus never occurs: the
            // TIMEOUT code always means "sent, no reply" (aborted class).
            const q = removeOutboundMsg(id);
            rej(
              new RPCError(
                "CHANNEL",
                "Not sent within timeout: " + prop,
                undefined,
                { cause: q !== undefined ? q.cause : undefined },
              ),
            );
          }
        }, timeout),
        sent: false,
      };
      pending.set(id, entry);

      if (signal !== undefined) {
        onAbort = function onCallAbort() {
          onAbort = null; // {once:true} already removed the listener
          if (pending.get(id) !== entry) return;
          pending.delete(id);
          clearTimeout(entry.timer);
          if (entry.sent) {
            // The request may have executed on the server — same UNKNOWN
            // outcome as a timeout. A late reply finds no pending entry
            // and is silently dropped. The session is not touched.
            rej(
              new RPCAbortedError(
                "ABORTED",
                "Call aborted: " + prop,
                undefined,
                { cause: signal.reason },
              ),
            );
          } else {
            // Still in the outbound queue — provably never left.
            removeOutboundMsg(id);
            rej(abortError(prop, signal.reason));
          }
        };
        signal.addEventListener("abort", onAbort, { once: true });
      }

      // Send now if the line is clear; queue behind earlier frames
      // otherwise (a non-empty queue means the channel was down a tick
      // ago — jumping it would reorder for no gain). A failed send does
      // NOT reject the call: the frame provably never left, the core
      // owns it and retries until sendTimeout. Async sends are counted
      // sent optimistically (a false "unknown outcome" is safe, a false
      // "never left" is not) and rolled back to the queue on rejection.
      if (outbound.length > 0 || flushInflight) {
        enqueueMsg(id, prop, encrypted);
      } else {
        try {
          const sent = channel.send(encrypted) as unknown;
          if (isThenable(sent)) {
            entry.sent = true;
            sent.catch(function onAsyncSendFail(err: unknown) {
              if (pending.get(id) !== entry || !entry.sent) return;
              entry.sent = false;
              if (state === "ready" && epoch === sendEpoch) {
                enqueueMsg(id, prop, encrypted, err);
              } else {
                // Reset (or reset + re-handshake) happened while the send
                // promise was pending. `enqueueMsg` stamps the CURRENT
                // epoch, which would smuggle old-key ciphertext past the
                // staleness check — under a new session it can never
                // decrypt. The rejection proves the frame never left:
                // fail plain CHANNEL immediately.
                pending.delete(id);
                clearTimeout(entry.timer);
                entry.reject(
                  new RPCError(
                    "CHANNEL",
                    "Session reset before send: " + prop,
                    undefined,
                    { cause: err },
                  ),
                );
              }
            });
          } else {
            entry.sent = true;
          }
        } catch (err: unknown) {
          enqueueMsg(id, prop, encrypted, err);
        }
      }
    });
  }

  // ── API proxy ─────────────────────────────────────────────

  const api = new Proxy(Object.create(null) as Client<T>, {
    get(_target, prop) {
      if (typeof prop !== "string") return undefined;
      if (prop === "then") return undefined;

      return async function call(
        input: unknown,
        callOpts?: CallOptions,
      ): Promise<unknown> {
        if (state === "closed") {
          throw new RPCError("SESSION", "Session destroyed");
        }

        const signal = callOpts !== undefined ? callOpts.signal : undefined;
        if (signal !== undefined && signal.aborted) {
          // Already aborted: nothing is sent, no handshake is triggered.
          throw abortError(prop, signal.reason);
        }

        // Validate caller data before starting a lazy handshake. A bad first
        // input must not even emit TAG_HELLO; sanitize() also canonicalizes
        // plain objects before the encrypted request is built.
        const sanitizedInput =
          input === undefined ? undefined : sanitize(input);

        if (signal !== undefined) {
          // Abort rejects THIS call only; the handshake itself is shared
          // state and keeps running for other callers / the next call.
          await raceAbort(ensureHandshake(), signal, prop);
        } else {
          await ensureHandshake();
        }

        if (knownProcedures.size < MAX_KNOWN_PROCEDURES) {
          knownProcedures.add(prop);
        }

        // Capture epoch before sending — used to detect stale failures.
        const sentEpoch = epoch;

        try {
          return await sendRequest(prop, sanitizedInput, signal);
        } catch (err: unknown) {
          // No auto-retry. An RPCAbortedError leaves the outcome UNKNOWN
          // (the request may have executed — auto-resending it is a silent
          // double-execution hazard for non-idempotent handlers); a plain
          // local error means the request provably never left. Either way
          // the error surfaces and the CALLER decides whether to retry —
          // it alone knows if the procedure is idempotent.
          //
          // We still reset the session (but do NOT resend) on exactly one
          // trigger: a reply-timeout on a SENT request — "it went out and
          // the server never answered" is the one signal the session may
          // be desynced (e.g. a restarted server silently dropping
          // TAG_MSG over a live transport); without the reset every
          // future call would wedge. A never-left CHANNEL failure is a
          // transport event, not a session event — the keys are fine,
          // and if send throws, a re-handshake's hello couldn't leave
          // either. ABORTED is a caller-local decision; guardrail
          // (CLIENT) and SESSION errors must not tear down a good key.
          if (
            state === "ready" &&
            epoch === sentEpoch &&
            err instanceof RPCAbortedError &&
            err.code === "TIMEOUT"
          ) {
            reset();
          }
          throw err;
        }
      };
    },
    has(_target, prop) {
      return typeof prop === "string" && knownProcedures.has(prop);
    },
    ownKeys() {
      return [...knownProcedures];
    },
    getOwnPropertyDescriptor(_target, prop) {
      if (typeof prop === "string" && knownProcedures.has(prop)) {
        return {
          configurable: true,
          enumerable: true,
          writable: false,
        };
      }
      return undefined;
    },
  });

  // ── Auto-reset ─────────────────────────────────────────────
  // Called on a reply-timeout of a SENT request (the one desync signal).
  // Zeros crypto and returns to idle. Sent pending calls are left
  // untouched — they'll time out naturally and retry individually
  // through the same catch → epoch-check → ensureHandshake path. Queued
  // UNSENT frames are failed immediately: they are ciphertext under the
  // zeroed key and can never succeed — plain CHANNEL, the definite
  // never-left error. If another call already reset (epoch advanced),
  // latecomers skip this and just join the in-progress handshake.

  function reset(): void {
    if (state !== "ready") return;
    zeroKeys();
    state = "idle";
    // Advance the epoch so anything encrypted under the zeroed key is
    // epoch-stale from this point on. This is what arms the belt in
    // dropStaleAndExpired for frames that were IN FLIGHT during the reset
    // (shifted out of `outbound`, so the purge below can't see them) and
    // get rolled back by an async-send rejection afterwards.
    epoch++;
    for (let i = outbound.length - 1; i >= 0; i--) {
      const e = outbound[i];
      if (e === undefined) continue;
      outbound.splice(i, 1);
      if (e.kind === "msg") {
        failQueued(
          e,
          new RPCError(
            "CHANNEL",
            "Session reset before send: " + e.prop,
            undefined,
            { cause: e.cause },
          ),
        );
      }
    }
    stopFlushTimerIfIdle();
  }

  // ── Destroy ───────────────────────────────────────────────

  function destroy(): void {
    if (state === "closed") return;
    const wasHandshaking = state === "handshaking";
    state = "closed";
    clearHsTimer();
    zeroKeys();
    unsubscribe?.();

    if (wasHandshaking && handshakeReject !== null) {
      const rej = handshakeReject;
      handshakePromise = null;
      handshakeResolve = null;
      handshakeReject = null;
      // Hello-waiters were never sent as calls — plain, retryable against
      // a fresh client.
      rej(new RPCError("SESSION", "Session destroyed"));
    }

    // Split the pending map by the sent boundary: still-queued frames
    // provably never left → plain; everything else was handed to the
    // transport → outcome unknown → RPCAbortedError.
    for (let i = outbound.length - 1; i >= 0; i--) {
      const e = outbound[i];
      if (e === undefined) continue;
      outbound.splice(i, 1);
      if (e.kind === "msg") {
        failQueued(e, new RPCError("SESSION", "Session destroyed"));
      }
    }
    if (flushTimer !== null) {
      clearInterval(flushTimer);
      flushTimer = null;
    }
    rejectPending(new RPCAbortedError("SESSION", "Session destroyed"));
  }

  return { api, destroy };
}
