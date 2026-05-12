/**
 * drpc/server — Resilient RPC server
 *
 * LIFECYCLE: Survives handshake failures and re-handshakes. Resets to
 * waiting on timeout, failure, or new hello (even in ready state).
 * Only explicit destroy() is permanent.
 */

import {
  x25519,
  concatBytes,
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
  isEmptyPsk,
  toPlainBytes,
  mpEncode,
  mpDecode,
  deriveSessionKey,
  computeProof,
  createEncryptor,
  createDecryptor,
  validateAuthConfig,
  EMPTY_PSK,
  buildHelloTranscript,
  buildReplyTranscript,
  RPCError,
  type Step,
  type HandlerFn,
  type Ctx,
  type Router,
  type Channel,
  type AuthOptions,
} from "./common.ts";

const MAX_ID_LEN = 64;

// ─── Server types ─────────────────────────────────────────

export interface ServerOptions {
  /**
   * Authentication configuration. At least one of `psk` OR asymmetric
   * auth (`sign`/`verify`) MUST be configured.
   */
  auth: AuthOptions;
  /**
   * Factory called per-request to create context for handlers.
   * MUST NOT hang — there is no server-side per-request timeout
   * (consistent with tRPC/oRPC). A blocking context() will accumulate
   * hanging closures until the client-side timeout fires.
   *
   * If `auth.verify` is configured and returns `auth` data,
   * it is passed to this factory as the optional first argument so the
   * application can merge it however it wants. The default behaviour
   * (when `context` is undefined) is to use the auth data directly as
   * the request context.
   */
  context?: (ctx: { auth?: Ctx }) => Ctx | Promise<Ctx>;
  /**
   * Max time (ms) to complete a handshake AFTER a client hello arrives.
   * The server waits indefinitely for a client to connect — this timeout
   * only governs the exchange once a hello is received.
   * On timeout the server resets to waiting (does NOT destroy).
   * Default: 5000ms.
   */
  handshakeTimeout?: number;
  maxMessageBytes?: number;
  /**
   * Called on handshake failures and non-fatal internal errors.
   * The server does NOT destroy on handshake failure — it resets to
   * waiting and accepts the next hello. Use this for logging/monitoring.
   */
  onError?: (err: unknown) => void;
}

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
        tip = function runMiddleware() {
          let called = false;
          return mw({
            ctx,
            input,
            next(extra?: Ctx) {
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
              return next();
            },
          });
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
// RESILIENT HANDSHAKE: The server survives handshake failures.
//
// States:
//   waiting — accepting hellos, no session yet
//   pending — hello reply sent, waiting for first valid encrypted msg
//   ready   — session established (first valid TAG_MSG decrypted)
//
// Transitions:
//   waiting → pending:  hello processed, reply sent
//   pending → ready:    first valid TAG_MSG decrypted (session confirmed)
//   pending → waiting:  timeout OR new hello arrives (client retry)
//   ready   → waiting:  new hello arrives (client re-handshaking)
//
// On handshake failure or timeout, the server resets with fresh
// ephemeral keys and waits for the next hello. An epoch counter
// guards against stale async operations from previous attempts.

export function server<T extends Router>(
  router: T,
  channel: Channel,
  opts: ServerOptions,
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
  const onError = opts.onError ?? null;

  let state: "waiting" | "pending" | "ready" = "waiting";
  let epoch = 0;
  let privateKey = x25519.utils.randomSecretKey();
  let publicKey = x25519.getPublicKey(privateKey);
  let sessionKey: Uint8Array | null = null;
  let encrypt: ((data: unknown) => Uint8Array) | null = null;
  let decrypt: ((payload: Uint8Array) => unknown) | null = null;
  // Verified auth data from auth.verify (server-only). Bound to
  // the current session; cleared on every reset so stale auth data
  // never leaks across handshake attempts.
  let authData: Ctx | null = null;
  let destroyed = false;
  let hsTimer: ReturnType<typeof setTimeout> | null = null;

  function clearHsTimer(): void {
    if (hsTimer !== null) {
      clearTimeout(hsTimer);
      hsTimer = null;
    }
  }

  /** Zero current keys, regenerate fresh ephemeral pair, return to waiting. */
  function resetHandshake(): void {
    clearHsTimer();
    epoch++;
    if (sessionKey !== null) {
      zero(sessionKey);
      sessionKey = null;
    }
    encrypt = null;
    decrypt = null;
    authData = null;
    zero(privateKey);
    zero(publicKey);
    privateKey = x25519.utils.randomSecretKey();
    publicKey = x25519.getPublicKey(privateKey);
    state = "waiting";
  }

  function destroy(): void {
    if (destroyed) return;
    destroyed = true;
    clearHsTimer();
    zero(privateKey);
    zero(publicKey);
    if (sessionKey !== null) {
      zero(sessionKey);
      sessionKey = null;
    }
    encrypt = null;
    decrypt = null;
    authData = null;
    if (unsubscribe !== null) {
      unsubscribe();
      unsubscribe = null;
    }
  }

  let unsubscribe: (() => void) | null = channel.receive(function onMessage(
    raw: Uint8Array,
  ) {
    if (destroyed || raw.length === 0) return;
    // Normalize so the inbound buffer is a plain Uint8Array; Node's
    // `Buffer` propagates its subclass through `subarray()` into msgpack
    // `bin` fields, which would defeat downstream `isPlainBytes` checks.
    const data = toPlainBytes(raw);
    const tag = data[0];

    // Every hello — regardless of current state — is a new attempt.
    // Reset unconditionally so the epoch is bumped even when a previous
    // attempt is still suspended at an `await`; in-flight stale coroutines
    // will detect the mismatch via the epoch guard and bail.
    if (tag === TAG_HELLO) {
      if (data.length > MAX_HELLO_BYTES) return;

      resetHandshake();

      const myEpoch = epoch;

      // Handshake timeout covers hello processing + waiting for
      // first encrypted message (session confirmation).
      hsTimer = setTimeout(function onHsTimeout() {
        if (epoch !== myEpoch || destroyed) return;
        resetHandshake();
        if (onError !== null) {
          onError(new RPCError("HANDSHAKE", "Handshake timeout"));
        }
      }, hsTimeout);

      (async function handleHello() {
        // Snapshot ephemeral keys by value. resetHandshake() may zero the
        // live buffers in place while we await; owning a copy means our
        // derivation is correct regardless of races.
        const myPriv = privateKey.slice();
        const myPub = publicKey.slice();

        // Local accumulators — only published to module-level state under
        // the FINAL epoch guard below. Cleaned up in finally on any exit.
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
          // the same predicate inside transcript building, but PSK-only
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
            if (epoch !== myEpoch || destroyed) return;
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
          // compatibility with PSK-only deployments.

          rawShared = x25519.getSharedSecret(myPriv, clientPub);
          // Private key no longer needed; zero our copy immediately.
          zero(myPriv);

          const pskBytes =
            auth.psk !== undefined ? await auth.psk() : EMPTY_PSK;
          if (epoch !== myEpoch || destroyed) return;

          if (!(pskBytes instanceof Uint8Array) || pskBytes.length < KEY_LEN) {
            throw new RPCError(
              "HANDSHAKE",
              `PSK must be a Uint8Array of at least ${KEY_LEN} bytes`,
            );
          }
          if (auth.psk !== undefined && isEmptyPsk(pskBytes)) {
            throw new RPCError(
              "HANDSHAKE",
              "Application returned an all-zero PSK",
            );
          }

          // The caller owns the PSK buffer's lifecycle — do NOT mutate it.
          // A `() => sharedSecret` pattern would break on the next handshake.
          localSessionKey = deriveSessionKey(rawShared, pskBytes);
          localProof = computeProof(localSessionKey, myPub, clientPub, nonce);

          // ── Server-side auth production ──────────────────
          // If `sign` is configured, sign over the canonical reply
          // transcript (which binds BOTH ephemeral pubs) so the client
          // can authenticate the server beyond what PSK alone provides.
          // Computed BEFORE state transition so a failure here cleanly
          // resets the handshake.
          if (auth.sign !== undefined) {
            const replyTranscript = buildReplyTranscript(
              clientEpoch,
              clientPub,
              nonce,
              myPub,
            );
            const signed = await auth.sign(replyTranscript);
            if (epoch !== myEpoch || destroyed) return;
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

          // FINAL epoch guard. The block below is fully synchronous, so the
          // module-level publishes (sessionKey, encrypt, decrypt, authData,
          // state) cannot race against an incoming hello.
          if (epoch !== myEpoch || destroyed) return;

          sessionKey = localSessionKey;
          localSessionKey = null; // ownership transferred — skip finally zero
          encrypt = createEncryptor(sessionKey);
          decrypt = createDecryptor(sessionKey);
          authData = localAuthData;
          state = "pending";

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

          await channel.send(reply);
          if (epoch !== myEpoch || destroyed) return;

          // Timer continues running — waiting for first valid TAG_MSG
          // to transition pending → ready. Total budget = hsTimeout.
        } finally {
          if (rawShared !== null) zero(rawShared);
          if (localSessionKey !== null) zero(localSessionKey);
          if (localProof !== null) zero(localProof);
          // myPriv may already be zeroed (after ECDH); harmless to repeat.
          zero(myPriv);
          zero(myPub);
        }
      })().catch(function onHsError(err: unknown) {
        if (epoch !== myEpoch || destroyed) return;
        resetHandshake();
        if (onError !== null) {
          onError(
            err instanceof RPCError
              ? err
              : new RPCError("HANDSHAKE", "Handshake failed"),
          );
        }
      });
      return;
    }

    if (tag === TAG_MSG && decrypt !== null && encrypt !== null) {
      if (data.length > maxBytes) return;

      const reqEpoch = epoch;

      (async function handleRequest() {
        if (decrypt === null || encrypt === null) return;

        let raw: unknown;
        try {
          raw = decrypt(data);
        } catch {
          return; // poly1305 failure → silently drop
        }

        // First valid decrypt confirms the session.
        // The client proved it has the correct sessionKey (which
        // requires the correct PSK) by producing a valid ciphertext.
        if (state === "pending") {
          clearHsTimer();
          state = "ready";
        }

        if (typeof raw !== "object" || raw === null) return;
        const msg = raw as Record<string, unknown>;

        if (msg["t"] !== 1) return;
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
            // Do NOT echo the attacker-controlled procedure name on the
            // wire — keep it in onError-only data for debuggability.
            throw new RPCError("NOT_FOUND", "Procedure not found", {
              procedure,
            });
          }
          const proc = frozen[procedure]!;
          // Snapshot auth data at request time so re-handshake mid-flight
          // does not race against an in-flight handler. The session is
          // bound to one handshake; if it resets, the response is dropped
          // by the epoch guard below.
          const ctxArg = authData !== null ? { auth: authData } : {};
          let ctx: Ctx;
          if (opts.context !== undefined) {
            ctx = await opts.context(ctxArg);
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

        // Epoch guard: if a reset/re-handshake happened while the
        // handler was running, this response belongs to a dead session.
        // Drop it — the client already timed out and retried.
        if (epoch !== reqEpoch || destroyed) return;

        const enc = encrypt;
        if (enc === null) return;
        await channel.send(enc(res));
      })().catch(function onSendError(err: unknown) {
        if (onError !== null) onError(err);
      });
    }
  });

  return { destroy };
}
