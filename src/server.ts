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
  type Authenticator,
} from "./common.ts";

// ─── Server types ─────────────────────────────────────────

export interface ServerOptions {
  /**
   * Authentication configuration. At least one of `psk` OR asymmetric
   * auth (`sign`/`verify`) MUST be configured.
   */
  auth?: AuthOptions;
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

  // Backward compatibility - old API
  /** @deprecated Use auth.psk instead */
  psk?: Uint8Array;
  /** @deprecated Use auth.sign/auth.verify instead */
  authenticator?: Authenticator;
}

// Backward compatibility
export type ServeOptions = ServerOptions;

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

  // Handle backward compatibility - convert old API to new API
  let auth: AuthOptions;
  if (opts.auth) {
    auth = opts.auth;
  } else if (opts.psk || opts.authenticator) {
    // Legacy API - convert to new format
    auth = {};
    if (opts.psk) {
      // Validate PSK at construction time for legacy API compatibility
      if (opts.psk.length < KEY_LEN) {
        throw new TypeError(`PSK must be at least ${KEY_LEN} bytes`);
      }
      const pskBytes = opts.psk;
      auth.psk = () => new Uint8Array(pskBytes);
    }
    if (opts.authenticator) {
      const authenticator = opts.authenticator as Authenticator;
      if (authenticator.produce) {
        auth.sign = authenticator.produce;
      }
      if (authenticator.verify) {
        auth.verify = authenticator.verify;
      }
    }
  } else {
    throw new TypeError(
      "Either 'auth' or legacy 'psk'/'authenticator' options must be provided"
    );
  }
  
  // Validate the final auth configuration
  validateAuthConfig(auth);

  const frozen: Router = Object.freeze(
    Object.assign(Object.create(null) as Router, router),
  );
  const hsTimeout =
    opts.handshakeTimeout !== undefined
      ? opts.handshakeTimeout
      : HANDSHAKE_TIMEOUT;
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
    data: Uint8Array,
  ) {
    if (destroyed || data.length === 0) return;
    const tag = data[0];

    // Accept hello in any active state. In "pending" or "ready",
    // reset the current session first — the client is re-handshaking.
    if (tag === TAG_HELLO) {
      if (data.length > MAX_HELLO_BYTES) return;

      // Reset any existing session for the new handshake attempt.
      if (state === "pending" || state === "ready") {
        resetHandshake();
      }

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
        // Capture keys locally — safe against future code changes
        // that might add an await before key usage.
        const myPriv = privateKey;
        const myPub = publicKey;

        const raw = sanitize(mpDecode(data.subarray(1)));
        if (typeof raw !== "object" || raw === null) {
          throw new RPCError("HANDSHAKE", "Invalid hello");
        }
        const hello = raw as Record<string, unknown> as any; // @TODO

        const clientPub = hello.pub;
        if (
          !(clientPub instanceof Uint8Array) ||
          clientPub.length !== KEY_LEN
        ) {
          throw new RPCError("HANDSHAKE", "Invalid public key");
        }

        const nonce = hello.nonce;
        if (!(nonce instanceof Uint8Array) || nonce.length !== KEY_LEN) {
          throw new RPCError("HANDSHAKE", "Invalid nonce");
        }

        // Client epoch — echoed in reply so client can discard
        // stale responses from previous handshake attempts.
        const clientEpoch = typeof hello.epoch === "number" ? hello.epoch : 0;

        // ── Client-side auth verification ─────────────────
        // If `verify` is configured, the client MUST embed an `auth`
        // payload bound to the canonical hello transcript. Reject
        // the handshake otherwise — and reject if the payload fails
        // verification — BEFORE deriving any session state, so a
        // failed verification does not silently leak ECDH artifacts.
        if (auth.verify !== undefined) {
          const helloAuth = hello.auth;
          if (!(helloAuth instanceof Uint8Array)) {
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
          // Epoch guard: if a new hello arrived during await (client retry
          // or DoS), this attempt is stale — abort silently.
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
              authData = sanitize(a) as Ctx;
            }
          }
        }
        // If `verify` is not configured, hello.auth is ignored even
        // if the client embedded one. This preserves backward
        // compatibility with PSK-only deployments.

        const rawShared = x25519.getSharedSecret(myPriv, clientPub);
        // Get PSK or use empty PSK if not configured
        const pskBytes = auth.psk !== undefined ? await auth.psk() : EMPTY_PSK;
        if (pskBytes.length < KEY_LEN) {
          throw new RPCError("HANDSHAKE", `PSK must be at least ${KEY_LEN} bytes`);
        }
        sessionKey = deriveSessionKey(rawShared, pskBytes);
        zero(rawShared);
        if (pskBytes !== EMPTY_PSK) zero(pskBytes);

        const proof = computeProof(sessionKey, myPub, clientPub, nonce);

        // ── Server-side auth production ──────────────────
        // If `sign` is configured, sign over the canonical
        // reply transcript (which binds BOTH ephemeral pubs) so the
        // client can authenticate the server beyond what PSK alone
        // provides. Computed BEFORE state transition so a failure
        // here cleanly resets the handshake.
        let serverAuth: Uint8Array | null = null;
        if (auth.sign !== undefined) {
          const replyTranscript = buildReplyTranscript(
            clientEpoch,
            clientPub,
            nonce,
            myPub,
          );
          const signed = await auth.sign(replyTranscript);
          if (epoch !== myEpoch || destroyed) {
            // Epoch advanced during await — drop everything.
            zero(proof);
            return;
          }
          if (
            !(signed instanceof Uint8Array) ||
            signed.length === 0 ||
            signed.length > MAX_AUTH_BYTES
          ) {
            zero(proof);
            throw new RPCError(
              "HANDSHAKE",
              "auth.sign returned invalid payload",
            );
          }
          serverAuth = signed;
        }

        // Set encrypt/decrypt BEFORE sending reply so synchronous
        // transports (e.g. MessageChannel) can process the client's
        // first TAG_MSG that arrives during channel.send().
        // State → "pending": accept TAG_MSG but session not confirmed.
        encrypt = createEncryptor(sessionKey);
        decrypt = createDecryptor(sessionKey);
        state = "pending";

        const replyMsg: Record<string, unknown> = {
          pub: myPub,
          proof,
          epoch: clientEpoch,
        };
        if (serverAuth !== null) replyMsg["auth"] = serverAuth;

        const replyPayload = mpEncode(replyMsg);
        const reply = concatBytes(new Uint8Array([TAG_HELLO]), replyPayload);
        zero(replyPayload);
        zero(proof);
        await channel.send(reply);

        // Epoch guard: if a new hello arrived during await (client retry),
        // this attempt is stale — abort silently.
        if (epoch !== myEpoch || destroyed) return;

        // Timer continues running — waiting for first valid TAG_MSG
        // to transition pending → ready. Total budget = hsTimeout.
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
        const msg = raw as Record<string, unknown> as any; // @TODO

        if (msg.t !== 1) return;
        if (typeof msg.id !== "string" || (msg.id as string).length === 0) {
          return;
        }
        if (typeof msg.p !== "string" || (msg.p as string).length === 0) {
          return;
        }

        const id = msg.id as string;
        const procedure = msg.p as string;
        let res: Record<string, unknown>;

        try {
          if (!(procedure in frozen)) {
            throw new RPCError("NOT_FOUND", "Unknown: " + procedure);
          }
          const proc = frozen[procedure]!;
          // Snapshot auth data at request time so re-handshake mid-flight
          // does not race against an in-flight handler. The session is
          // bound to one handshake; if it resets, the response is dropped
          // by the epoch guard below.
          const ctxArg = 
            authData !== null ? { auth: authData } : {};
          let ctx: Ctx;
          if (opts.context !== undefined) {
            ctx = await opts.context(ctxArg);
          } else if ('auth' in ctxArg && ctxArg.auth !== undefined) {
            ctx = Object.assign(Object.create(null), ctxArg.auth);
          } else {
            ctx = Object.create(null);
          }
          const result = await execute(proc._steps, proc._handler, ctx, msg.i);
          res = { t: 2, id, ok: true, d: result, e: null };
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
