/**
 * drpc/client — Lazy RPC client with auto-retry
 *
 * LIFECYCLE: Handshake triggers lazily on first RPC call. On session
 * failure (timeout/send error), resets and retries once with a fresh
 * handshake — transparent to the caller. Concurrent calls coordinate
 * via epoch to avoid redundant resets.
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
  type Router,
  type Channel,
  type AuthOptions,
} from "./common.ts";

// ─── Client constants ─────────────────────────────────────

const PROOF_LEN = 32;
const MAX_PENDING = 256;
const DEFAULT_TIMEOUT = 10_000;
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

export type Client<T extends Router> = {
  [K in keyof T & string]: (input: unknown) => Promise<unknown>;
};

export interface ClientOptions {
  /**
   * Authentication configuration. At least one of `secret` OR asymmetric
   * auth (`sign`/`verify`) MUST be configured.
   */
  auth: AuthOptions;
  /** Per-RPC-call timeout. Default: 10000ms. */
  timeout?: number;
  /** Max concurrent pending RPC calls. Default: 256. */
  maxPending?: number;
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
): { api: Client<T>; destroy: () => void } {
  if (typeof channel.send !== "function") {
    throw new TypeError("client() channel.send must be a function");
  }
  if (typeof channel.receive !== "function") {
    throw new TypeError("client() channel.receive must be a function");
  }

  validateAuthConfig(opts.auth);
  const auth = opts.auth;
  const timeout = opts.timeout !== undefined ? opts.timeout : DEFAULT_TIMEOUT;
  const maxPending =
    opts.maxPending !== undefined ? opts.maxPending : MAX_PENDING;
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

  // ── State machine: idle → handshaking → ready, or closed ──
  // idle:        no session. Next RPC call triggers handshake.
  // handshaking: hello sent, waiting for server reply.
  //              All RPC calls await the same handshakePromise.
  // ready:       session key established. RPC calls go through.
  // closed:      destroyed. All calls throw.
  //
  // RETRY: On handshake failure, state → idle. Next call retries.
  // AUTO-RESET: On RPC timeout or send error while ready, zeros crypto
  //   and goes idle. Pending calls keep their timers — they retry
  //   individually when they time out. Epoch prevents redundant resets.
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

  // Pending RPC responses
  const pending = new Map<
    string,
    {
      resolve: (v: unknown) => void;
      reject: (e: unknown) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  let counter = 0;

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
        if (state !== "handshaking" || epoch !== currentEpoch) return;
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
      } catch (err: unknown) {
        if (state !== "handshaking" || epoch !== currentEpoch) return;
        failHandshake(err);
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
            // while verify was awaiting (e.g. user destroy()).
            if (state !== "handshaking" || epoch !== currentEpoch) return;
          }

          rawShared = x25519.getSharedSecret(priv, serverPub);
          zero(priv);

          const secretBytes =
            auth.secret !== undefined ? await auth.secret() : EMPTY_SECRET;
          if (state !== "handshaking" || epoch !== currentEpoch) return;

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
          if (state !== "handshaking" || epoch !== currentEpoch) return;

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
        if (state === "closed" || epoch !== currentEpoch) return;
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
        if (typeof rawId !== "string") return;

        const entry = pending.get(rawId);
        if (entry === undefined) return;

        pending.delete(rawId);
        clearTimeout(entry.timer);

        if (msg["ok"] === true) {
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

  // ── Send a single RPC request, returns promise for the response ──

  function sendRequest(prop: string, input: unknown): Promise<unknown> {
    const enc = encrypt;
    if (state === "closed" || enc === null) {
      return Promise.reject(new RPCError("SESSION", "Session destroyed"));
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
    const encrypted = enc({ t: 1, id, p: prop, i: input });

    return new Promise(function rpcExec(res, rej) {
      const timer = setTimeout(function onRpcTimeout() {
        pending.delete(id);
        rej(new RPCError("TIMEOUT", "Timed out: " + prop));
      }, timeout);

      pending.set(id, { resolve: res, reject: rej, timer });

      Promise.resolve(channel.send(encrypted)).catch(function onSendError(err) {
        pending.delete(id);
        clearTimeout(timer);
        rej(err);
      });
    });
  }

  // ── API proxy ─────────────────────────────────────────────

  const api = new Proxy(Object.create(null) as Client<T>, {
    get(_target, prop) {
      if (typeof prop !== "string") return undefined;
      if (prop === "then") return undefined;

      return async function call(input: unknown): Promise<unknown> {
        if (state === "closed") {
          throw new RPCError("SESSION", "Session destroyed");
        }

        await ensureHandshake();

        if (knownProcedures.size < MAX_KNOWN_PROCEDURES) {
          knownProcedures.add(prop);
        }

        // Capture epoch before sending — used to detect stale failures.
        const sentEpoch = epoch;

        try {
          return await sendRequest(prop, input);
        } catch (err: unknown) {
          // If session was ready and the call failed (timeout, send error),
          // the server likely died. Auto-reset and retry ONCE with a fresh
          // handshake — transparent to the caller.
          if ((state as any) === "closed") throw err; // @TODO: Invistigae error
          // Don't retry RemoteRPCError — the server responded, session is fine
          if (err instanceof RemoteRPCError) throw err;

          // Only reset if still in the same session. If epoch moved on,
          // another call already reset — just ride the new handshake.
          if (epoch === sentEpoch) {
            reset();
          }
          await ensureHandshake();
          return sendRequest(prop, input);
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
  // Called when a call's sendRequest fails (timeout or send error).
  // Only zeros crypto and returns to idle — pending calls are left
  // untouched. They'll time out naturally and retry individually
  // through the same catch → epoch-check → ensureHandshake path.
  // If another call already reset (epoch advanced), latecomers skip
  // this and just join the in-progress handshake.

  function reset(): void {
    if (state !== "ready") return;
    zeroKeys();
    state = "idle";
  }

  // ── Destroy ───────────────────────────────────────────────

  function destroy(): void {
    if (state === "closed") return;
    const wasHandshaking = state === "handshaking";
    state = "closed";
    clearHsTimer();
    zeroKeys();
    unsubscribe();

    if (wasHandshaking && handshakeReject !== null) {
      const rej = handshakeReject;
      handshakePromise = null;
      handshakeResolve = null;
      handshakeReject = null;
      rej(new RPCError("SESSION", "Session destroyed"));
    }

    rejectPending(new RPCError("SESSION", "Session destroyed"));
  }

  return { api, destroy };
}
