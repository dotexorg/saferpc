/**
 * drpc/common — Shared types, crypto primitives, and chain builder
 *
 * This module contains everything shared between server and client:
 * constants, security utilities, crypto helpers, error types, the
 * Channel interface, procedure/router types, and the chain builder.
 */

import { type ZodType } from "zod";
import type { z } from "zod";
import { xsalsa20poly1305 } from "@noble/ciphers/salsa.js";
import { encode, decode, ExtensionCodec } from "@msgpack/msgpack";
import { concatBytes, randomBytes } from "@noble/ciphers/utils.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";

// Re-export crypto primitives needed by both server.ts and client.ts
export { x25519 } from "@noble/curves/ed25519.js";
export { concatBytes } from "@noble/ciphers/utils.js";

// ─── Constants ────────────────────────────────────────────

export const NONCE_LEN = 24;
export const KEY_LEN = 32;
export const TAG_HELLO = 0x00;
export const TAG_MSG = 0x01;
export const MAX_MSG_BYTES = 1_048_576;
/**
 * Hello frames carry the optional `auth` payload produced by the
 * application's authenticator (e.g. a JWT + signature). 64 KiB is
 * sized for typical credential + signature combinations; bump if
 * your authenticator embeds larger material.
 */
export const MAX_HELLO_BYTES = 65_536;
export const HANDSHAKE_TIMEOUT = 5_000;
/**
 * Hard cap on `auth` payload bytes embedded in hello / reply.
 * Independent of MAX_HELLO_BYTES because the auth payload is only
 * one component of the hello.
 */
export const MAX_AUTH_BYTES = 32_768;

/**
 * Maximum recursion depth `sanitize()` will follow. Exposed so adapter
 * authors that emit deeply-nested payloads can size their data against
 * the protocol's hard limit.
 */
export const MAX_DEPTH = 32;
const KDF_INFO = new TextEncoder().encode("saferpc-v1");

/**
 * Domain-separated transcript prefixes. The handshake transcript is the
 * canonical byte string the application's authenticator signs / verifies
 * over. Keep these tight, versioned, and never reused across domains.
 */
const TRANSCRIPT_HELLO_MAGIC = new TextEncoder().encode(
  "saferpc-hs-hello-v1\0",
);
const TRANSCRIPT_REPLY_MAGIC = new TextEncoder().encode(
  "saferpc-hs-reply-v1\0",
);

/**
 * Hardened ExtensionCodec — rejects ALL msgpack extension types including
 * the built-in Timestamp (type -1). This prevents type-confusion attacks
 * where a malicious payload uses ext types to inject Date / Map / Set /
 * other non-plain host objects that would surprise handlers.
 *
 * Implementation: msgpack-javascript hard-codes the Timestamp decoder, so
 * we explicitly register a throwing decoder for type -1 to override it.
 * Unregistered ext types bypass our codec and surface as ExtData; sanitize()
 * rejects those via its non-plain-object check.
 */
const SAFE_CODEC = new ExtensionCodec();
SAFE_CODEC.register({
  type: -1,
  encode: () => null,
  decode: () => {
    throw new RPCError("INVALID_DATA", "Timestamp extension rejected");
  },
});

// ─── Security utilities ──────────────────────────────────

export function zero(buf: Uint8Array | ArrayBuffer): void {
  const view = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  view.fill(0);
}

/** Constant-time equality for byte arrays. Independent of input contents. */
export function constTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) {
    d |= a[i]! ^ b[i]!;
  }
  return d === 0;
}

/**
 * Tight type guard for wire-decoded byte fields. `instanceof Uint8Array`
 * accepts every subclass; this guard requires the exact `Uint8Array`
 * prototype so a custom subclass with overridden methods cannot smuggle
 * behavior past the protocol layer. Inbound frames are normalized via
 * `toPlainBytes()` at the channel boundary so msgpack-decoded `bin`
 * fields are always plain Uint8Arrays by the time they reach this guard.
 * Use on values that originated on the wire.
 */
export function isPlainBytes(v: unknown): v is Uint8Array {
  return (
    v instanceof Uint8Array && Object.getPrototypeOf(v) === Uint8Array.prototype
  );
}

/**
 * Normalize an inbound buffer to a plain `Uint8Array`. Node's `Buffer`
 * extends `Uint8Array` and its `subarray()` returns another `Buffer`;
 * msgpack's `bin` decoder propagates that subclass into decoded fields,
 * which would defeat `isPlainBytes()`. Wrapping at the boundary creates
 * a plain `Uint8Array` view (zero byte copy) so all internal code can
 * trust that `bin` values have the canonical prototype.
 */
export function toPlainBytes(v: Uint8Array): Uint8Array {
  if (Object.getPrototypeOf(v) === Uint8Array.prototype) return v;
  return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
}

/**
 * Constant-time check that a buffer is the protocol's "no secret" sentinel:
 * 32 zero bytes. Returns false for any other length. Safe RPC's internal flow
 * uses `EMPTY_SECRET` as the HKDF salt when `auth.secret` is absent — but if a
 * user-provided `secret()` returns 32 zeros (e.g. `new Uint8Array(32)`), the
 * resulting session has no secret authentication. Refuse it at runtime.
 */
export function isEmptySecret(buf: Uint8Array): boolean {
  if (buf.length !== KEY_LEN) return false;
  let acc = 0;
  for (let i = 0; i < buf.length; i++) acc |= buf[i]!;
  return acc === 0;
}

const POISON = new Set(["__proto__", "constructor", "prototype"]);

export function sanitize(v: unknown, depth: number = 0): unknown {
  if (depth > MAX_DEPTH) {
    throw new RPCError("INVALID_DATA", "Max nesting depth exceeded");
  }
  if (v === null || v === undefined) return v;
  if (typeof v !== "object") return v;
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v)) {
    const out: unknown[] = [];
    for (let i = 0; i < v.length; i++) {
      out[i] = sanitize(v[i], depth + 1);
    }
    return out;
  }
  // Reject non-plain objects (Date, Map, Set, ExtData, etc.). Any object
  // whose prototype is neither Object.prototype nor null is suspicious —
  // it likely came in via a msgpack ext type or a JS host object that
  // could surprise downstream handlers.
  const proto = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) {
    throw new RPCError("INVALID_DATA", "Non-plain object rejected");
  }
  const out: Record<string, unknown> = Object.create(null);
  const keys = Object.keys(v as Record<string, unknown>);
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i]!;
    if (POISON.has(k)) continue;
    out[k] = sanitize((v as Record<string, unknown>)[k], depth + 1);
  }
  return out;
}

// ─── Safe msgpack wrappers ──────────────────────────────

export function mpEncode(data: unknown): Uint8Array {
  return encode(data, { extensionCodec: SAFE_CODEC, useBigInt64: true });
}

export function mpDecode(buf: Uint8Array): unknown {
  return decode(buf, { extensionCodec: SAFE_CODEC, useBigInt64: true });
}

// ─── Key derivation ──────────────────────────────────────

export function deriveSessionKey(
  rawShared: Uint8Array,
  secret: Uint8Array,
): Uint8Array {
  return hkdf(sha256, rawShared, secret, KDF_INFO, KEY_LEN);
}

export function computeProof(
  sessionKey: Uint8Array,
  serverPub: Uint8Array,
  clientPub: Uint8Array,
  nonce: Uint8Array,
): Uint8Array {
  // The concatenated buffer contains only public values; nothing to zero.
  const msg = concatBytes(serverPub, clientPub, nonce);
  return hmac(sha256, sessionKey, msg);
}

/**
 * Derive a session-bound secret from a session identifier and secret using HKDF.
 * This provides better security than static secrets by binding each session
 * to a specific session token/identifier.
 *
 * @param sessionId Session identifier (e.g., JWT, session token)
 * @param secret Secret key material (device secret, server secret, etc.)
 * @returns 32-byte derived secret
 */
export function deriveSessionSecret(
  sessionId: string,
  secret: Uint8Array,
): Uint8Array {
  if (typeof sessionId !== "string" || sessionId.length === 0) {
    throw new TypeError("sessionId must be a non-empty string");
  }
  if (!(secret instanceof Uint8Array) || secret.length < KEY_LEN) {
    throw new TypeError(`secret must be at least ${KEY_LEN} bytes`);
  }
  const sessionBytes = new TextEncoder().encode(sessionId);
  const info = new TextEncoder().encode("saferpc-session-v1");
  return hkdf(sha256, secret, sessionBytes, info, KEY_LEN);
}

// ─── Encrypted message helpers ───────────────────────────

export function createEncryptor(
  sessionKey: Uint8Array,
): (data: unknown) => Uint8Array {
  return function encrypt(data: unknown): Uint8Array {
    const nonce = randomBytes(NONCE_LEN);
    const encoded = mpEncode(data);
    const cipher = xsalsa20poly1305(sessionKey, nonce);
    const ct = cipher.encrypt(encoded);
    const payload = concatBytes(new Uint8Array([TAG_MSG]), nonce, ct);
    zero(nonce);
    zero(encoded);
    zero(ct);
    return payload;
  };
}

export function createDecryptor(
  sessionKey: Uint8Array,
): (payload: Uint8Array) => unknown {
  return function decrypt(payload: Uint8Array): unknown {
    const nonce = payload.slice(1, 1 + NONCE_LEN);
    const ct = payload.slice(1 + NONCE_LEN);
    const cipher = xsalsa20poly1305(sessionKey, nonce);
    const encoded = cipher.decrypt(ct);
    const data = mpDecode(encoded);
    // NOTE: msgpack-javascript v3 returns Uint8Array (bin) fields as
    // zero-copy views into `encoded`. Zeroing `encoded` or `payload` here
    // would clobber any binary field on the returned object. The plaintext
    // remains in the caller's hands; callers that need stricter memory
    // hygiene should sanitize and zero their own buffers after use.
    zero(nonce);
    zero(ct);
    return sanitize(data);
  };
}

// ─── Handshake transcript ────────────────────────────────
//
// The transcript is the canonical byte string the application's
// auth signs (via `auth.sign`) and verifies (via `auth.verify`).
//
// Two transcripts:
//   HELLO  — what the client commits to before knowing the server's pub
//   REPLY  — what the server commits to after seeing the client's hello
//
// Both bind the per-handshake `epoch`, the client's ephemeral pub and
// nonce. The REPLY transcript additionally binds the server's
// ephemeral pub, so a server-side signature locks both sides of the
// ECDH exchange. An active MITM cannot substitute either ephemeral
// public key without invalidating the corresponding signature.

function encodeEpoch(epoch: number): Uint8Array {
  // 4-byte big-endian unsigned. Epochs increment per handshake attempt
  // and are short-lived; 32-bit is sufficient.
  if (
    typeof epoch !== "number" ||
    !Number.isInteger(epoch) ||
    epoch < 0 ||
    epoch > 0xffffffff
  ) {
    throw new RPCError("INVALID_DATA", "Invalid epoch");
  }
  const out = new Uint8Array(4);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, epoch, false);
  return out;
}

export function buildHelloTranscript(
  epoch: number,
  clientPub: Uint8Array,
  clientNonce: Uint8Array,
): Uint8Array {
  if (!(clientPub instanceof Uint8Array) || clientPub.length !== KEY_LEN) {
    throw new RPCError("INVALID_DATA", "Invalid clientPub for transcript");
  }
  if (!(clientNonce instanceof Uint8Array) || clientNonce.length !== KEY_LEN) {
    throw new RPCError("INVALID_DATA", "Invalid clientNonce for transcript");
  }
  return concatBytes(
    TRANSCRIPT_HELLO_MAGIC,
    encodeEpoch(epoch),
    clientPub,
    clientNonce,
  );
}

export function buildReplyTranscript(
  epoch: number,
  clientPub: Uint8Array,
  clientNonce: Uint8Array,
  serverPub: Uint8Array,
): Uint8Array {
  if (!(clientPub instanceof Uint8Array) || clientPub.length !== KEY_LEN) {
    throw new RPCError("INVALID_DATA", "Invalid clientPub for transcript");
  }
  if (!(clientNonce instanceof Uint8Array) || clientNonce.length !== KEY_LEN) {
    throw new RPCError("INVALID_DATA", "Invalid clientNonce for transcript");
  }
  if (!(serverPub instanceof Uint8Array) || serverPub.length !== KEY_LEN) {
    throw new RPCError("INVALID_DATA", "Invalid serverPub for transcript");
  }
  return concatBytes(
    TRANSCRIPT_REPLY_MAGIC,
    encodeEpoch(epoch),
    clientPub,
    clientNonce,
    serverPub,
  );
}

// ─── Auth config validation ──────────────────────────────

/**
 * Empty salt used in HKDF when no secret is configured. HKDF with an
 * all-zero salt is well-defined per RFC 5869 and provides no
 * authentication on its own — pair with `sign`/`verify` to get
 * a usable session.
 */
export const EMPTY_SECRET: Uint8Array = new Uint8Array(KEY_LEN);

/**
 * Validate the auth configuration. At least one of:
 *
 *   - `secret` function is configured, OR
 *   - asymmetric auth (`sign` or `verify`) is configured, OR
 *   - BOTH are configured (defense-in-depth)
 *
 * Configuring NEITHER is a hard error: the resulting handshake would
 * be unauthenticated and any active MITM on the transport could
 * impersonate either peer.
 */
export function validateAuthConfig(auth: AuthOptions): void {
  if (typeof auth !== "object" || auth === null) {
    throw new TypeError("auth must be an object");
  }

  const hasSecret = typeof auth.secret === "function";
  const hasSign = typeof auth.sign === "function";
  const hasVerify = typeof auth.verify === "function";
  const hasAsymmetric = hasSign || hasVerify;

  if (!hasSecret && !hasAsymmetric) {
    throw new TypeError(
      "At least one of `auth.secret` or asymmetric auth (`auth.sign`/`auth.verify`) must be configured. " +
        "A Safe RPC handshake with neither would be unauthenticated.",
    );
  }
}

// ─── Error ────────────────────────────────────────────────

export class RPCError extends Error {
  public readonly code: string;
  public readonly data: unknown;

  constructor(code: string, message: string, data?: unknown) {
    if (typeof code !== "string" || code.length === 0) {
      throw new TypeError("RPCError: code must be a non-empty string");
    }
    if (typeof message !== "string") {
      throw new TypeError("RPCError: message must be a string");
    }
    super(message);
    this.code = code;
    this.data = data !== undefined ? data : null;
  }
}

// ─── Types ───────────────────────────────────────────────

export type Ctx = Record<string, unknown>;

export type MwFn = (opts: {
  ctx: Ctx;
  input: unknown;
  next: (extra?: Ctx) => Promise<unknown>;
}) => Promise<unknown>;

export type Step =
  | { t: "m"; fn: MwFn }
  | { t: "i"; schema: ZodType }
  | { t: "o"; schema: ZodType };

export type HandlerFn = (opts: {
  ctx: Ctx;
  input: unknown;
}) => Promise<unknown>;

export interface Procedure {
  readonly _steps: ReadonlyArray<Step>;
  readonly _handler: HandlerFn;
}

export type Router = Record<string, Procedure>;

export interface Channel {
  send(data: Uint8Array): void | Promise<void>;
  receive(cb: (data: Uint8Array) => void): () => void;
}

// ─── Authentication (secret + asymmetric handshake authentication) ─

/**
 * Result of `AuthOptions.verify` on the server side. The optional
 * `auth` is merged into RPC handler context for the lifetime of
 * the session that handshake established.
 *
 * On the client side the return value is unused (success ↔ no throw).
 */
export type VerifyResult = { auth?: Ctx } | void;

/**
 * Authentication configuration for Safe RPC. At least one of `secret` OR
 * asymmetric auth (`sign`/`verify`) MUST be configured.
 *
 * Three modes:
 * 1. Secret-only: { secret: () => secret }
 * 2. Asymmetric-only: { sign: ..., verify?: ... }
 * 3. Both (defense-in-depth): { secret: () => secret, sign: ..., verify?: ... }
 */
export interface AuthOptions {
  /**
   * Pre-shared secret function. Returns secret bytes mixed into session key
   * derivation. Called once per handshake attempt.
   *
   * Use session-derived secrets for better security:
   * ```typescript
   * secret: () => deriveSessionSecret(sessionToken, deviceSecret)
   * ```
   *
   * Minimum 32 bytes when returned.
   */
  secret?: () => Uint8Array | Promise<Uint8Array>;

  /**
   * Create proof of identity over handshake transcript. The returned
   * payload is embedded in hello (client) or reply (server).
   *
   * Typically a signature over the transcript with a private key.
   *
   * Called once per handshake attempt.
   */
  sign?: (transcript: Uint8Array) => Uint8Array | Promise<Uint8Array>;

  /**
   * Verify counterparty's proof of identity. Throw to reject the
   * handshake; return/resolve to accept.
   *
   * If configured, the counterparty MUST provide a proof (else
   * handshake fails). If omitted, any counterparty proof is ignored.
   *
   * On the server side, `auth` (if returned) is merged into
   * RPC handler context for the session.
   *
   * Called once per handshake attempt.
   */
  verify?: (
    proof: Uint8Array,
    transcript: Uint8Array,
  ) => VerifyResult | Promise<VerifyResult>;
}

// ─── Chain builder ────────────────────────────────────────

export interface Chain<TCtx extends Ctx = {}, TIn = unknown, TOut = unknown> {
  use<E extends Ctx = {}>(
    fn: (opts: {
      ctx: TCtx;
      input: TIn;
      next: (extra?: E) => Promise<unknown>;
    }) => Promise<unknown>,
  ): Chain<TCtx & E, TIn, TOut>;

  input<T extends ZodType>(schema: T): Chain<TCtx, z.output<T>, TOut>;
  output<T extends ZodType>(schema: T): Chain<TCtx, TIn, z.output<T>>;

  handler(fn: (opts: { ctx: TCtx; input: TIn }) => Promise<TOut>): Procedure;
}

export function chain(steps: Step[] = []): Chain {
  return {
    use(fn: MwFn): Chain {
      if (typeof fn !== "function") {
        throw new TypeError("use() requires a function");
      }
      return chain([...steps, { t: "m", fn }]);
    },
    input(schema: ZodType): Chain {
      if (
        schema === null ||
        schema === undefined ||
        typeof schema.safeParse !== "function"
      ) {
        throw new TypeError("input() requires a Zod schema");
      }
      return chain([...steps, { t: "i", schema }]);
    },
    output(schema: ZodType): Chain {
      if (
        schema === null ||
        schema === undefined ||
        typeof schema.safeParse !== "function"
      ) {
        throw new TypeError("output() requires a Zod schema");
      }
      return chain([...steps, { t: "o", schema }]);
    },
    handler(fn: HandlerFn): Procedure {
      if (typeof fn !== "function") {
        throw new TypeError("handler() requires a function");
      }
      return Object.freeze({
        _steps: Object.freeze([...steps]),
        _handler: fn,
      });
    },
  } as Chain;
}
