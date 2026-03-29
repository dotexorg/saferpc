/**
 * drpc/common — Shared types, crypto primitives, and chain builder
 *
 * This module contains everything shared between server and client:
 * constants, security utilities, crypto helpers, error types, the
 * Channel interface, procedure/router types, and the chain builder.
 */

import { type ZodType } from "zod";
import type { z } from "zod";
import { xsalsa20poly1305 } from "@noble/ciphers/salsa";
import { encode, decode, ExtensionCodec } from "@msgpack/msgpack";
import { concatBytes, randomBytes } from "@noble/ciphers/utils";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { hmac } from "@noble/hashes/hmac";

// Re-export crypto primitives needed by both server.ts and client.ts
export { x25519 } from "@noble/curves/ed25519";
export { concatBytes } from "@noble/ciphers/utils";

// ─── Constants ────────────────────────────────────────────

export const NONCE_LEN = 24;
export const KEY_LEN = 32;
export const TAG_HELLO = 0x00;
export const TAG_MSG = 0x01;
export const MAX_MSG_BYTES = 1_048_576;
export const MAX_HELLO_BYTES = 256;
export const HANDSHAKE_TIMEOUT = 5_000;

const MAX_DEPTH = 32;
const KDF_INFO = new TextEncoder().encode("drpc-v1");

/**
 * Empty ExtensionCodec — rejects ALL msgpack extension types including
 * the default Timestamp (-1). This prevents type confusion attacks where
 * a malicious payload uses extension types to inject Date, Map, or Set
 * objects that bypass sanitize().
 */
const SAFE_CODEC = new ExtensionCodec();

// ─── Security utilities ──────────────────────────────────

export function zero(buf: Uint8Array | ArrayBuffer): void {
  const view = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  view.fill(0);
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
  psk: Uint8Array,
): Uint8Array {
  return hkdf(sha256, rawShared, psk, KDF_INFO, KEY_LEN);
}

export function computeProof(
  sessionKey: Uint8Array,
  serverPub: Uint8Array,
  clientPub: Uint8Array,
  nonce: Uint8Array,
): Uint8Array {
  const msg = concatBytes(serverPub, clientPub, nonce);
  const result = hmac(sha256, sessionKey, msg);
  zero(msg);
  return result;
}

// ─── Encrypted message helpers ───────────────────────────

export function createEncryptor(sessionKey: Uint8Array) {
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

export function createDecryptor(sessionKey: Uint8Array) {
  return function decrypt(payload: Uint8Array): unknown {
    const nonce = payload.slice(1, 1 + NONCE_LEN);
    const ct = payload.slice(1 + NONCE_LEN);
    const cipher = xsalsa20poly1305(sessionKey, nonce);
    const encoded = cipher.decrypt(ct);
    const data = mpDecode(encoded);
    zero(nonce);
    zero(ct);
    zero(encoded);
    zero(payload);
    return sanitize(data);
  };
}

// ─── PSK validation ──────────────────────────────────────

export function validatePSK(psk: Uint8Array): void {
  if (!(psk instanceof Uint8Array)) {
    throw new TypeError("psk must be a Uint8Array");
  }
  if (psk.length < KEY_LEN) {
    throw new TypeError(`psk must be at least ${KEY_LEN} bytes`);
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
