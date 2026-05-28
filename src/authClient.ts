/**
 * Client-side authentication helpers.
 *
 * Each helper returns a Partial<AuthOptions> containing a `sign` function.
 * Spread it into your `auth` block. All helpers bind their proof payload
 * to the handshake transcript provided by Safe RPC (signature input or, for
 * bearer-token modes, an embedded transcript digest verified by the peer).
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { mpEncode, RPCError, type AuthOptions } from "./common.ts";

// ─── JWT bearer (transcript-bound) ──────────────────────────────────

export interface JWTClientConfig {
  /** Returns the current JWT, or null/undefined if the user is not signed in. */
  getToken: () =>
    | string
    | null
    | undefined
    | Promise<string | null | undefined>;
}

/**
 * Bearer-token client auth. The JWT is sent alongside a SHA-256 digest of the
 * canonical handshake transcript. The server validates both: the JWT proves
 * identity, the digest binds the token to this specific handshake so a
 * captured frame cannot be replayed into a new handshake (e.g. with an
 * attacker-controlled ephemeral key) within the token's lifetime.
 *
 * JWTs remain bearer tokens — anyone who steals one can impersonate the
 * principal until expiry. Pair with a secret or a real signature mode when you
 * need stronger guarantees.
 */
export function createJWTClientAuth(
  config: JWTClientConfig,
): Pick<AuthOptions, "sign"> {
  return {
    sign: async (transcript) => {
      const token = await config.getToken();
      if (typeof token !== "string" || token.length === 0) {
        throw new RPCError("UNAUTHORIZED", "No JWT token available");
      }
      return mpEncode({
        v: 1,
        jwt: token,
        ts: Date.now(),
        th: sha256(transcript),
      });
    },
  };
}

// ─── Ed25519 device signature ───────────────────────────────────────

export interface Ed25519ClientConfig {
  /** 32-byte Ed25519 secret key (seed). */
  privateKey: Uint8Array;
  /** Identifier the server uses to look up the matching public key. */
  deviceId: string;
}

/**
 * Client signs the canonical handshake transcript with an Ed25519 key.
 * Uses @noble/curves (pure JS) for cross-runtime portability — WebCrypto's
 * raw Ed25519 import is not supported uniformly across browsers.
 */
export function createEd25519ClientAuth(
  config: Ed25519ClientConfig,
): Pick<AuthOptions, "sign"> {
  if (
    !(config.privateKey instanceof Uint8Array) ||
    config.privateKey.length !== 32
  ) {
    throw new TypeError("Ed25519 privateKey must be 32 bytes");
  }
  if (typeof config.deviceId !== "string" || config.deviceId.length === 0) {
    throw new TypeError("Ed25519 deviceId must be a non-empty string");
  }
  return {
    sign: async (transcript) => {
      const signature = ed25519.sign(transcript, config.privateKey);
      return mpEncode({
        v: 1,
        deviceId: config.deviceId,
        sig: signature,
      });
    },
  };
}

// ─── ECDSA P-256 (WebCrypto) ────────────────────────────────────────

export interface ECDSAClientConfig {
  /** WebCrypto ECDSA P-256 private key with `sign` usage. */
  privateKey: CryptoKey;
  /** Identifier the server uses to look up the matching public key. */
  identifier: string;
}

/**
 * Client signs the handshake transcript with ECDSA P-256 (SHA-256) via WebCrypto.
 * Use this when device keys must be non-extractable (`generateKey({ extractable: false })`).
 */
export function createECDSAClientAuth(
  config: ECDSAClientConfig,
): Pick<AuthOptions, "sign"> {
  if (typeof config.identifier !== "string" || config.identifier.length === 0) {
    throw new TypeError("ECDSA identifier must be a non-empty string");
  }
  return {
    sign: async (transcript) => {
      if (typeof crypto === "undefined" || !crypto.subtle) {
        throw new RPCError("INTERNAL", "WebCrypto not available");
      }
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        config.privateKey,
        transcript as BufferSource,
      );
      return mpEncode({
        v: 1,
        identifier: config.identifier,
        sig: new Uint8Array(signature),
      });
    },
  };
}

// ─── Keypair generators ─────────────────────────────────────────────

/**
 * Generate a fresh Ed25519 keypair using @noble/curves. Works in every JS
 * runtime — no WebCrypto required.
 */
export async function generateEd25519Keypair(): Promise<{
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}> {
  const privateKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Generate a fresh non-extractable ECDSA P-256 keypair via WebCrypto.
 * The private key is bound to the running context and cannot be exported.
 */
export async function generateECDSAKeypair(): Promise<{
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}> {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new RPCError("INTERNAL", "WebCrypto not available");
  }
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );
  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}
