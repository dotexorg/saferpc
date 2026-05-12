/**
 * Server-side authentication helpers.
 *
 * All decoders use the hardened msgpack codec (`mpDecode`) so that auth
 * payloads cannot smuggle ext types, prototype-polluting keys, or oversized
 * arrays. Every helper performs strict type validation on the decoded
 * fields and binds verification to the canonical handshake transcript that
 * eRPC passes in.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";

import {
  constTimeEqual,
  isPlainBytes,
  mpDecode,
  RPCError,
  type AuthOptions,
  type Ctx,
} from "./common.ts";

// ─── Decode helpers ─────────────────────────────────────────────────

function decodeAuthPayload(proof: Uint8Array): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = mpDecode(proof);
  } catch {
    throw new RPCError("UNAUTHORIZED", "Malformed auth payload");
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new RPCError("UNAUTHORIZED", "Malformed auth payload");
  }
  return parsed as Record<string, unknown>;
}

// ─── JWT bearer (transcript-bound) ──────────────────────────────────

export interface JWTServerConfig {
  /**
   * Verify a JWT and return its decoded payload. Throw or return a falsy
   * value to reject the token. Returned object becomes the verified
   * principal — sanitized by eRPC before reaching `context`.
   */
  verifyToken: (
    token: string,
  ) =>
    | Record<string, unknown>
    | null
    | undefined
    | Promise<Record<string, unknown> | null | undefined>;
  /**
   * Max clock skew (ms) for the embedded timestamp. Defaults to 30_000.
   * Set tighter if your clocks are well-synchronized.
   */
  maxAge?: number;
}

export function createJWTServerAuth(
  config: JWTServerConfig,
): Pick<AuthOptions, "verify"> {
  const maxAge = config.maxAge ?? 30_000;
  return {
    verify: async (proof, transcript) => {
      const payload = decodeAuthPayload(proof);
      const jwt = payload["jwt"];
      const ts = payload["ts"];
      const th = payload["th"];

      if (typeof jwt !== "string" || jwt.length === 0) {
        throw new RPCError("UNAUTHORIZED", "Missing JWT");
      }
      if (typeof ts !== "number" || !Number.isFinite(ts)) {
        throw new RPCError("UNAUTHORIZED", "Invalid timestamp");
      }
      if (!isPlainBytes(th) || th.length !== 32) {
        throw new RPCError("UNAUTHORIZED", "Invalid transcript binding");
      }

      // Symmetric clock-skew check — guards against past replays AND
      // future-dated forgeries (the latter would otherwise yield a
      // negative diff that trivially passes a one-sided `>` check).
      if (Math.abs(Date.now() - ts) > maxAge) {
        throw new RPCError("UNAUTHORIZED", "Stale or future-dated auth");
      }

      // Constant-time binding check. Defeats replay of a captured hello
      // into a fresh handshake (different transcript ⇒ different digest).
      if (!constTimeEqual(th, sha256(transcript))) {
        throw new RPCError("UNAUTHORIZED", "Transcript binding mismatch");
      }

      const verified = await config.verifyToken(jwt);
      if (!verified || typeof verified !== "object") {
        throw new RPCError("UNAUTHORIZED", "Invalid JWT");
      }

      return { auth: verified as Ctx };
    },
  };
}

// ─── Ed25519 device signature ───────────────────────────────────────

export interface Ed25519ServerConfig {
  /** Resolve a device's 32-byte Ed25519 public key by deviceId. */
  getPublicKey: (deviceId: string) => Uint8Array | Promise<Uint8Array>;
  /** Optional gate before signature verification (revocation, allow-listing). */
  validateDevice?: (deviceId: string) => boolean | Promise<boolean>;
}

export function createEd25519ServerAuth(
  config: Ed25519ServerConfig,
): Pick<AuthOptions, "verify"> {
  return {
    verify: async (proof, transcript) => {
      const payload = decodeAuthPayload(proof);
      const deviceId = payload["deviceId"];
      const sig = payload["sig"];

      if (typeof deviceId !== "string" || deviceId.length === 0) {
        throw new RPCError("UNAUTHORIZED", "Missing deviceId");
      }
      if (!isPlainBytes(sig) || sig.length !== 64) {
        throw new RPCError("UNAUTHORIZED", "Invalid Ed25519 signature");
      }
      if (config.validateDevice && !(await config.validateDevice(deviceId))) {
        throw new RPCError("UNAUTHORIZED", "Unknown device");
      }

      const publicKey = await config.getPublicKey(deviceId);
      if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
        throw new RPCError("INTERNAL", "Resolved public key is invalid");
      }

      const ok = ed25519.verify(sig, transcript, publicKey);
      if (!ok) {
        throw new RPCError("UNAUTHORIZED", "Invalid device signature");
      }

      return { auth: { deviceId, verified: true } };
    },
  };
}

// ─── ECDSA P-256 (WebCrypto) ────────────────────────────────────────

export interface ECDSAServerConfig {
  /** Resolve an ECDSA P-256 public CryptoKey by identifier. */
  getPublicKey: (identifier: string) => CryptoKey | Promise<CryptoKey>;
  /** Optional gate before signature verification. */
  validateEntity?: (identifier: string) => boolean | Promise<boolean>;
}

export function createECDSAServerAuth(
  config: ECDSAServerConfig,
): Pick<AuthOptions, "verify"> {
  return {
    verify: async (proof, transcript) => {
      const payload = decodeAuthPayload(proof);
      const identifier = payload["identifier"];
      const sig = payload["sig"];

      if (typeof identifier !== "string" || identifier.length === 0) {
        throw new RPCError("UNAUTHORIZED", "Missing identifier");
      }
      if (!isPlainBytes(sig) || sig.length === 0) {
        throw new RPCError("UNAUTHORIZED", "Invalid ECDSA signature");
      }
      if (config.validateEntity && !(await config.validateEntity(identifier))) {
        throw new RPCError("UNAUTHORIZED", "Unknown entity");
      }
      if (typeof crypto === "undefined" || !crypto.subtle) {
        throw new RPCError("INTERNAL", "WebCrypto not available");
      }

      const publicKey = await config.getPublicKey(identifier);
      const ok = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        publicKey,
        sig as BufferSource,
        transcript as BufferSource,
      );
      if (!ok) {
        throw new RPCError("UNAUTHORIZED", "Invalid ECDSA signature");
      }

      return { auth: { identifier, verified: true } };
    },
  };
}

// ─── Certificate-based authentication ──────────────────────────────

export interface CertificateServerConfig {
  /** Verify cert chain, return the bound public key + subject metadata. */
  verifyCertificate: (
    certBytes: Uint8Array,
  ) => Promise<{ subject: Record<string, string>; publicKey: CryptoKey }>;
  /** Optional subject allow-list / policy check. */
  validateSubject?: (
    subject: Record<string, string>,
  ) => boolean | Promise<boolean>;
}

export function createCertificateServerAuth(
  config: CertificateServerConfig,
): Pick<AuthOptions, "verify"> {
  return {
    verify: async (proof, transcript) => {
      const payload = decodeAuthPayload(proof);
      const cert = payload["cert"];
      const sig = payload["sig"];

      if (!isPlainBytes(cert) || cert.length === 0) {
        throw new RPCError("UNAUTHORIZED", "Missing certificate");
      }
      if (!isPlainBytes(sig) || sig.length === 0) {
        throw new RPCError("UNAUTHORIZED", "Missing certificate signature");
      }
      if (typeof crypto === "undefined" || !crypto.subtle) {
        throw new RPCError("INTERNAL", "WebCrypto not available");
      }

      const { subject, publicKey } = await config.verifyCertificate(cert);
      if (config.validateSubject && !(await config.validateSubject(subject))) {
        throw new RPCError("UNAUTHORIZED", "Invalid certificate subject");
      }

      const ok = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        publicKey,
        sig as BufferSource,
        transcript as BufferSource,
      );
      if (!ok) {
        throw new RPCError("UNAUTHORIZED", "Invalid certificate signature");
      }

      return { auth: { subject, verified: true } };
    },
  };
}

// ─── Multifactor (compose two verifiers) ───────────────────────────

export interface MultifactorServerConfig {
  primary: Pick<AuthOptions, "verify">;
  secondary: Pick<AuthOptions, "verify">;
  /** Combine the two verified principals. Default: shallow merge with `multifactor: true`. */
  combineAuth?: (primary: Ctx | undefined, secondary: Ctx | undefined) => Ctx;
}

export function createMultifactorServerAuth(
  config: MultifactorServerConfig,
): Pick<AuthOptions, "verify"> {
  if (typeof config.primary?.verify !== "function") {
    throw new TypeError("primary.verify must be a function");
  }
  if (typeof config.secondary?.verify !== "function") {
    throw new TypeError("secondary.verify must be a function");
  }
  return {
    verify: async (proof, transcript) => {
      const payload = decodeAuthPayload(proof);
      const primary = payload["primary"];
      const secondary = payload["secondary"];

      if (!isPlainBytes(primary) || primary.length === 0) {
        throw new RPCError("UNAUTHORIZED", "Missing primary factor");
      }
      if (!isPlainBytes(secondary) || secondary.length === 0) {
        throw new RPCError("UNAUTHORIZED", "Missing secondary factor");
      }

      const primaryRes = await config.primary.verify!(primary, transcript);
      const secondaryRes = await config.secondary.verify!(
        secondary,
        transcript,
      );

      const primaryAuth =
        primaryRes && typeof primaryRes === "object"
          ? ((primaryRes as { auth?: Ctx }).auth ?? undefined)
          : undefined;
      const secondaryAuth =
        secondaryRes && typeof secondaryRes === "object"
          ? ((secondaryRes as { auth?: Ctx }).auth ?? undefined)
          : undefined;

      const combined = config.combineAuth
        ? config.combineAuth(primaryAuth, secondaryAuth)
        : {
            ...(primaryAuth ?? {}),
            ...(secondaryAuth ?? {}),
            multifactor: true,
          };

      return { auth: combined };
    },
  };
}
