/**
 * Server-side authentication helpers
 */

import { decode } from "@msgpack/msgpack";
import { RPCError, type AuthOptions } from "./common.ts";

// ─── JWT Server Authentication Helper ───────────────────────────────

export interface JWTServerConfig {
  /** Verify JWT and return payload */
  verifyToken: (token: string) => any | Promise<any>;
  /** Optional: max age for timestamp check (default: 30 seconds) */
  maxAge?: number;
}

/**
 * Create server-side JWT verification for eRPC.
 */
export function createJWTServerAuth(config: JWTServerConfig): Pick<AuthOptions, 'verify'> {
  const maxAge = config.maxAge ?? 30000; // 30 seconds default
  
  return {
    verify: async (proof, _transcript) => {
      const { jwt, timestamp } = JSON.parse(
        new TextDecoder().decode(proof)
      );
      
      // Optional: Check timestamp to prevent replay
      if (Date.now() - timestamp > maxAge) {
        throw new RPCError("UNAUTHORIZED", "Stale authentication");
      }
      
      const payload = await config.verifyToken(jwt);
      if (!payload) {
        throw new RPCError("UNAUTHORIZED", "Invalid JWT");
      }
      
      return { 
        auth: { 
          userId: payload.sub,
          sessionId: payload.jti,
          permissions: payload.permissions || [],
          issuedAt: payload.iat
        }
      };
    }
  };
}

// ─── Ed25519 Server Authentication Helper ───────────────────────────────

export interface Ed25519ServerConfig {
  /** Function to get public key for a device ID */
  getPublicKey: (deviceId: string) => Uint8Array | Promise<Uint8Array>;
  /** Optional: additional device validation */
  validateDevice?: (deviceId: string) => boolean | Promise<boolean>;
}

/**
 * Create server-side Ed25519 device verification for eRPC.
 */
export function createEd25519ServerAuth(config: Ed25519ServerConfig): Pick<AuthOptions, 'verify'> {
  return {
    verify: async (proof, transcript) => {
      const { deviceId, signature } = decode(proof) as {
        deviceId: string;
        signature: number[];
      };
      
      if (!deviceId || !signature) {
        throw new RPCError("UNAUTHORIZED", "Invalid device proof");
      }
      
      // Optional device validation
      if (config.validateDevice && !(await config.validateDevice(deviceId))) {
        throw new RPCError("UNAUTHORIZED", "Unknown device");
      }
      
      // Get public key for device
      const publicKeyBytes = await config.getPublicKey(deviceId);
      
      // Use WebCrypto if available, otherwise throw
      if (typeof crypto === "undefined" || !crypto.subtle) {
        throw new RPCError("INTERNAL", "WebCrypto not available");
      }
      
      // Import public key
      const publicKey = await crypto.subtle.importKey(
        "raw",
        publicKeyBytes.buffer as ArrayBuffer,
        { name: "Ed25519" },
        false,
        ["verify"]
      );
      
      // Verify signature
      const isValid = await crypto.subtle.verify(
        "Ed25519",
        publicKey,
        new Uint8Array(signature).buffer as ArrayBuffer,
        transcript.buffer as ArrayBuffer
      );
      
      if (!isValid) {
        throw new RPCError("UNAUTHORIZED", "Invalid device signature");
      }
      
      return { 
        auth: { 
          deviceId, 
          verified: true 
        }
      };
    }
  };
}

// ─── ECDSA P-256 Server Authentication Helper ────────────────────────────────

export interface ECDSAServerConfig {
  /** Function to get public key for verification */
  getPublicKey: (identifier: string) => CryptoKey | Promise<CryptoKey>;
  /** Optional: additional entity validation */
  validateEntity?: (identifier: string) => boolean | Promise<boolean>;
}

/**
 * Create server-side ECDSA P-256 verification for eRPC using WebCrypto.
 */
export function createECDSAServerAuth(config: ECDSAServerConfig): Pick<AuthOptions, 'verify'> {
  return {
    verify: async (proof, transcript) => {
      const { identifier, signature } = decode(proof) as {
        identifier: string;
        signature: number[];
      };
      
      if (!identifier || !signature) {
        throw new RPCError("UNAUTHORIZED", "Invalid ECDSA proof");
      }
      
      // Optional entity validation
      if (config.validateEntity && !(await config.validateEntity(identifier))) {
        throw new RPCError("UNAUTHORIZED", "Unknown entity");
      }
      
      const publicKey = await config.getPublicKey(identifier);
      
      const isValid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        publicKey,
        new Uint8Array(signature).buffer as ArrayBuffer,
        transcript.buffer as ArrayBuffer
      );
      
      if (!isValid) {
        throw new RPCError("UNAUTHORIZED", "Invalid ECDSA signature");
      }
      
      return { 
        auth: { 
          identifier, 
          verified: true 
        }
      };
    }
  };
}

// ─── Certificate-based Authentication Helper ──────────────────────────────

export interface CertificateServerConfig {
  /** Verify certificate chain and extract subject */
  verifyCertificate: (certBytes: Uint8Array) => Promise<{
    subject: Record<string, string>;
    publicKey: CryptoKey;
  }>;
  /** Optional: validate certificate subject */
  validateSubject?: (subject: Record<string, string>) => boolean | Promise<boolean>;
}

/**
 * Create server-side certificate verification for eRPC.
 * Useful for mutual TLS-style authentication.
 */
export function createCertificateServerAuth(config: CertificateServerConfig): Pick<AuthOptions, 'verify'> {
  return {
    verify: async (proof, transcript) => {
      const { certificate, signature } = decode(proof) as {
        certificate: number[];
        signature: number[];
      };
      
      if (!certificate || !signature) {
        throw new RPCError("UNAUTHORIZED", "Invalid certificate proof");
      }
      
      const certBytes = new Uint8Array(certificate);
      const { subject, publicKey } = await config.verifyCertificate(certBytes);
      
      // Optional subject validation
      if (config.validateSubject && !(await config.validateSubject(subject))) {
        throw new RPCError("UNAUTHORIZED", "Invalid certificate subject");
      }
      
      // Verify signature over transcript
      const isValid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" }, // Assume ECDSA, could be parameterized
        publicKey,
        new Uint8Array(signature).buffer as ArrayBuffer,
        transcript.buffer as ArrayBuffer
      );
      
      if (!isValid) {
        throw new RPCError("UNAUTHORIZED", "Invalid certificate signature");
      }
      
      return {
        auth: {
          subject,
          verified: true
        }
      };
    }
  };
}

// ─── Multi-factor Authentication Helper ────────────────────────────────────

export interface MultifactorServerConfig {
  /** Primary authentication method */
  primary: Pick<AuthOptions, 'verify'>;
  /** Secondary authentication method */
  secondary: Pick<AuthOptions, 'verify'>;
  /** How to combine auth results */
  combineAuth?: (primary: any, secondary: any) => any;
}

/**
 * Create server-side multi-factor authentication combining two auth methods.
 */
export function createMultifactorServerAuth(config: MultifactorServerConfig): Pick<AuthOptions, 'verify'> {
  return {
    verify: async (proof, transcript) => {
      const { primary: primaryProof, secondary: secondaryProof } = decode(proof) as {
        primary: Uint8Array;
        secondary: Uint8Array;
      };
      
      if (!primaryProof || !secondaryProof) {
        throw new RPCError("UNAUTHORIZED", "Multi-factor proof required");
      }
      
      // Verify both factors
      const primaryResult = await config.primary.verify!(primaryProof, transcript);
      const secondaryResult = await config.secondary.verify!(secondaryProof, transcript);
      
      if (!primaryResult || !secondaryResult) {
        throw new RPCError("UNAUTHORIZED", "Multi-factor verification failed");
      }
      
      // Combine results
      let combinedAuth;
      if (config.combineAuth) {
        combinedAuth = config.combineAuth(
          (primaryResult as any)?.auth,
          (secondaryResult as any)?.auth
        );
      } else {
        // Default: merge auth objects
        combinedAuth = {
          ...(primaryResult as any)?.auth,
          ...(secondaryResult as any)?.auth,
          multifactor: true
        };
      }
      
      return { auth: combinedAuth };
    }
  };
}