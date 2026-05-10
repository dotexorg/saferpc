/**
 * Client-side authentication helpers
 */

import { encode } from "@msgpack/msgpack";
import { RPCError, type AuthOptions } from "./common.ts";

// ─── JWT Client Authentication Helper ───────────────────────────────

export interface JWTClientConfig {
  /** Get JWT token (e.g., from localStorage or session storage) */
  getToken: () => string | null | Promise<string | null>;
}

/**
 * Create client-side JWT authentication for eRPC. The JWT is embedded in the
 * authenticator payload and sent to the server for verification.
 */
export function createJWTClientAuth(config: JWTClientConfig): Pick<AuthOptions, 'sign'> {
  return {
    sign: async (_transcript) => {
      const token = await config.getToken();
      if (!token) {
        throw new RPCError("UNAUTHORIZED", "No JWT token available");
      }
      
      // Embed JWT in the authenticator payload
      return new TextEncoder().encode(JSON.stringify({
        jwt: token,
        timestamp: Date.now()
      }));
    }
  };
}

// ─── Ed25519 Client Authentication Helper ───────────────────────────────

export interface Ed25519ClientConfig {
  /** Ed25519 private key for signing */
  privateKey: Uint8Array;
  /** This device's ID (for signing) */
  deviceId: string;
}

/**
 * Create client-side Ed25519 device authentication for eRPC.
 */
export function createEd25519ClientAuth(config: Ed25519ClientConfig): Pick<AuthOptions, 'sign'> {
  return {
    sign: async (transcript) => {
      // Use WebCrypto if available, otherwise throw
      if (typeof crypto === "undefined" || !crypto.subtle) {
        throw new RPCError("INTERNAL", "WebCrypto not available");
      }
      
      // Import private key
      const privateKey = await crypto.subtle.importKey(
        "raw",
        config.privateKey.buffer as ArrayBuffer,
        { name: "Ed25519" },
        false,
        ["sign"]
      );
      
      // Sign transcript
      const signature = await crypto.subtle.sign(
        "Ed25519",
        privateKey,
        transcript.buffer as ArrayBuffer
      );
      
      // Encode device ID + signature
      return encode({
        deviceId: config.deviceId,
        signature: Array.from(new Uint8Array(signature))
      });
    }
  };
}

// ─── ECDSA P-256 Client Authentication Helper ────────────────────────────────

export interface ECDSAClientConfig {
  /** ECDSA P-256 private key for signing */
  privateKey: CryptoKey;
  /** This entity's identifier (for signing) */
  identifier: string;
}

/**
 * Create client-side ECDSA P-256 authentication for eRPC using WebCrypto.
 */
export function createECDSAClientAuth(config: ECDSAClientConfig): Pick<AuthOptions, 'sign'> {
  return {
    sign: async (transcript) => {
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        config.privateKey,
        transcript.buffer as ArrayBuffer
      );
      
      return encode({
        identifier: config.identifier,
        signature: Array.from(new Uint8Array(signature))
      });
    }
  };
}

// ─── Device Key Management Helpers ────────────────────────────────────

/**
 * Generate a new Ed25519 keypair for device authentication
 */
export async function generateEd25519Keypair(): Promise<{
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}> {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new RPCError("INTERNAL", "WebCrypto not available");
  }
  
  const keyPair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"]
  );
  
  const privateKeyBytes = await crypto.subtle.exportKey("raw", keyPair.privateKey);
  const publicKeyBytes = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  
  return {
    privateKey: new Uint8Array(privateKeyBytes),
    publicKey: new Uint8Array(publicKeyBytes)
  };
}

/**
 * Generate a new ECDSA P-256 keypair for authentication
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
    true,
    ["sign", "verify"]
  );
  
  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey
  };
}