/**
 * Authentication utilities
 */

// ─── Session-Derived PSK Helper ─────────────────────────────

/**
 * Re-export deriveSessionPSK for convenience
 */
export { deriveSessionPSK } from "./common.ts";

// ─── Re-exports for convenience ──────────────────────────────

// Client-side auth helpers
export {
  createJWTClientAuth,
  createEd25519ClientAuth,
  createECDSAClientAuth,
  generateEd25519Keypair,
  generateECDSAKeypair,
  type JWTClientConfig,
  type Ed25519ClientConfig,
  type ECDSAClientConfig,
} from "./authClient.ts";

// Server-side auth helpers
export {
  createJWTServerAuth,
  createEd25519ServerAuth,
  createECDSAServerAuth,
  createCertificateServerAuth,
  createMultifactorServerAuth,
  type JWTServerConfig,
  type Ed25519ServerConfig,
  type ECDSAServerConfig,
  type CertificateServerConfig,
  type MultifactorServerConfig,
} from "./authServer.ts";
