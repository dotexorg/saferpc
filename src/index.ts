export {
  // Constants
  NONCE_LEN,
  KEY_LEN,
  TAG_HELLO,
  TAG_MSG,
  MAX_MSG_BYTES,
  MAX_HELLO_BYTES,
  MAX_AUTH_BYTES,
  HANDSHAKE_TIMEOUT,
  // Crypto re-exports
  x25519,
  concatBytes,
  // Security utilities
  zero,
  sanitize,
  // Msgpack
  mpEncode,
  mpDecode,
  // Key derivation
  deriveSessionKey,
  computeProof,
  // Handshake transcript (used by auth implementations)
  buildHelloTranscript,
  buildReplyTranscript,
  // Encryption
  createEncryptor,
  createDecryptor,
  // Auth config
  validateAuthConfig,
  validatePSK,
  EMPTY_PSK,
  // Error
  RPCError,
  // Chain builder
  chain,
  // Types
  type Ctx,
  type MwFn,
  type Step,
  type HandlerFn,
  type Procedure,
  type Router,
  type Channel,
  type Chain,
  type AuthOptions,
  type VerifyResult,
  // Backward compatibility
  type Authenticator,
  type AuthVerifyResult,
} from "./common.ts";

export {
  client,
  RemoteRPCError,
  type Client,
  type ClientOptions,
} from "./client.ts";
export { server, type ServerOptions } from "./server.ts";

// Auth helpers
export {
  deriveSessionPSK,
  // Client-side auth helpers
  createJWTClientAuth,
  createEd25519ClientAuth,
  createECDSAClientAuth,
  generateEd25519Keypair,
  generateECDSAKeypair,
  // Server-side auth helpers
  createJWTServerAuth,
  createEd25519ServerAuth,
  createECDSAServerAuth,
  createCertificateServerAuth,
  createMultifactorServerAuth,
  // Types
  type JWTClientConfig,
  type Ed25519ClientConfig,
  type ECDSAClientConfig,
  type JWTServerConfig,
  type Ed25519ServerConfig,
  type ECDSAServerConfig,
  type CertificateServerConfig,
  type MultifactorServerConfig,
} from "./auth.ts";
