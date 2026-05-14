# Security

eRPC treats the transport as hostile. This page covers what that buys you, how to configure auth so those guarantees hold, and what is *not* covered. Wire-level mechanics (frame layout, handshake steps, state machines, key derivation) live in [Protocol](protocol.md).

## Threat model

The transport channel is **untrusted**. The attacker may:

- Read all messages (eavesdrop)
- Inject messages (forge)
- Replay captured messages
- Drop or reorder messages

eRPC does **not** protect against:

- **Denial of service.** An attacker who drops every byte makes communication impossible. No protocol-layer fix.
- **Compromised endpoints.** Once attacker code runs on either side, encryption is moot.
- **Timing side channels in your handlers.** eRPC's own comparisons are constant-time. Your handler code is not, unless you write it that way.

## Security properties

| Property | Mechanism |
|----------|-----------|
| Confidentiality | XSalsa20-Poly1305 AEAD per message |
| Authentication (session) | Secret mixed into HKDF + optional asymmetric signatures |
| Server identity | HMAC proof in handshake reply (+ optional signature) |
| Client identity | Implicit (wrong PSK ⇒ invalid ciphertext) + optional signature |
| Forward secrecy | Fresh ephemeral X25519 keys per session |
| Replay across handshakes | Random nonce + epoch counter + transcript-bound signatures |
| Replay across peers | Domain-separated transcript prefixes |
| Replay within a session | Random 24-byte nonces per message (probabilistic) |
| Stale responses | Epoch counter echoed in reply |
| Prototype pollution | `sanitize()` strips `__proto__`, `constructor`, `prototype` |
| Type confusion | msgpack extension types disabled (including Timestamp); inbound `bin` fields require exact `Uint8Array` prototype |
| Memory hygiene | Ephemeral keys zeroed on reset/destroy |
| Plaintext lifetime | Returned `Uint8Array` fields alias the encrypted payload (msgpack `bin` is zero-copy); copy them out if you need to zero them yourself |

## Authentication modes

At least one of `secret` or asymmetric auth (`sign` / `verify`) must be configured. Neither configured is a hard error at construction time. An unauthenticated handshake would let an active MITM impersonate either peer.

### Secret only

```typescript
auth: { secret: () => sharedSecret }

auth: {
  secret: () => deriveSessionSecret(sessionToken, deviceSecret),
}
```

Use when both endpoints are controlled by the same entity, secrets can be rotated, and individual revocation is not required. A pre-shared secret is cheap: no signature operations on the hot path.

> The secret buffer's lifecycle belongs to the caller. eRPC reads it during HKDF and never mutates it. Returning the same `Uint8Array` from `secret()` across handshakes is safe; if you want it zeroed, zero it yourself when the secret is no longer needed.

### Asymmetric only

Client signs, server verifies. Or both sign and both verify (mutual auth).

```typescript
// Client
auth: { sign: async (transcript) => signWithDeviceKey(transcript) }

// Server
auth: {
  verify: async (proof, transcript) => {
    const principal = await verifyDeviceSignature(proof, transcript);
    return { auth: principal };
  },
}
```

Fits when one side is a public client (browser, mobile app, IoT device), when there is no safe place to put a shared secret, or when you need per-device identity and revocation.

### Both (defense-in-depth)

```typescript
auth: {
  secret: () => deriveSessionSecret(sessionId, deploymentSecret),
  sign: (transcript) => signWithDeviceKey(transcript),
  verify: (proof, transcript) => verifyDeviceSignature(proof, transcript),
}
```

Use when you want session binding *and* identity proof. An attacker must now compromise two independent things (the derivation secret and the device key) and still cannot read past sessions because of forward secrecy.

### Comparison

| Property | Session-derived secret | Asymmetric |
|----------|----------------------|------------|
| Identity granularity | Per session | Per key/device |
| Revocation | Rotate root secret (affects all) | Revoke individual keys |
| Compromise blast radius | All sessions sharing the root | The compromised device only |
| Forward secrecy | Ephemeral ECDH | Ephemeral ECDH |
| Replay protection | Epoch + nonce + key binding | Transcript bound |
| Cost | Low (HMAC only) | Higher (signature ops) |
| Complexity | Simple | More moving parts |

Forward secrecy comes from the ephemeral X25519 exchange in either mode. Even if a long-term secret leaks, past session ciphertexts remain unreadable. The ephemeral private keys were zeroed when the session ended.

## Transcript format

Signatures are taken over canonical byte strings built by eRPC. Two transcripts exist, each with a domain-separated magic prefix, so a hello signature cannot be replayed as a reply (or vice versa).

```
HELLO transcript:
  "erpc-hs-hello-v1\0"   (17 bytes)
  epoch                  (4 bytes, big-endian uint32)
  client_pub             (32 bytes, X25519)
  client_nonce           (32 bytes)

REPLY transcript:
  "erpc-hs-reply-v1\0"   (17 bytes)
  epoch                  (4 bytes, big-endian uint32)
  client_pub             (32 bytes)
  client_nonce           (32 bytes)
  server_pub             (32 bytes)
```

Prefix, epoch, and per-handshake nonce together defeat:

- Replay across direction — hello and reply use different prefixes
- Replay across handshake attempts - epoch differs each time
- Substitution attacks — an active MITM cannot swap either ephemeral public key without invalidating the signature

For the full wire layout of the frames that carry these signatures, see [Protocol § Frame format](protocol.md#frame-format).

## Auth processing order

Auth runs **before** any session key is materialized, so a failed verification never leaks ECDH artifacts. Step-by-step in [Protocol § Handshake](protocol.md#handshake).

A throw at any auth step rejects the handshake. The client resets to `idle`, the server resets to `waiting`. Failed verification never silently downgrades into an unauthenticated session.

## Ephemeral key validity

The peer's X25519 public key is consumed verbatim by `getSharedSecret`. eRPC relies on the curve implementation to reject the small-subgroup elements listed in RFC 7748 §6.1 (the all-zero point, the order-1 element, the four order-8 elements, and the three near-`p` variants). If those points were accepted, the ECDH output would be all zeros and an active MITM in asymmetric-only mode could rewrite the hello's `pub` to drive both sides to a deterministic `session_key = HKDF(zeros, EMPTY_SECRET, "drpc-v1", 32)`, then replay a captured bearer-style auth payload over the matching transcript and decrypt the session.

The reference implementation gets this defense from `@noble/curves` (^2.2.0), which throws on every known low-order input. The pin in `package.json` is therefore load-bearing: a future curve dependency that relaxed the check would re-open the attack against asymmetric-only deployments. The regression test `test/security/f002-low-order-x25519-pubkey.test.ts` pins both halves of the contract — the library throws, and a forged hello carrying a low-order `pub` aborts the server handshake before any session state is derived. A port to another language must enforce the same rejection at the application layer if its chosen curve library does not.

## Safe vs unsafe secret patterns

```typescript
// ✅ Static secret from a secrets vault, server-to-server
auth: {
  secret: async () => await vault.getSecret("erpc-server-key"),
}

// ✅ Session-derived from an authenticated token + device secret
auth: {
  secret: async () => deriveSessionSecret(
    await getValidatedSession(),
    await getSecureDeviceSecret(),
  ),
}

// ✅ Time-bucketed rotation
auth: {
  secret: () => deriveSessionSecret(
    String(Math.floor(Date.now() / 3_600_000)), // hourly bucket
    rotatingMasterSecret,
  ),
}
```

```typescript
// ❌ Hard-coded constant: leaks the moment your bundle leaks
auth: { secret: () => new TextEncoder().encode("secret123") }

// ❌ Predictable session ID: attacker just guesses it
auth: { secret: () => deriveSessionSecret("user-123", secret) }

// ❌ All-zero or weak derivation material: no security at all.
// eRPC refuses an all-zero secret at runtime: `HANDSHAKE` is thrown with
// "Application returned an all-zero secret" so this mistake fails loudly
// instead of silently degrading into the asymmetric-only mode.
auth: { secret: () => deriveSessionSecret(sessionId, new Uint8Array(32)) }

// ❌ Secret material in client-side bundle
auth: {
  secret: () => deriveSessionSecret(sessionId, new TextEncoder().encode(API_KEY)),
}
```

The unsafe list shares one pattern: the attacker can reproduce the derivation, either because the input is guessable or because the secret material lives in the wrong place.

## Built-in signature helpers

eRPC ships ready-made helpers for the common cases. Each one binds its proof to the handshake transcript that eRPC passes in.

```typescript
import {
  createEd25519ClientAuth,
  createEd25519ServerAuth,
  createECDSAClientAuth,
  createECDSAServerAuth,
  createJWTClientAuth,
  createJWTServerAuth,
  createCertificateServerAuth,
  createMultifactorServerAuth,
  generateEd25519Keypair,
  generateECDSAKeypair,
} from "@dotex/erpc";
```

### Ed25519 (recommended)

```typescript
const clientAuth = createEd25519ClientAuth({
  privateKey: devicePrivateKey,     // 32-byte secret key
  deviceId: "device-123",
});

const serverAuth = createEd25519ServerAuth({
  getPublicKey: async (deviceId) => getDevicePublicKey(deviceId),
});

// Client
auth: { ...clientAuth }
// Server
auth: { ...serverAuth }
```

Uses `@noble/curves` so it works in every JS runtime. No dependency on WebCrypto Ed25519, which is not uniformly available across browsers.

### ECDSA P-256 (WebCrypto)

```typescript
const clientAuth = createECDSAClientAuth({
  privateKey: ecdsaPrivateKey,      // CryptoKey (can be non-extractable)
  identifier: "device-123",
});

const serverAuth = createECDSAServerAuth({
  getPublicKey: async (id) => getDevicePublicKey(id),
});
```

Use this when the private key must be non-extractable. Pair `generateECDSAKeypair()` with platform key stores.

### JWT (bearer token, transcript-bound)

```typescript
const clientAuth = createJWTClientAuth({
  getToken: () => localStorage.getItem("jwt"),
});

const serverAuth = createJWTServerAuth({
  verifyToken: async (jwt) => {
    const payload = await validateJWT(jwt);
    return { userId: payload.sub, permissions: payload.permissions };
  },
  maxAge: 30_000,
});
```

The JWT helper does **not** sign the transcript. JWTs are bearer tokens. Instead, the client embeds `{ jwt, ts, th = SHA-256(transcript) }` in the auth payload, and the server validates the JWT, the timestamp (symmetric `maxAge` skew, so future-dated forgeries are rejected too), and the transcript digest in constant time.

The transcript digest prevents replay of a captured auth payload into a different handshake — the digest was computed over the old transcript and will not match the new one. It does **not** prevent an attacker who has obtained the JWT itself from mounting a fresh handshake with their own ephemeral key and recomputing the digest. JWTs are bearer credentials: anyone holding one can authenticate until it expires. Combine with PSK or a real signature mode when this matters.

### Certificate-based

```typescript
const serverAuth = createCertificateServerAuth({
  verifyCertificate: async (certBytes) => {
    return { subject, publicKey }; // your chain verification
  },
});
```

The client embeds `{ cert, sig }` where `sig` is an ECDSA P-256 signature over the transcript using the cert's key.

### Multifactor

Compose two verifiers. Both must pass.

```typescript
const serverAuth = createMultifactorServerAuth({
  primary: createEd25519ServerAuth({ getPublicKey: ... }),
  secondary: createJWTServerAuth({ verifyToken: ... }),
});
```

The client embeds `{ primary, secondary }`: two pre-encoded sub-payloads.

## Replay within a session

eRPC uses random 24-byte nonces (not counters) for XSalsa20-Poly1305. The collision probability is negligible. But **a captured ciphertext can be replayed by an attacker who can inject into a live channel**. The replayed message will decrypt and execute again.

For non-idempotent operations, add an idempotency key inside the procedure input, or keep a request-ID set on the server keyed by the verified principal.

This is the only known replay window in the protocol. A counter-based scheme would close it, but it would also require strict transport ordering, and several supported transports (BroadcastChannel, lossy WebRTC, multi-path links) cannot promise that.

## Recommended configurations

**Public web app (browser ↔ server):** asymmetric auth. No shared secrets in the bundle.

```typescript
auth: { sign: async (t) => signWithSessionJWT(t) }
```

**Mobile app ↔ backend:** device certificates or platform attestation.

```typescript
auth: { sign: async (t) => getDeviceAttestation(t) }
```

**Microservices (server ↔ server):** session-derived secret from a service-mesh identity.

```typescript
auth: { secret: async () => deriveSessionSecret(await serviceToken(), clusterSecret) }
```

**High-security environment:** both secret and asymmetric, with hardware key storage on at least one side.

```typescript
auth: {
  secret: () => deriveSessionSecret(sessionToken, hsmSecret),
  sign: (t) => signWithHardwareKey(t),
  verify: (p, t) => verifyWithPKI(p, t),
}
```

## Constants and limits

| Constant | Value | Notes |
|----------|-------|-------|
| `NONCE_LEN` | 24 | XSalsa20-Poly1305 per-message nonce |
| `KEY_LEN` | 32 | Symmetric key, X25519 pub/priv, and the client hello nonce |
| `MAX_HELLO_BYTES` | 65,536 | Sized for typical signature payloads |
| `MAX_AUTH_BYTES` | 32,768 | Hard cap on `auth` payload inside a hello/reply |
| `MAX_MSG_BYTES` | 1,048,576 | Per encrypted RPC frame (configurable) |
| `HANDSHAKE_TIMEOUT` | 5,000 ms | Default |
| Secret minimum | 32 bytes | Validated when `secret()` returns |
| Encryption nonce | 24 bytes | Random per message |
