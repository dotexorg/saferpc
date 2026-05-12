# Security

eRPC treats the transport as hostile. This page covers what that means, what eRPC actually guarantees, how to configure auth so those guarantees hold, and what is *not* covered. Wire-level mechanics (frame layout, handshake steps, state machines, key derivation) live in [Protocol](protocol.md).

## Threat model

The transport channel is **untrusted**. The attacker may:

- Read all messages (eavesdrop)
- Inject messages (forge)
- Replay captured messages
- Drop or reorder messages

eRPC does **not** protect against:

- **Denial of service.** If the attacker drops every byte, communication is impossible. No fix at this layer.
- **Compromised endpoints.** If the attacker runs code on either side, encryption is irrelevant.
- **Timing side channels in your handlers.** eRPC's own comparisons are constant-time; your handler code is not unless you write it that way.

## Security properties

| Property | Mechanism |
|----------|-----------|
| Confidentiality | XSalsa20-Poly1305 AEAD per message |
| Authentication (session) | PSK mixed into HKDF + optional asymmetric signatures |
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

At least one of `psk` or asymmetric auth (`sign` / `verify`) must be configured. Neither configured is a hard error at construction time — the handshake would be unauthenticated and an active MITM could impersonate either peer.

### PSK only

```typescript
auth: { psk: () => sharedSecret }

auth: {
  psk: () => deriveSessionPSK(sessionToken, deviceSecret),
}
```

Use when both endpoints are controlled by the same entity, secrets can be rotated, and individual revocation is not required. PSK is cheap — no signature operations on the hot path.

> The PSK buffer's lifecycle belongs to the caller. eRPC reads it during HKDF and never mutates it. Returning the same `Uint8Array` from `psk()` across handshakes is safe; if you want it zeroed, zero it yourself when the secret is no longer needed.

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

Use when one side is a public client (browser, mobile app, IoT device), when there are no shared secrets to safely distribute, or when you need per-device identity and revocation.

### Both (defense-in-depth)

```typescript
auth: {
  psk: () => deriveSessionPSK(sessionId, deploymentSecret),
  sign: (transcript) => signWithDeviceKey(transcript),
  verify: (proof, transcript) => verifyDeviceSignature(proof, transcript),
}
```

Use when you want session binding *and* identity proof. An attacker must now compromise two independent things — the derivation secret and the device key — and still cannot read past sessions because of forward secrecy.

### Comparison

| Property | Session-derived PSK | Asymmetric |
|----------|-------------------|------------|
| Identity granularity | Per session | Per key/device |
| Revocation | Rotate root secret (affects all) | Revoke individual keys |
| Compromise blast radius | All sessions sharing the root | The compromised device only |
| Forward secrecy | Ephemeral ECDH | Ephemeral ECDH |
| Replay protection | Epoch + nonce + key binding | Transcript bound |
| Cost | Low (HMAC only) | Higher (signature ops) |
| Complexity | Simple | More moving parts |

Forward secrecy comes from the ephemeral X25519 exchange in either mode. Even if a long-term secret leaks, past session ciphertexts remain unreadable — the ephemeral private keys were zeroed when the session ended.

## Transcript format

Signatures are taken over canonical byte strings built by eRPC. There are two, with domain-separated magic prefixes so a hello signature can never be replayed as a reply (or vice versa).

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

These prefixes plus the epoch plus the per-handshake nonce defeat:

- Replay across direction (hello vs. reply use different prefixes)
- Replay across handshake attempts (epoch differs each time)
- Substitution attacks (an active MITM cannot swap either ephemeral public key without invalidating the signature)

For the full wire layout of the frames that carry these signatures, see [Protocol § Frame format](protocol.md#frame-format).

## Auth processing order

Auth runs **before** any session key is materialized. Failed verification never leaks ECDH artifacts. See [Protocol § Handshake](protocol.md#handshake) for the step-by-step details.

A throw at any auth step rejects the handshake. The client resets to `idle`; the server resets to `waiting`. Failed verifications never silently downgrade.

## Safe vs unsafe PSK patterns

```typescript
// ✅ Static PSK from a secrets vault — server-to-server
auth: {
  psk: async () => await vault.getSecret("erpc-server-key"),
}

// ✅ Session-derived from an authenticated token + device secret
auth: {
  psk: async () => deriveSessionPSK(
    await getValidatedSession(),
    await getSecureDeviceSecret(),
  ),
}

// ✅ Time-bucketed rotation
auth: {
  psk: () => deriveSessionPSK(
    String(Math.floor(Date.now() / 3_600_000)), // hourly bucket
    rotatingMasterSecret,
  ),
}
```

```typescript
// ❌ Hard-coded constant — leaks the moment your bundle leaks
auth: { psk: () => new TextEncoder().encode("secret123") }

// ❌ Predictable session ID — attacker just guesses it
auth: { psk: () => deriveSessionPSK("user-123", secret) }

// ❌ All-zero or weak derivation material — no security at all.
// eRPC refuses an all-zero PSK at runtime: `HANDSHAKE` is thrown with
// "Application returned an all-zero PSK" so this mistake fails loudly
// instead of silently degrading into the asymmetric-only mode.
auth: { psk: () => deriveSessionPSK(sessionId, new Uint8Array(32)) }

// ❌ Secret material in client-side bundle
auth: {
  psk: () => deriveSessionPSK(sessionId, new TextEncoder().encode(API_KEY)),
}
```

The common pattern in the unsafe list: the attacker can reproduce the derivation either because the input is guessable or because the secret is in the wrong place.

## Built-in signature helpers

eRPC ships ready-made helpers for common cases. Every helper binds its proof to the handshake transcript that eRPC passes in.

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

Uses `@noble/curves` so it works in every JS runtime — no dependency on WebCrypto Ed25519 (which is not uniformly available across browsers).

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

Use this when you want the private key to be non-extractable. Pair `generateECDSAKeypair()` with platform key stores.

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

The JWT helper does **not** sign the transcript — JWTs are bearer tokens. Instead, the client embeds `{ jwt, ts, th = SHA-256(transcript) }` in the auth payload, and the server validates the JWT, the timestamp (symmetric `maxAge` skew, so future-dated forgeries are rejected too), and the transcript digest in constant time. A captured payload can only be replayed within a handshake that produces the same transcript, which means the attacker cannot mount a new handshake with their own ephemeral key.

A leaked JWT still lets the attacker authenticate as long as the token is valid. Combine with PSK or a real signature mode when this matters.

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

The client embeds `{ primary, secondary }` — two pre-encoded sub-payloads.

## Replay within a session

eRPC uses random 24-byte nonces (not counters) for XSalsa20-Poly1305. The collision probability is negligible — but **a captured ciphertext can be replayed by an attacker who can inject into a live channel**. The replayed message will decrypt and execute again.

For non-idempotent operations, add an application-level idempotency key inside the procedure input, or maintain a request-ID set on the server keyed by the verified principal.

This is the only known replay window in the protocol. A counter-based scheme would close it but introduces a stronger ordering requirement on the transport, which is not always available (BroadcastChannel, lossy WebRTC, etc.).

## Recommended configurations

**Public web app (browser ↔ server):** asymmetric auth. No shared secrets in the bundle.

```typescript
auth: { sign: async (t) => signWithSessionJWT(t) }
```

**Mobile app ↔ backend:** device certificates or platform attestation.

```typescript
auth: { sign: async (t) => getDeviceAttestation(t) }
```

**Microservices (server ↔ server):** session-derived PSK from a service-mesh identity.

```typescript
auth: { psk: async () => deriveSessionPSK(await serviceToken(), clusterSecret) }
```

**High-security environment:** both PSK and asymmetric, with hardware key storage on at least one side.

```typescript
auth: {
  psk: () => deriveSessionPSK(sessionToken, hsmSecret),
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
| PSK minimum | 32 bytes | Validated when `psk()` returns |
| Encryption nonce | 24 bytes | Random per message |
