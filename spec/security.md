# Security

Safe RPC treats the transport as hostile. This page covers what that buys you, how to configure auth so those guarantees hold, and what is _not_ covered. Wire-level mechanics (frame layout, handshake steps, state machines, key derivation) live in [Protocol](protocol.md). How well the implementation holds up against this model — what was verified and the honest list of residual risks — lives in [Assessment](assessment.md).

## Threat model

The transport channel is **untrusted**. The attacker may:

- Read all messages (eavesdrop)
- Inject messages (forge)
- Replay captured messages
- Drop or reorder messages

Safe RPC does **not** protect against:

- **Denial of service.** An attacker who drops every byte makes communication impossible. No protocol-layer fix.
- **Compromised endpoints.** Once attacker code runs on either side, encryption is moot.
- **Timing side channels in your handlers.** Safe RPC's own comparisons are constant-time. Your handler code is not, unless you write it that way.

## Why authentication is required

A bare ephemeral X25519 exchange produces a shared key, but says nothing about _who_ the key was shared with. An active attacker on the transport can run the exchange separately with each side, hold two different session keys, and sit between the peers rewriting traffic in both directions. Each side sees a clean handshake; neither sees the other. This is the textbook MITM-on-DH attack and the reason `auth` is not optional.

The `auth` callbacks close that gap by binding the ephemeral keys to something the attacker does not have:

- **`secret`** mixes a pre-shared 32-byte value into HKDF as the salt (see [Protocol § Key derivation](protocol.md#key-derivation)). A peer without the secret derives a different `session_key`, and the HMAC proof in the reply fails to verify.
- **`sign` / `verify`** signs the [hello/reply transcript](#transcript-format) with a long-term key the peer can verify. The transcript covers the epoch and both ephemeral public keys, so a signature captured from one handshake will not validate in another.

Without one of those configured, `client()` / `server()` throws a `TypeError` at construction. There is no anonymous fallback, and a `secret()` callback that returns all-zero bytes of any length is also rejected at runtime — a typo cannot silently downgrade an intended PSK deployment into asymmetric-only mode.

### Transport encryption is not a substitute

When a transport already provides its own encryption (TLS for WebSocket, DTLS for WebRTC), `auth` is still required. Two reasons:

- **Transport encryption authenticates the transport endpoint, not the application peer.** A correctly terminated TLS connection to `api.example.com` says nothing about which process inside that deployment answers, what tenant it serves, or whether a reverse proxy is doing inspection. `auth` binds the session to a key controlled by the actual peer.
- **The trust anchor for transport encryption is often outside your control.** For TLS, the public PKI; for WebRTC DTLS, the signalling server. Both can be subverted independently of the cryptographic transport itself.

WebRTC is the clearest case. DTLS runs between the two `RTCPeerConnection` endpoints, but the DTLS certificates are self-signed and their fingerprints are exchanged through the signalling server inside SDP. A malicious or compromised signalling server can substitute fingerprints in both directions, terminating DTLS at itself rather than at the intended peer. The browser still reports an encrypted connection; the operator sees plaintext. Safe RPC's `auth` runs outside the signalling channel: as long as each peer learns the other's public key through a trusted side channel (account system, prior pairing, DID, scanned QR), `verify` rejects any handshake whose signature was not produced by that key, regardless of what the signalling server did with the SDP.

### Why `sign` and `verify` are async

Ed25519 itself is synchronous, but most realistic signature sources are not:

- WebCrypto (`crypto.subtle.sign`) returns a `Promise`.
- Hardware-backed keys (WebAuthn, Secure Enclave, YubiKey, TPM) are all async.
- The peer's public key often has to be fetched (database, account API, DID resolver).
- User-confirmation flows (modal, scanned QR, hardware tap) are async by definition.

When the key is already in memory and the math is synchronous, return `Promise.resolve(sign(t))` and pay nothing for the wrapping. The async signature exists so the harder cases are possible at all, not because every caller must use it.

## Security properties

| Property                 | Mechanism                                                                                                                              |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| Confidentiality          | XSalsa20-Poly1305 AEAD per message                                                                                                     |
| Authentication (session) | Secret mixed into HKDF + optional asymmetric signatures                                                                                |
| Server identity          | HMAC proof in handshake reply (+ optional signature)                                                                                   |
| Client identity          | Implicit (wrong PSK ⇒ invalid ciphertext) + optional signature                                                                         |
| Forward secrecy          | Fresh ephemeral X25519 keys per session                                                                                                |
| Replay across handshakes | Random nonce + epoch counter + transcript-bound signatures                                                                             |
| Replay across peers      | Domain-separated transcript prefixes                                                                                                   |
| Replay within a session  | Random 24-byte nonces + bounded seen-nonce set (server, default 4096)                                                                  |
| Stale responses          | Epoch counter echoed in reply                                                                                                          |
| Prototype pollution      | `sanitize()` strips `__proto__`, `constructor`, `prototype`                                                                            |
| Type confusion           | msgpack extension types disabled (including Timestamp); inbound `bin` fields require exact `Uint8Array` prototype                      |
| Memory hygiene           | Ephemeral keys zeroed on reset/destroy                                                                                                 |
| Plaintext lifetime       | Returned `Uint8Array` fields alias the encrypted payload (msgpack `bin` is zero-copy); copy them out if you need to zero them yourself |

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

> The secret buffer's lifecycle belongs to the caller. Safe RPC reads it during HKDF and never mutates it. Returning the same `Uint8Array` from `secret()` across handshakes is safe; if you want it zeroed, zero it yourself when the secret is no longer needed.

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

Use when you want session binding _and_ identity proof. An attacker must now compromise two independent things (the derivation secret and the device key) and still cannot read past sessions because of forward secrecy.

### Comparison

| Property                | Session-derived secret           | Asymmetric                  |
| ----------------------- | -------------------------------- | --------------------------- |
| Identity granularity    | Per session                      | Per key/device              |
| Revocation              | Rotate root secret (affects all) | Revoke individual keys      |
| Compromise blast radius | All sessions sharing the root    | The compromised device only |
| Forward secrecy         | Ephemeral ECDH                   | Ephemeral ECDH              |
| Replay protection       | Epoch + nonce + key binding      | Transcript bound            |
| Cost                    | Low (HMAC only)                  | Higher (signature ops)      |
| Complexity              | Simple                           | More moving parts           |

Forward secrecy comes from the ephemeral X25519 exchange in either mode. Even if a long-term secret leaks, past session ciphertexts remain unreadable. The ephemeral private keys were zeroed when the session ended.

## Transcript format

Signatures are taken over canonical byte strings built by Safe RPC. Two transcripts exist, each with a domain-separated magic prefix, so a hello signature cannot be replayed as a reply (or vice versa).

```
HELLO transcript:
  "saferpc-hs-hello-v1\0"   (20 bytes)
  epoch                  (4 bytes, big-endian uint32)
  client_pub             (32 bytes, X25519)
  client_nonce           (32 bytes)

REPLY transcript:
  "saferpc-hs-reply-v1\0"   (20 bytes)
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

Client-auth **verification** (the server's `verify` callback) runs **before** ECDH and key derivation, so a failed verification never materializes session-key state and never leaks ECDH artifacts. The server's **`sign`** step runs _after_ key derivation in the normative step order (step 9; the reply transcript binds both ephemeral pubs, the client nonce, and the epoch), but a failed `sign` publishes nothing: no candidate is installed and no reply is sent. Step-by-step in [Protocol § Handshake](protocol.md#handshake).

A throw at any auth step rejects the handshake **attempt**. On the client a failed attempt returns to `idle`. On the server, under make-before-break, only the attempt is discarded — an established live session is never disturbed by a failed attempt and keeps serving. Failed verification never silently downgrades into an unauthenticated session.

Auth callbacks are application-owned Promises and cannot be forcibly cancelled by the library. The server therefore bounds unsettled attempts with `maxPendingHandshakes` (default 16); timed-out attempts retain a slot until their callback settles, and hellos at the cap are silently dropped. The client retains one timed-out unsettled handshake operation and rejects a new attempt until it settles, preventing repeated retries from accumulating closures.

## Ephemeral key validity

The peer's X25519 public key is consumed verbatim by `getSharedSecret`. Safe RPC relies on the curve implementation to reject the small-subgroup elements listed in RFC 7748 §6.1 (the all-zero point, the order-1 element, the four order-8 elements, and the three near-`p` variants). If those points were accepted, the ECDH output would be all zeros and an active MITM in asymmetric-only mode could rewrite the hello's `pub` to drive both sides to a deterministic `session_key = HKDF(zeros, EMPTY_SECRET, "saferpc-v1", 32)`, then replay a captured bearer-style auth payload over the matching transcript and decrypt the session.

The reference implementation gets this defense from `@noble/curves` (^2.2.0), which throws on every known low-order input. The pin in `package.json` is therefore load-bearing: a future curve dependency that relaxed the check would re-open the attack against asymmetric-only deployments. The regression test `test/security/f002-low-order-x25519-pubkey.test.ts` pins both halves of the contract — the library throws, and a forged hello carrying a low-order `pub` aborts the server handshake before any session state is derived. A port to another language must enforce the same rejection at the application layer if its chosen curve library does not.

## Safe vs unsafe secret patterns

```typescript
// ✅ Static secret from a secrets vault, server-to-server
auth: {
  secret: async () => await vault.getSecret("saferpc-server-key"),
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
// `deriveSessionSecret` rejects all-zero input material outright, and the
// handshake refuses an all-zero secret of ANY length at runtime ("Application
// returned an all-zero secret") — either way this mistake fails loudly instead
// of silently degrading into the asymmetric-only mode.
auth: { secret: () => deriveSessionSecret(sessionId, new Uint8Array(32)) }

// ❌ Secret material in client-side bundle
auth: {
  secret: () => deriveSessionSecret(sessionId, new TextEncoder().encode(API_KEY)),
}
```

The unsafe list shares one pattern: the attacker can reproduce the derivation, either because the input is guessable or because the secret material lives in the wrong place.

### The secret is a key, not a password

The `secret` **must** be a high-entropy cryptographic key (e.g. `randomBytes(32)` from a CSPRNG), not a password or passphrase. The 32-byte minimum length is a floor, not a guarantee of strength: 32 bytes of a human-chosen or dictionary-derived value still has only password-level entropy.

The reason is a proof oracle inherent to the handshake. On any well-formed hello the server derives `session_key = HKDF(raw, salt=secret)` and returns `proof = HMAC(session_key, s_pub‖c_pub‖c_nonce)` — before the client has proven anything. An attacker who sends their own hello with an ephemeral pair they generated knows `raw` (X25519 is symmetric: `X25519(attacker_priv, s_pub) == X25519(s_priv, attacker_pub)`), and receives `s_pub` and `proof`. That leaves the secret as the only unknown in the proof, so the attacker can grind candidate secrets **offline**, at billions of guesses per second, with no further traffic to the server:

```
for guess in candidates:            # offline, no network
    k = HKDF(raw, salt=guess)
    if HMAC(k, s_pub‖c_pub‖c_nonce) == proof:  # found it
```

Against a random 32-byte key this is 2²⁵⁶ work — infeasible. Against a password-derived secret it is a fast dictionary attack. This is a property of the scheme (PSK as HKDF salt with a server-first proof), not a fixable bug; defending weak passwords would require a PAKE, which saferpc is not.

```typescript
// ✅ Real random key from a CSPRNG
import { randomBytes } from "@noble/ciphers/utils.js";
const key = randomBytes(32);
auth: {
  secret: () => key;
}

// ❌ Password / passphrase used directly — offline-bruteforceable via the proof
auth: {
  secret: () => new TextEncoder().encode("correct horse battery staple");
}

// ⚠️ If you MUST start from a human password, stretch it with a slow KDF first
//     (scrypt / argon2) — this raises the per-guess cost but does not make a
//     weak password strong; prefer a real random key wherever possible.
auth: {
  secret: async () =>
    await scrypt(password, salt, { N: 2 ** 17, r: 8, p: 1, dkLen: 32 });
}
```

## Built-in signature helpers

Safe RPC ships ready-made helpers for the common cases. Each one binds its proof to the handshake transcript that Safe RPC passes in.

```typescript
import {
  createEd25519ClientAuth,
  createEd25519ServerAuth,
  createECDSAClientAuth,
  createECDSAServerAuth,
  createJWTClientAuth,
  createJWTServerAuth,
  generateEd25519Keypair,
  generateECDSAKeypair,
} from "@dotex/saferpc";
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
  privateKey: ecdsaPrivateKey, // CryptoKey (can be non-extractable)
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

**The token is wire-visible.** The hello frame is not yet encrypted — it carries the ephemeral public key that establishes the session — so the JWT rides it in cleartext. A passive observer of the transport (already in scope in the threat model above) reads the token directly off the opening frame; obtaining it does not require any out-of-band access. JWT-only mode therefore assumes a **confidential transport** (TLS / DTLS) or a second factor (PSK or a signature mode). Over an untrusted transport the token is disclosed on every handshake. Signature modes (`ed25519` / `ecdsa`) do not have this property: their payload is a signature over the transcript, not a reusable secret.

### Custom schemes (certificates, multiple factors)

There are no built-in helpers for certificate-based or multi-factor auth: in both cases the security-critical logic (chain verification; asserting that all factors resolve to the _same_ principal) depends on application knowledge the library does not have, so a generic helper would only wrap the trivial part while its name suggested it handles the hard part. Implement `sign`/`verify` directly instead:

- **Certificates** — client `sign` returns an encoded `{ cert, sig }` where `sig` is a signature over the transcript with the cert's key; server `verify` runs your chain verification, then checks the signature (the checking step is exactly what `createECDSAServerAuth` does — reuse it for the signature half if the key is P-256).
- **Multiple factors** — client `sign` encodes both sub-proofs; server `verify` decodes them, runs each sub-verifier against the same transcript, and **must reject unless both factors resolve to the same principal** (e.g. the JWT's `sub` owns the signing `deviceId` per your own store). Only then combine them into one explicit principal. Never merge two independently verified principals blindly: a stolen bearer token plus the attacker's _own_ validly registered second factor would otherwise pass as "multi-factor" for the victim's identity.

## Replay within a session

Safe RPC uses random 24-byte nonces (not counters) for XSalsa20-Poly1305. The collision probability is negligible. A captured ciphertext could otherwise be replayed by an attacker who can inject into a live channel, and the replayed message would decrypt and execute again.

As of 0.7.0 the server keeps a **bounded seen-nonce set** per session (`replayWindow`, default 4096): after Poly1305 verification it records malformed envelopes and request frames, then silently drops later duplicates. Reflected response frames (`t: 2`) are dropped without consuming request replay-window capacity. This closes the replay window for the last `replayWindow` request-side messages of a session, with no wire change and no ordering requirement (so lossy / reordering transports stay supported). The set is cleared on every re-handshake, and only the server needs it — the client already matches responses to a monotonic request `id` that is never reused.

The window is **narrowed to N, not closed**: a replay older than the last `replayWindow` accepted messages still executes. For non-idempotent operations on long-lived sessions, still add an idempotency key inside the procedure input, or keep a request-ID set keyed by the verified principal. Set `replayWindow: 0` to disable the defense. Counter-based nonces would close the window fully but require strict transport ordering and directional keys (keystream reuse otherwise on the single shared key); that is deferred to a future protocol version.

## Recommended configurations

**Public web app (browser ↔ server):** asymmetric auth. No shared secrets in the bundle.

```typescript
auth: {
  sign: async (t) => signWithSessionJWT(t);
}
```

**Mobile app ↔ backend:** device keys (`createEd25519ClientAuth` / `createECDSAClientAuth`) or platform attestation.

```typescript
auth: {
  sign: async (t) => getDeviceAttestation(t);
}
```

**Microservices (server ↔ server):** session-derived secret from a service-mesh identity.

```typescript
auth: {
  secret: async () => deriveSessionSecret(await serviceToken(), clusterSecret);
}
```

**High-security environment:** both secret and asymmetric, with hardware key storage on at least one side.

```typescript
auth: {
  secret: () => deriveSessionSecret(sessionToken, hsmSecret),
  sign: (t) => signWithHardwareKey(t),
  verify: (p, t) => verifyWithPKI(p, t),
}
```

### Authentication is directional

`sign` / `verify` authenticate one direction at a time, and the examples above (client `sign`, server `verify`) are **one-directional**: they prove the _client's_ identity to the server. They do **not** prove the _server's_ identity to the client — a client configured with only `sign` learns nothing about the peer beyond "it completed the key exchange". Under an empty secret the reply proof only demonstrates that the peer derived the same session key, which any endpoint reachable on the wire can do; a client with a real device key will therefore complete a handshake with any server that accepts it.

For **mutual** authentication configure both directions — the server also `sign`s and the client also `verify`s (as in the high-security block above) — or bind both peers to a shared `secret` (PSK), which authenticates symmetrically. Choose one-directional only when the unauthenticated side is genuinely untrusted (a public server serving anonymous clients, for instance).

## Constants and limits

| Constant            | Value     | Notes                                                      |
| ------------------- | --------- | ---------------------------------------------------------- |
| `NONCE_LEN`         | 24        | XSalsa20-Poly1305 per-message nonce                        |
| `KEY_LEN`           | 32        | Symmetric key, X25519 pub/priv, and the client hello nonce |
| `MAX_HELLO_BYTES`   | 65,536    | Sized for typical signature payloads                       |
| `MAX_AUTH_BYTES`    | 32,768    | Hard cap on `auth` payload inside a hello/reply            |
| `MAX_MSG_BYTES`     | 1,048,576 | Per encrypted RPC frame (configurable)                     |
| `HANDSHAKE_TIMEOUT` | 5,000 ms  | Default                                                    |
| Secret minimum      | 32 bytes  | Validated when `secret()` returns                          |
| Encryption nonce    | 24 bytes  | Random per message                                         |
