// Generate known-answer test vectors for spec/protocol.md from the
// reference implementation. Deterministic fixed inputs -> hex outputs.
// Run: node scripts/gen-vectors.mjs   (requires node >= 22 w/ strip-types? no —
// we import from noble directly + replicate the exact derivation calls)

import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { xsalsa20poly1305 } from "@noble/ciphers/salsa.js";
import { concatBytes } from "@noble/ciphers/utils.js";
import { encode } from "@msgpack/msgpack";

const hex = (b) => Buffer.from(b).toString("hex");
const fromPattern = (start, len = 32) =>
  new Uint8Array(Array.from({ length: len }, (_, i) => (start + i) & 0xff));

// ── Fixed inputs ──
const c_priv = fromPattern(0x01); // 0x01..0x20
const s_priv = fromPattern(0x41); // 0x41..0x60
const c_nonce = fromPattern(0x81); // 0x81..0xa0
const secret = fromPattern(0xc1); // 0xc1..0xe0
const epoch = 1;

const c_pub = x25519.getPublicKey(c_priv);
const s_pub = x25519.getPublicKey(s_priv);

// raw shared: both sides must agree
const raw_c = x25519.getSharedSecret(c_priv, s_pub);
const raw_s = x25519.getSharedSecret(s_priv, c_pub);
if (hex(raw_c) !== hex(raw_s)) throw new Error("ECDH mismatch");

const KDF_INFO = new TextEncoder().encode("saferpc-v1");
const EMPTY_SECRET = new Uint8Array(32);

// session keys (exact call from src/common.ts deriveSessionKey)
const session_key_psk = hkdf(sha256, raw_c, secret, KDF_INFO, 32);
const session_key_nopsk = hkdf(sha256, raw_c, EMPTY_SECRET, KDF_INFO, 32);

// proof (exact call from src/common.ts computeProof)
const proof = hmac(sha256, session_key_psk, concatBytes(s_pub, c_pub, c_nonce));

// transcripts (exact layout from src/common.ts)
const epochBytes = new Uint8Array(4);
new DataView(epochBytes.buffer).setUint32(0, epoch, false);
const HELLO_MAGIC = new TextEncoder().encode("saferpc-hs-hello-v1\0");
const REPLY_MAGIC = new TextEncoder().encode("saferpc-hs-reply-v1\0");
const hello_transcript = concatBytes(HELLO_MAGIC, epochBytes, c_pub, c_nonce);
const reply_transcript = concatBytes(
  REPLY_MAGIC,
  epochBytes,
  c_pub,
  c_nonce,
  s_pub,
);

// deriveSessionSecret helper (exact call from src/common.ts)
const dss = hkdf(
  sha256,
  secret,
  new TextEncoder().encode("session-abc123"),
  new TextEncoder().encode("saferpc-session-v1"),
  32,
);

// encrypted frame KAT: fixed msg nonce, request {t:1,id:"1",p:"ping"}
const msg_nonce = fromPattern(0x11, 24); // 0x11..0x28
const plaintext = encode({ t: 1, id: "1", p: "ping" }); // default codec fine: no ext, no bigints
const ct = xsalsa20poly1305(session_key_psk, msg_nonce).encrypt(plaintext);
const frame = concatBytes(new Uint8Array([0x01]), msg_nonce, ct);

// ── Auth profile payload KATs ──
// All bind to hello_transcript above. Encoded with the library codec options
// ({ useBigInt64: true } — matters for jwt.ts, which must land as float64).
const mp = (data) => encode(data, { useBigInt64: true });

// jwt profile: fully deterministic given fixed ts.
const jwt_token = "test.jwt.token";
const jwt_ts = 1700000000000; // fixed; encodes as msgpack float64 (0xcb)
const jwt_payload = mp({
  v: 1,
  jwt: jwt_token,
  ts: jwt_ts,
  th: sha256(hello_transcript),
});

// ed25519 profile: RFC 8032 signatures are deterministic — byte-exact KAT.
const ed_seed = fromPattern(0x61); // 0x61..0x80
const ed_pub = ed25519.getPublicKey(ed_seed);
const ed_sig = ed25519.sign(hello_transcript, ed_seed); // exact call from src/auth/client.ts
const ed_payload = mp({ v: 1, deviceId: "device-1", sig: ed_sig });

// ecdsa profile: WebCrypto signing is randomized, so the KAT signature is the
// RFC 6979 deterministic lowS signature (prehash SHA-256, P-1363 r||s) — it
// verifies under WebCrypto like any other valid signature. A port with a
// randomized signer will NOT reproduce these bytes; its payload must instead
// VERIFY against ecdsa_pub, and this payload must verify in its verifier.
const ecdsa_priv = fromPattern(0xa1); // 0xa1..0xc0, valid P-256 scalar
const ecdsa_pub = p256.getPublicKey(ecdsa_priv, false); // uncompressed, 65 bytes
const ecdsa_sig = p256.sign(hello_transcript, ecdsa_priv, {
  lowS: true,
  prehash: true,
});
const ecdsa_payload = mp({ v: 1, identifier: "entity-1", sig: ecdsa_sig });

const out = {
  inputs: {
    c_priv: hex(c_priv),
    s_priv: hex(s_priv),
    c_nonce: hex(c_nonce),
    secret: hex(secret),
    epoch,
  },
  derived: {
    c_pub: hex(c_pub),
    s_pub: hex(s_pub),
    raw_shared: hex(raw_c),
    session_key_psk: hex(session_key_psk),
    session_key_empty_secret: hex(session_key_nopsk),
    proof: hex(proof),
    hello_transcript: hex(hello_transcript),
    reply_transcript: hex(reply_transcript),
    deriveSessionSecret_session_abc123: hex(dss),
  },
  encrypted_frame: {
    msg_nonce: hex(msg_nonce),
    plaintext_msgpack: hex(plaintext),
    frame: hex(frame),
  },
  auth_profiles: {
    transcript: "hello_transcript (above)",
    jwt: {
      token: jwt_token,
      ts: jwt_ts,
      th: hex(sha256(hello_transcript)),
      payload: hex(jwt_payload),
    },
    ed25519: {
      seed: hex(ed_seed),
      publicKey: hex(ed_pub),
      deviceId: "device-1",
      sig: hex(ed_sig),
      payload: hex(ed_payload),
    },
    ecdsa: {
      privateScalar: hex(ecdsa_priv),
      publicKeyUncompressed: hex(ecdsa_pub),
      identifier: "entity-1",
      sig: hex(ecdsa_sig),
      payload: hex(ecdsa_payload),
    },
  },
};
console.log(JSON.stringify(out, null, 2));
