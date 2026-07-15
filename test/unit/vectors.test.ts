/**
 * Known-answer test vectors — canonical fixtures for ports.
 * These exact values are published in spec/protocol.md §Test vectors.
 * A port that reproduces them byte-for-byte derives compatible sessions.
 * DO NOT regenerate casually: a change here means a wire-protocol change.
 */
import { describe, it, expect } from "vitest";
import { sha256 } from "@noble/hashes/sha2.js";

import {
  deriveSessionKey,
  computeProof,
  buildHelloTranscript,
  buildReplyTranscript,
  deriveSessionSecret,
  createDecryptor,
  x25519,
  EMPTY_SECRET,
  mpEncode,
  createEd25519ClientAuth,
  createJWTServerAuth,
  createEd25519ServerAuth,
  createECDSAServerAuth,
} from "../../src/index.ts";

const h = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fromHex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const pat = (start: number, len = 32) =>
  new Uint8Array(Array.from({ length: len }, (_, i) => (start + i) & 0xff));

describe("KAT vectors match src implementation", () => {
  const c_priv = pat(0x01);
  const s_priv = pat(0x41);
  const c_nonce = pat(0x81);
  const secret = pat(0xc1);

  const c_pub = x25519.getPublicKey(c_priv);
  const s_pub = x25519.getPublicKey(s_priv);
  const raw = x25519.getSharedSecret(c_priv, s_pub);
  const sk = deriveSessionKey(raw, secret);

  it("pubs / shared / keys / proof", () => {
    expect(h(c_pub)).toBe(
      "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c",
    );
    expect(h(s_pub)).toBe(
      "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466",
    );
    expect(h(raw)).toBe(
      "26c2c17fdb82161cb21ad16e721315355b64d1763119b10bfc962530dc7cc163",
    );
    expect(h(sk)).toBe(
      "26cfff1fd363520e6adc49c5f0647197d6bf84063ba7d977be53abe5a09e4df1",
    );
    expect(
      h(deriveSessionKey(x25519.getSharedSecret(s_priv, c_pub), EMPTY_SECRET)),
    ).toBe("09f21f20ea6205029a057330916649c6d92ca421067b2249358a4f7d8d79ba68");
    expect(h(computeProof(sk, s_pub, c_pub, c_nonce))).toBe(
      "1d55f7b3d9eda8cb8a30a269197139afe10fd4557f426698513de175a41cd0b3",
    );
  });

  it("transcripts", () => {
    expect(h(buildHelloTranscript(1, c_pub, c_nonce))).toBe(
      "736166657270632d68732d68656c6c6f2d7631000000000107a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c8182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0",
    );
    expect(h(buildReplyTranscript(1, c_pub, c_nonce, s_pub))).toBe(
      "736166657270632d68732d7265706c792d7631000000000107a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c8182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa064b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466",
    );
  });

  it("deriveSessionSecret", () => {
    expect(h(deriveSessionSecret("session-abc123", secret))).toBe(
      "e90487157dafebc492bf80cb1b0dc9818b220ee2fbbce3304ed4fc0a181e02db",
    );
  });

  it("encrypted frame decrypts via createDecryptor", () => {
    const frame = fromHex(
      "011112131415161718191a1b1c1d1e1f202122232425262728d6305197fd685b58024ba4e38d269a78d4afe8373d476fe52d04f1d3ed9aa51e",
    );
    const decrypt = createDecryptor(
      deriveSessionKey(x25519.getSharedSecret(c_priv, s_pub), pat(0xc1)),
    );
    const msg = decrypt(frame) as Record<string, unknown>;
    expect(msg["t"]).toBe(1);
    expect(msg["id"]).toBe("1");
    expect(msg["p"]).toBe("ping");
  });
});

describe("KAT vectors — auth profile payloads", () => {
  // All profiles bind to the hello transcript from the main vector set.
  const c_priv = pat(0x01);
  const c_nonce = pat(0x81);
  const c_pub = x25519.getPublicKey(c_priv);
  const transcript = buildHelloTranscript(1, c_pub, c_nonce);

  it("jwt profile: payload bytes + verifies through createJWTServerAuth", async () => {
    const payload = mpEncode({
      v: 1,
      jwt: "test.jwt.token",
      ts: 1700000000000, // travels as msgpack float64 — see spec §msgpack profile
      th: sha256(transcript),
    });
    expect(h(payload)).toBe(
      "84a17601a36a7774ae746573742e6a77742e746f6b656ea27473cb4278bcfe56800000a27468c420c76c6aaff8ac6c00e1168ffdafc87255a79eef052a4a7b39c542506a81010c9e",
    );
    const server = createJWTServerAuth({
      verifyToken: async (t) =>
        t === "test.jwt.token" ? { sub: "vector" } : null,
      maxAge: 1e13, // vector ts is fixed in the past; finite skew large enough forever
    });
    const res = (await server.verify!(payload, transcript)) as {
      auth: { sub: string };
    };
    expect(res.auth.sub).toBe("vector");
  });

  it("ed25519 profile: helper reproduces payload bytes (RFC 8032 deterministic) + verifies", async () => {
    const seed = pat(0x61);
    const payload = await createEd25519ClientAuth({
      privateKey: seed,
      deviceId: "device-1",
    }).sign!(transcript);
    expect(h(payload)).toBe(
      "83a17601a86465766963654964a86465766963652d31a3736967c440c056e0893556d73576ab05fa9ef2314d16686f326905c3e1e1f0b2b10eb003f51a6a41aa2d1e14f737fdfeede47d7ecec84380d7e70733cd3579653db72c7105",
    );
    const server = createEd25519ServerAuth({
      getPublicKey: async () =>
        fromHex(
          "882d0ea3b2864e7a587f3e698cea4459998312e655e05fa5e8b5119d8baac8cd",
        ),
    });
    const res = (await server.verify!(payload, transcript)) as {
      auth: { deviceId: string; verified: boolean };
    };
    expect(res.auth.deviceId).toBe("device-1");
    expect(res.auth.verified).toBe(true);
  });

  it("ecdsa profile: pinned RFC 6979 payload verifies through createECDSAServerAuth", async () => {
    // WebCrypto signing is randomized; the KAT signature is the deterministic
    // RFC 6979 lowS one. Byte-reproduction requires a deterministic signer;
    // the normative check is that this payload VERIFIES against the pinned key.
    const payload = fromHex(
      "83a17601aa6964656e746966696572a8656e746974792d31a3736967c440383ae1bc960796f9ae710ffa7dc73cc8bdb7522567e0f5b2180f4a74cac0f68a00bea85c160d745e881050a72bdb9fbb4a03a2aba4c65dcf29c29dc319796b01",
    );
    // Envelope construction is still byte-exact given the sig:
    expect(
      h(
        mpEncode({
          v: 1,
          identifier: "entity-1",
          sig: fromHex(
            "383ae1bc960796f9ae710ffa7dc73cc8bdb7522567e0f5b2180f4a74cac0f68a00bea85c160d745e881050a72bdb9fbb4a03a2aba4c65dcf29c29dc319796b01",
          ),
        }),
      ),
    ).toBe(h(payload));
    const publicKey = await crypto.subtle.importKey(
      "raw",
      fromHex(
        "04ad137f7ef829eef8a8571bf4d307664ea8e024e05bda4e26da8f7ae884456058a88e48c9a1d9386471f13f2559758edc4bc1e11394eb415d63e2d33e4d38519d",
      ),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const server = createECDSAServerAuth({
      getPublicKey: async () => publicKey,
    });
    const res = (await server.verify!(payload, transcript)) as {
      auth: { identifier: string; verified: boolean };
    };
    expect(res.auth.identifier).toBe("entity-1");
    expect(res.auth.verified).toBe(true);
  });
});
