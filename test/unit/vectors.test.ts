/**
 * Known-answer test vectors — canonical fixtures for ports.
 * These exact values are published in spec/protocol.md §Test vectors.
 * A port that reproduces them byte-for-byte derives compatible sessions.
 * DO NOT regenerate casually: a change here means a wire-protocol change.
 */
import { describe, it, expect } from "vitest";
import {
  deriveSessionKey,
  computeProof,
  buildHelloTranscript,
  buildReplyTranscript,
  deriveSessionSecret,
  createDecryptor,
  x25519,
  EMPTY_SECRET,
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
