import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import { deriveSessionKey, computeProof, KEY_LEN } from "../../src/index.ts";

describe("deriveSessionKey", () => {
  it("produces a deterministic 32-byte key for the same inputs", () => {
    const shared = randomBytes(32);
    const psk = randomBytes(32);
    const k1 = deriveSessionKey(shared, psk);
    const k2 = deriveSessionKey(shared, psk);
    expect(k1.length).toBe(KEY_LEN);
    expect(Array.from(k1)).toEqual(Array.from(k2));
  });

  it("differs when the PSK differs (same shared)", () => {
    const shared = randomBytes(32);
    const k1 = deriveSessionKey(shared, randomBytes(32));
    const k2 = deriveSessionKey(shared, randomBytes(32));
    expect(k1.some((v, i) => v !== k2[i])).toBe(true);
  });

  it("differs when the shared secret differs (same PSK)", () => {
    const psk = randomBytes(32);
    const k1 = deriveSessionKey(randomBytes(32), psk);
    const k2 = deriveSessionKey(randomBytes(32), psk);
    expect(k1.some((v, i) => v !== k2[i])).toBe(true);
  });

  it("returns 32 bytes regardless of input length", () => {
    const shared = randomBytes(64);
    const psk = randomBytes(64);
    expect(deriveSessionKey(shared, psk).length).toBe(KEY_LEN);
  });
});

describe("computeProof", () => {
  it("produces a deterministic 32-byte proof for the same inputs", () => {
    const sk = randomBytes(32);
    const sPub = randomBytes(32);
    const cPub = randomBytes(32);
    const nonce = randomBytes(32);
    const a = computeProof(sk, sPub, cPub, nonce);
    const b = computeProof(sk, sPub, cPub, nonce);
    expect(a.length).toBe(32);
    expect(Array.from(a)).toEqual(Array.from(b));
  });

  it("changes when any input changes", () => {
    const sk = randomBytes(32);
    const sPub = randomBytes(32);
    const cPub = randomBytes(32);
    const nonce = randomBytes(32);
    const base = computeProof(sk, sPub, cPub, nonce);

    const differs = (other: Uint8Array): boolean =>
      base.some((v, i) => v !== other[i]);

    expect(differs(computeProof(randomBytes(32), sPub, cPub, nonce))).toBe(true);
    expect(differs(computeProof(sk, randomBytes(32), cPub, nonce))).toBe(true);
    expect(differs(computeProof(sk, sPub, randomBytes(32), nonce))).toBe(true);
    expect(differs(computeProof(sk, sPub, cPub, randomBytes(32)))).toBe(true);
  });

  it("is order-sensitive (HMAC over concatenation, not commutative)", () => {
    const sk = randomBytes(32);
    const a = randomBytes(32);
    const b = randomBytes(32);
    const nonce = randomBytes(32);
    const ab = computeProof(sk, a, b, nonce);
    const ba = computeProof(sk, b, a, nonce);
    expect(ab.some((v, i) => v !== ba[i])).toBe(true);
  });
});
