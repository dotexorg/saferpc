import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  createEncryptor,
  createDecryptor,
  KEY_LEN,
  NONCE_LEN,
  TAG_MSG,
} from "../../src/index.ts";

describe("createEncryptor / createDecryptor", () => {
  it("roundtrips plain objects (decryptor returns null-prototype copy)", () => {
    const key = randomBytes(KEY_LEN);
    const enc = createEncryptor(key);
    const dec = createDecryptor(key);
    const data = { method: "greet", args: ["world"] };
    const out = dec(enc(data)) as { method: string; args: string[] };
    expect(out.method).toBe("greet");
    expect(out.args).toEqual(["world"]);
    expect(Object.getPrototypeOf(out)).toBeNull();
  });

  it("roundtrips Uint8Array fields intact", () => {
    const key = randomBytes(KEY_LEN);
    const enc = createEncryptor(key);
    const dec = createDecryptor(key);
    const blob = new Uint8Array(2048);
    for (let i = 0; i < blob.length; i++) blob[i] = i & 0xff;
    const expected = Array.from(blob);
    const out = dec(enc({ blob })) as { blob: Uint8Array };
    expect(out.blob).toBeInstanceOf(Uint8Array);
    expect(Array.from(out.blob)).toEqual(expected);
  });

  it("emits TAG_MSG as the first byte", () => {
    const enc = createEncryptor(randomBytes(KEY_LEN));
    const ct = enc({ x: 1 });
    expect(ct[0]).toBe(TAG_MSG);
  });

  it("places a NONCE_LEN nonce after the tag", () => {
    const enc = createEncryptor(randomBytes(KEY_LEN));
    const ct = enc({ x: 1 });
    expect(ct.length).toBeGreaterThan(1 + NONCE_LEN);
  });

  it("produces different ciphertexts for the same plaintext (random nonce)", () => {
    const enc = createEncryptor(randomBytes(KEY_LEN));
    const a = enc({ x: 1 });
    const b = enc({ x: 1 });
    expect(a.length).toBe(b.length);
    let differs = false;
    for (let i = 0; i < a.length; i++)
      if (a[i] !== b[i]) {
        differs = true;
        break;
      }
    expect(differs).toBe(true);
  });

  it("fails to decrypt with the wrong key", () => {
    const enc = createEncryptor(randomBytes(KEY_LEN));
    const dec = createDecryptor(randomBytes(KEY_LEN));
    expect(() => dec(enc({ x: 1 }))).toThrow();
  });

  it("fails to decrypt a tampered ciphertext (bit flip in body)", () => {
    const key = randomBytes(KEY_LEN);
    const enc = createEncryptor(key);
    const dec = createDecryptor(key);
    const ct = enc({ x: 1 });
    const tampered = ct.slice();
    tampered[ct.length - 1] = (tampered[ct.length - 1]! ^ 0xff) & 0xff;
    expect(() => dec(tampered)).toThrow();
  });

  it("fails to decrypt with a tampered nonce", () => {
    const key = randomBytes(KEY_LEN);
    const enc = createEncryptor(key);
    const dec = createDecryptor(key);
    const ct = enc({ x: 1 });
    const tampered = ct.slice();
    tampered[1] = (tampered[1]! ^ 0x01) & 0xff;
    expect(() => dec(tampered)).toThrow();
  });

  it("fails to decrypt a truncated ciphertext", () => {
    const key = randomBytes(KEY_LEN);
    const enc = createEncryptor(key);
    const dec = createDecryptor(key);
    const ct = enc({ x: 1 });
    expect(() => dec(ct.slice(0, ct.length - 1))).toThrow();
  });
});
