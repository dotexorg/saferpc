import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import { validatePSK, KEY_LEN } from "../../src/index.ts";

describe("validatePSK", () => {
  it("accepts a 32-byte PSK", () => {
    expect(() => validatePSK(randomBytes(KEY_LEN))).not.toThrow();
  });

  it("accepts a longer PSK", () => {
    expect(() => validatePSK(randomBytes(KEY_LEN * 2))).not.toThrow();
  });

  it("rejects a PSK shorter than KEY_LEN", () => {
    for (const len of [0, 1, 16, 31]) {
      expect(() => validatePSK(randomBytes(len))).toThrow(TypeError);
    }
  });

  it("rejects non-Uint8Array values", () => {
    expect(() => validatePSK("not-bytes" as unknown as Uint8Array)).toThrow(TypeError);
    expect(() => validatePSK(null as unknown as Uint8Array)).toThrow(TypeError);
    expect(() => validatePSK(undefined as unknown as Uint8Array)).toThrow(TypeError);
    expect(() => validatePSK({} as unknown as Uint8Array)).toThrow(TypeError);
    expect(() => validatePSK(new ArrayBuffer(32) as unknown as Uint8Array)).toThrow(TypeError);
    expect(() => validatePSK([1, 2, 3] as unknown as Uint8Array)).toThrow(TypeError);
  });
});
