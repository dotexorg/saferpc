/**
 * Unit tests for the PSK-side of auth:
 *   - `deriveSessionPSK` — HKDF-derived per-session PSK
 *   - `isEmptyPsk` — recognise the all-zero sentinel
 *   - `validateAuthConfig` — at least one of PSK / asymmetric auth must be configured
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";

import {
  deriveSessionPSK,
  isEmptyPsk,
  validateAuthConfig,
  EMPTY_PSK,
  KEY_LEN,
} from "../../src/index.ts";

// ─── deriveSessionPSK ─────────────────────────────────────────

describe("deriveSessionPSK", () => {
  it("returns a 32-byte PSK", () => {
    const psk = deriveSessionPSK("session-abc", randomBytes(32));
    expect(psk).toBeInstanceOf(Uint8Array);
    expect(psk.length).toBe(KEY_LEN);
  });

  it("is deterministic for the same (sessionId, secret) pair", () => {
    const secret = randomBytes(32);
    const a = deriveSessionPSK("s-1", secret);
    const b = deriveSessionPSK("s-1", secret);
    expect(Array.from(a)).toEqual(Array.from(b));
  });

  it("differs when the sessionId differs (same secret)", () => {
    const secret = randomBytes(32);
    const a = deriveSessionPSK("s-1", secret);
    const b = deriveSessionPSK("s-2", secret);
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  it("differs when the secret differs (same sessionId)", () => {
    const a = deriveSessionPSK("s", randomBytes(32));
    const b = deriveSessionPSK("s", randomBytes(32));
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  it("accepts secrets longer than KEY_LEN", () => {
    const psk = deriveSessionPSK("s", randomBytes(64));
    expect(psk.length).toBe(KEY_LEN);
  });

  it("rejects an empty sessionId", () => {
    expect(() => deriveSessionPSK("", randomBytes(32))).toThrow(TypeError);
  });

  it("rejects a non-string sessionId", () => {
    expect(() =>
      // @ts-expect-error — deliberately bad shape
      deriveSessionPSK(123, randomBytes(32)),
    ).toThrow(TypeError);
    expect(() =>
      // @ts-expect-error — deliberately bad shape
      deriveSessionPSK(null, randomBytes(32)),
    ).toThrow(TypeError);
  });

  it("rejects a secret shorter than KEY_LEN", () => {
    for (const len of [0, 1, 16, 31]) {
      expect(() => deriveSessionPSK("s", randomBytes(len))).toThrow(TypeError);
    }
  });

  it("rejects a non-Uint8Array secret", () => {
    expect(() =>
      // @ts-expect-error — deliberately bad shape
      deriveSessionPSK("s", "secret-string"),
    ).toThrow(TypeError);
    expect(() =>
      // @ts-expect-error — deliberately bad shape
      deriveSessionPSK("s", null),
    ).toThrow(TypeError);
  });

  it("derived PSK is never the all-zero sentinel for non-trivial inputs", () => {
    const psk = deriveSessionPSK("session-x", randomBytes(32));
    expect(isEmptyPsk(psk)).toBe(false);
  });
});

// ─── isEmptyPsk ──────────────────────────────────────────────

describe("isEmptyPsk", () => {
  it("returns true for a 32-byte all-zero buffer", () => {
    expect(isEmptyPsk(new Uint8Array(KEY_LEN))).toBe(true);
    expect(isEmptyPsk(EMPTY_PSK)).toBe(true);
  });

  it("returns false for a 32-byte buffer with any non-zero byte", () => {
    const buf = new Uint8Array(KEY_LEN);
    buf[17] = 1;
    expect(isEmptyPsk(buf)).toBe(false);
  });

  it("returns false for wrong-length buffers regardless of contents", () => {
    expect(isEmptyPsk(new Uint8Array(0))).toBe(false);
    expect(isEmptyPsk(new Uint8Array(16))).toBe(false);
    expect(isEmptyPsk(new Uint8Array(64))).toBe(false);
  });
});

// ─── validateAuthConfig ──────────────────────────────────────

describe("validateAuthConfig", () => {
  it("accepts a PSK-only config", () => {
    expect(() =>
      validateAuthConfig({ psk: () => new Uint8Array(KEY_LEN) }),
    ).not.toThrow();
  });

  it("accepts a sign-only config (client-side asymmetric auth)", () => {
    expect(() =>
      validateAuthConfig({ sign: async () => new Uint8Array([1]) }),
    ).not.toThrow();
  });

  it("accepts a verify-only config (server-side asymmetric auth)", () => {
    expect(() =>
      validateAuthConfig({ verify: async () => undefined }),
    ).not.toThrow();
  });

  it("accepts a defense-in-depth config (PSK + sign + verify)", () => {
    expect(() =>
      validateAuthConfig({
        psk: () => new Uint8Array(KEY_LEN),
        sign: async () => new Uint8Array([1]),
        verify: async () => undefined,
      }),
    ).not.toThrow();
  });

  it("rejects an empty config (neither PSK nor asymmetric)", () => {
    expect(() => validateAuthConfig({})).toThrow(TypeError);
  });

  it("rejects a null / non-object config", () => {
    expect(() =>
      // @ts-expect-error — deliberately bad shape
      validateAuthConfig(null),
    ).toThrow(TypeError);
    expect(() =>
      // @ts-expect-error — deliberately bad shape
      validateAuthConfig("not-an-object"),
    ).toThrow(TypeError);
  });

  it("rejects non-function fields", () => {
    expect(() =>
      validateAuthConfig({
        // @ts-expect-error — deliberately bad shape
        psk: "not-a-fn",
      }),
    ).toThrow(TypeError);
  });
});
