/**
 * Unit tests for the secret-side of auth:
 *   - `deriveSessionSecret` — HKDF-derived per-session secret
 *   - `isEmptySecret` — recognise the all-zero sentinel
 *   - `validateAuthConfig` — at least one of secret / asymmetric auth must be configured
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";

import {
  deriveSessionSecret,
  isEmptySecret,
  validateAuthConfig,
  EMPTY_SECRET,
  KEY_LEN,
} from "../../src/index.ts";

// ─── deriveSessionSecret ─────────────────────────────────────────

describe("deriveSessionSecret", () => {
  it("returns a 32-byte secret", () => {
    const secret = deriveSessionSecret("session-abc", randomBytes(32));
    expect(secret).toBeInstanceOf(Uint8Array);
    expect(secret.length).toBe(KEY_LEN);
  });

  it("is deterministic for the same (sessionId, secret) pair", () => {
    const secret = randomBytes(32);
    const a = deriveSessionSecret("s-1", secret);
    const b = deriveSessionSecret("s-1", secret);
    expect(Array.from(a)).toEqual(Array.from(b));
  });

  it("differs when the sessionId differs (same secret)", () => {
    const secret = randomBytes(32);
    const a = deriveSessionSecret("s-1", secret);
    const b = deriveSessionSecret("s-2", secret);
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  it("differs when the secret differs (same sessionId)", () => {
    const a = deriveSessionSecret("s", randomBytes(32));
    const b = deriveSessionSecret("s", randomBytes(32));
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  it("accepts secrets longer than KEY_LEN", () => {
    const secret = deriveSessionSecret("s", randomBytes(64));
    expect(secret.length).toBe(KEY_LEN);
  });

  it("rejects an empty sessionId", () => {
    expect(() => deriveSessionSecret("", randomBytes(32))).toThrow(TypeError);
  });

  it("rejects a non-string sessionId", () => {
    expect(() =>
      // @ts-expect-error — deliberately bad shape
      deriveSessionSecret(123, randomBytes(32)),
    ).toThrow(TypeError);
    expect(() =>
      // @ts-expect-error — deliberately bad shape
      deriveSessionSecret(null, randomBytes(32)),
    ).toThrow(TypeError);
  });

  it("rejects a secret shorter than KEY_LEN", () => {
    for (const len of [0, 1, 16, 31]) {
      expect(() => deriveSessionSecret("s", randomBytes(len))).toThrow(
        TypeError,
      );
    }
  });

  it("rejects a non-Uint8Array secret", () => {
    expect(() =>
      // @ts-expect-error — deliberately bad shape
      deriveSessionSecret("s", "secret-string"),
    ).toThrow(TypeError);
    expect(() =>
      // @ts-expect-error — deliberately bad shape
      deriveSessionSecret("s", null),
    ).toThrow(TypeError);
  });

  it("derived secret is never the all-zero sentinel for non-trivial inputs", () => {
    const secret = deriveSessionSecret("session-x", randomBytes(32));
    expect(isEmptySecret(secret)).toBe(false);
  });
});

// ─── isEmptySecret ──────────────────────────────────────────────

describe("isEmptySecret", () => {
  it("returns true for a 32-byte all-zero buffer", () => {
    expect(isEmptySecret(new Uint8Array(KEY_LEN))).toBe(true);
    expect(isEmptySecret(EMPTY_SECRET)).toBe(true);
  });

  it("returns false for a 32-byte buffer with any non-zero byte", () => {
    const buf = new Uint8Array(KEY_LEN);
    buf[17] = 1;
    expect(isEmptySecret(buf)).toBe(false);
  });

  it("returns false for wrong-length buffers regardless of contents", () => {
    expect(isEmptySecret(new Uint8Array(0))).toBe(false);
    expect(isEmptySecret(new Uint8Array(16))).toBe(false);
    expect(isEmptySecret(new Uint8Array(64))).toBe(false);
  });
});

// ─── validateAuthConfig ──────────────────────────────────────

describe("validateAuthConfig", () => {
  it("accepts a secret-only config", () => {
    expect(() =>
      validateAuthConfig({ secret: () => new Uint8Array(KEY_LEN) }),
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

  it("accepts a defense-in-depth config (secret + sign + verify)", () => {
    expect(() =>
      validateAuthConfig({
        secret: () => new Uint8Array(KEY_LEN),
        sign: async () => new Uint8Array([1]),
        verify: async () => undefined,
      }),
    ).not.toThrow();
  });

  it("rejects an empty config (neither secret nor asymmetric)", () => {
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
        secret: "not-a-fn",
      }),
    ).toThrow(TypeError);
  });
});
