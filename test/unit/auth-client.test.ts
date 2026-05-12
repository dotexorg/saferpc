/**
 * Unit tests for client-side auth helpers (authClient.ts).
 *
 * These exercise the sign() return shape directly without spinning up a
 * server: each helper must produce a msgpack-encoded payload that decodes
 * to the expected schema. Helpers also reject obviously bad inputs at
 * construction time.
 */
import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";

import {
  createJWTClientAuth,
  createEd25519ClientAuth,
  createECDSAClientAuth,
  generateEd25519Keypair,
  generateECDSAKeypair,
  mpDecode,
  RPCError,
} from "../../src/index.ts";

const transcript = new TextEncoder().encode("test-transcript-bytes");

// ─── createJWTClientAuth ─────────────────────────────────────

describe("createJWTClientAuth", () => {
  it("returns a sign() that emits a msgpack payload binding token + transcript", async () => {
    const before = Date.now();
    const helper = createJWTClientAuth({ getToken: () => "tok-1" });
    const out = await helper.sign!(transcript);
    const after = Date.now();

    expect(out).toBeInstanceOf(Uint8Array);
    const decoded = mpDecode(out) as {
      v: number;
      jwt: string;
      ts: number;
      th: Uint8Array;
    };
    expect(decoded.v).toBe(1);
    expect(decoded.jwt).toBe("tok-1");
    expect(typeof decoded.ts).toBe("number");
    expect(decoded.ts).toBeGreaterThanOrEqual(before);
    expect(decoded.ts).toBeLessThanOrEqual(after);
    expect(decoded.th).toBeInstanceOf(Uint8Array);
    expect(Array.from(decoded.th)).toEqual(Array.from(sha256(transcript)));
  });

  it("supports async getToken()", async () => {
    const helper = createJWTClientAuth({
      getToken: async () => {
        await Promise.resolve();
        return "async-tok";
      },
    });
    const out = await helper.sign!(transcript);
    const decoded = mpDecode(out) as { jwt: string };
    expect(decoded.jwt).toBe("async-tok");
  });

  it("throws UNAUTHORIZED when getToken() returns null", async () => {
    const helper = createJWTClientAuth({ getToken: () => null });
    await expect(helper.sign!(transcript)).rejects.toBeInstanceOf(RPCError);
    await expect(helper.sign!(transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("throws UNAUTHORIZED when getToken() returns undefined", async () => {
    const helper = createJWTClientAuth({ getToken: () => undefined });
    await expect(helper.sign!(transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("throws UNAUTHORIZED when getToken() returns an empty string", async () => {
    const helper = createJWTClientAuth({ getToken: () => "" });
    await expect(helper.sign!(transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("throws UNAUTHORIZED when getToken() returns a non-string value", async () => {
    const helper = createJWTClientAuth({
      // @ts-expect-error — deliberately bad shape, exercising the runtime guard
      getToken: () => 12345,
    });
    await expect(helper.sign!(transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("binds the digest to *this* transcript (different bytes → different th)", async () => {
    const helper = createJWTClientAuth({ getToken: () => "t" });
    const a = mpDecode(await helper.sign!(new Uint8Array([1, 2, 3]))) as {
      th: Uint8Array;
    };
    const b = mpDecode(await helper.sign!(new Uint8Array([4, 5, 6]))) as {
      th: Uint8Array;
    };
    expect(Array.from(a.th)).not.toEqual(Array.from(b.th));
  });
});

// ─── createEd25519ClientAuth ─────────────────────────────────

describe("createEd25519ClientAuth", () => {
  it("returns a sign() that produces a verifiable Ed25519 signature", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const helper = createEd25519ClientAuth({
      privateKey,
      deviceId: "device-A",
    });
    const out = await helper.sign!(transcript);
    const decoded = mpDecode(out) as {
      v: number;
      deviceId: string;
      sig: Uint8Array;
    };
    expect(decoded.v).toBe(1);
    expect(decoded.deviceId).toBe("device-A");
    expect(decoded.sig).toBeInstanceOf(Uint8Array);
    expect(decoded.sig.length).toBe(64);
    expect(ed25519.verify(decoded.sig, transcript, publicKey)).toBe(true);
  });

  it("rejects a private key that is not a 32-byte Uint8Array", () => {
    expect(() =>
      createEd25519ClientAuth({
        privateKey: new Uint8Array(16),
        deviceId: "x",
      }),
    ).toThrow(TypeError);
    expect(() =>
      createEd25519ClientAuth({
        // @ts-expect-error — deliberately bad shape
        privateKey: "not-bytes",
        deviceId: "x",
      }),
    ).toThrow(TypeError);
  });

  it("rejects an empty / non-string deviceId", async () => {
    const { privateKey } = await generateEd25519Keypair();
    expect(() => createEd25519ClientAuth({ privateKey, deviceId: "" })).toThrow(
      TypeError,
    );
    expect(() =>
      // @ts-expect-error — deliberately bad shape
      createEd25519ClientAuth({ privateKey, deviceId: 42 }),
    ).toThrow(TypeError);
  });

  it("signs each transcript distinctly (Ed25519 is deterministic per key+msg)", async () => {
    const { privateKey } = await generateEd25519Keypair();
    const helper = createEd25519ClientAuth({ privateKey, deviceId: "d" });
    const a = mpDecode(await helper.sign!(new Uint8Array([1]))) as {
      sig: Uint8Array;
    };
    const b = mpDecode(await helper.sign!(new Uint8Array([2]))) as {
      sig: Uint8Array;
    };
    expect(Array.from(a.sig)).not.toEqual(Array.from(b.sig));
  });
});

// ─── createECDSAClientAuth ───────────────────────────────────

describe("createECDSAClientAuth", () => {
  it("returns a sign() that produces a verifiable ECDSA signature", async () => {
    const { privateKey, publicKey } = await generateECDSAKeypair();
    const helper = createECDSAClientAuth({
      privateKey,
      identifier: "entity-A",
    });
    const out = await helper.sign!(transcript);
    const decoded = mpDecode(out) as {
      v: number;
      identifier: string;
      sig: Uint8Array;
    };
    expect(decoded.v).toBe(1);
    expect(decoded.identifier).toBe("entity-A");
    expect(decoded.sig).toBeInstanceOf(Uint8Array);
    expect(decoded.sig.length).toBeGreaterThan(0);

    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      decoded.sig as BufferSource,
      transcript as BufferSource,
    );
    expect(ok).toBe(true);
  });

  it("rejects an empty identifier at construction time", async () => {
    const { privateKey } = await generateECDSAKeypair();
    expect(() => createECDSAClientAuth({ privateKey, identifier: "" })).toThrow(
      TypeError,
    );
    expect(() =>
      // @ts-expect-error — deliberately bad shape
      createECDSAClientAuth({ privateKey, identifier: null }),
    ).toThrow(TypeError);
  });

  it("ECDSA signatures over the same input differ between calls (random k)", async () => {
    const { privateKey } = await generateECDSAKeypair();
    const helper = createECDSAClientAuth({ privateKey, identifier: "e" });
    const a = mpDecode(await helper.sign!(transcript)) as { sig: Uint8Array };
    const b = mpDecode(await helper.sign!(transcript)) as { sig: Uint8Array };
    expect(Array.from(a.sig)).not.toEqual(Array.from(b.sig));
  });
});

// ─── Keypair generators ──────────────────────────────────────

describe("generateEd25519Keypair", () => {
  it("returns 32-byte private and public keys", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    expect(privateKey).toBeInstanceOf(Uint8Array);
    expect(publicKey).toBeInstanceOf(Uint8Array);
    expect(privateKey.length).toBe(32);
    expect(publicKey.length).toBe(32);
  });

  it("produces a fresh keypair each call", async () => {
    const k1 = await generateEd25519Keypair();
    const k2 = await generateEd25519Keypair();
    expect(Array.from(k1.privateKey)).not.toEqual(Array.from(k2.privateKey));
    expect(Array.from(k1.publicKey)).not.toEqual(Array.from(k2.publicKey));
  });

  it("returns a publicKey that matches the privateKey (sign+verify)", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const msg = new TextEncoder().encode("hello");
    const sig = ed25519.sign(msg, privateKey);
    expect(ed25519.verify(sig, msg, publicKey)).toBe(true);
  });
});

describe("generateECDSAKeypair", () => {
  it("returns a non-extractable ECDSA P-256 keypair", async () => {
    const { privateKey, publicKey } = await generateECDSAKeypair();
    expect(privateKey).toBeDefined();
    expect(publicKey).toBeDefined();
    expect(privateKey.type).toBe("private");
    expect(publicKey.type).toBe("public");
    expect(privateKey.algorithm.name).toBe("ECDSA");
    expect(privateKey.extractable).toBe(false);
    expect(privateKey.usages).toContain("sign");
    expect(publicKey.usages).toContain("verify");
  });

  it("private keys cannot be exported (non-extractable)", async () => {
    const { privateKey } = await generateECDSAKeypair();
    await expect(
      crypto.subtle.exportKey("pkcs8", privateKey),
    ).rejects.toThrow();
  });
});
