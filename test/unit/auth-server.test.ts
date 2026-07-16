/**
 * Unit tests for server-side auth helpers (auth/server.ts).
 *
 * Each helper exposes a `verify(proof, transcript)` function. These tests
 * call it directly with crafted payloads to exercise validation paths,
 * malformed input handling, transcript binding, and the optional gates
 * (validateDevice / validateEntity / validateSubject).
 */
import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { encode as rawEncode, ExtData } from "@msgpack/msgpack";

import {
  createJWTServerAuth,
  createEd25519ServerAuth,
  createECDSAServerAuth,
  createJWTClientAuth,
  createEd25519ClientAuth,
  createECDSAClientAuth,
  generateEd25519Keypair,
  generateECDSAKeypair,
  mpEncode,
  RPCError,
} from "../../src/index.ts";

const transcript = new TextEncoder().encode("server-test-transcript");

// ─── createJWTServerAuth ─────────────────────────────────────

describe("createJWTServerAuth", () => {
  async function makeProof(
    overrides: Partial<{
      jwt: unknown;
      ts: unknown;
      th: unknown;
    }> = {},
    customTranscript: Uint8Array = transcript,
  ): Promise<Uint8Array> {
    return mpEncode({
      v: 1,
      jwt: "jwt-1",
      ts: Date.now(),
      th: sha256(customTranscript),
      ...overrides,
    });
  }

  it("accepts a well-formed proof bound to the transcript", async () => {
    const helper = createJWTServerAuth({
      verifyToken: async (jwt) => (jwt === "jwt-1" ? { sub: "u" } : null),
    });
    const proof = await makeProof();
    const res = await helper.verify!(proof, transcript);
    expect(res).toEqual({ auth: { sub: "u" } });
  });

  it("rejects malformed msgpack payload", async () => {
    const helper = createJWTServerAuth({ verifyToken: async () => ({}) });
    await expect(
      helper.verify!(new Uint8Array([0xff, 0xff, 0xff]), transcript),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("rejects a non-object decoded payload", async () => {
    const helper = createJWTServerAuth({ verifyToken: async () => ({}) });
    await expect(
      helper.verify!(mpEncode("a string"), transcript),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    await expect(
      helper.verify!(mpEncode(42), transcript),
    ).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects an auth payload with an absent or unknown profile version", async () => {
    const helper = createJWTServerAuth({ verifyToken: async () => ({}) });
    // No `v` at all.
    await expect(
      helper.verify!(
        mpEncode({ jwt: "x", ts: Date.now(), th: sha256(transcript) }),
        transcript,
      ),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    // A future/unknown version the verifier was not written for.
    await expect(
      helper.verify!(
        mpEncode({ v: 2, jwt: "x", ts: Date.now(), th: sha256(transcript) }),
        transcript,
      ),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("rejects a missing JWT field", async () => {
    const helper = createJWTServerAuth({ verifyToken: async () => ({}) });
    const proof = mpEncode({
      v: 1,
      ts: Date.now(),
      th: sha256(transcript),
    });
    await expect(helper.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects an empty JWT", async () => {
    const helper = createJWTServerAuth({ verifyToken: async () => ({}) });
    const proof = await makeProof({ jwt: "" });
    await expect(helper.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects a non-string JWT", async () => {
    const helper = createJWTServerAuth({ verifyToken: async () => ({}) });
    const proof = await makeProof({ jwt: 12345 });
    await expect(helper.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects a missing timestamp", async () => {
    const helper = createJWTServerAuth({ verifyToken: async () => ({}) });
    const proof = mpEncode({
      v: 1,
      jwt: "x",
      th: sha256(transcript),
    });
    await expect(helper.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects a non-finite timestamp", async () => {
    const helper = createJWTServerAuth({ verifyToken: async () => ({}) });
    const proof = await makeProof({ ts: Number.NaN });
    await expect(helper.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects a transcript digest of the wrong length", async () => {
    const helper = createJWTServerAuth({ verifyToken: async () => ({}) });
    const proof = await makeProof({ th: new Uint8Array(16) });
    await expect(helper.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects a non-bytes transcript digest", async () => {
    const helper = createJWTServerAuth({ verifyToken: async () => ({}) });
    const proof = await makeProof({ th: "not-bytes" });
    await expect(helper.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects a stale timestamp", async () => {
    const helper = createJWTServerAuth({
      verifyToken: async () => ({ sub: "u" }),
      maxAge: 1_000,
    });
    const proof = await makeProof({ ts: Date.now() - 10_000 });
    await expect(helper.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects a future-dated timestamp (symmetric clock-skew check)", async () => {
    const helper = createJWTServerAuth({
      verifyToken: async () => ({ sub: "u" }),
      maxAge: 1_000,
    });
    const proof = await makeProof({ ts: Date.now() + 60_000 });
    await expect(helper.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects a payload whose digest does not match the transcript", async () => {
    const helper = createJWTServerAuth({ verifyToken: async () => ({}) });
    const wrongTranscript = new TextEncoder().encode("not-the-real-one");
    const proof = await makeProof({}, wrongTranscript);
    await expect(helper.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects when verifyToken returns null/undefined/false", async () => {
    const nullHelper = createJWTServerAuth({ verifyToken: async () => null });
    await expect(
      nullHelper.verify!(await makeProof(), transcript),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    const undefHelper = createJWTServerAuth({
      verifyToken: async () => undefined,
    });
    await expect(
      undefHelper.verify!(await makeProof(), transcript),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("propagates the decoded principal returned by verifyToken", async () => {
    const helper = createJWTServerAuth({
      verifyToken: async () => ({ sub: "u_42", roles: ["admin"] }),
    });
    const res = (await helper.verify!(await makeProof(), transcript)) as {
      auth: Record<string, unknown>;
    };
    expect(res.auth["sub"]).toBe("u_42");
    expect(res.auth["roles"]).toEqual(["admin"]);
  });

  it("interoperates with createJWTClientAuth", async () => {
    const clientHelper = createJWTClientAuth({ getToken: () => "interop" });
    const serverHelper = createJWTServerAuth({
      verifyToken: async (jwt) => (jwt === "interop" ? { ok: true } : null),
    });
    const proof = await clientHelper.sign!(transcript);
    const res = await serverHelper.verify!(proof, transcript);
    expect(res).toEqual({ auth: { ok: true } });
  });
});

// ─── Auth payload sanitization (shared decodeAuthPayload gate) ───
//
// The decode gate is shared by all three server helpers; the JWT helper
// stands in for all of them. Protocol § Sanitization applies to auth
// payloads in full — including fields a profile ignores — so a payload
// smuggling an unknown msgpack ext type or over-deep nesting in an extra
// field must be rejected even when every validated field is well-formed.

describe("auth payload sanitization", () => {
  const validFields = () => ({
    v: 1,
    jwt: "jwt-1",
    ts: Date.now(),
    th: sha256(transcript),
  });
  const helper = () =>
    createJWTServerAuth({ verifyToken: async () => ({ sub: "u" }) });

  it("rejects an unknown msgpack ext type in an ignored extra field", async () => {
    const proof = rawEncode(
      { ...validFields(), extra: new ExtData(42, new Uint8Array([1, 2, 3])) },
      { useBigInt64: true },
    );
    await expect(helper().verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects nesting beyond MAX_DEPTH in an ignored extra field", async () => {
    const deep: Record<string, unknown> = {};
    let cur = deep;
    for (let i = 0; i < 40; i++) {
      const next: Record<string, unknown> = {};
      cur["x"] = next;
      cur = next;
    }
    const proof = rawEncode(
      { ...validFields(), extra: deep },
      { useBigInt64: true },
    );
    await expect(helper().verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("maps a __proto__ map key to UNAUTHORIZED, not an unhandled throw", async () => {
    // The codec itself bans `__proto__` keys (first line of defense;
    // `sanitize` strips constructor/prototype as depth-in-depth). The
    // decode gate must surface that as a clean UNAUTHORIZED.
    const proof = rawEncode(
      { ...validFields(), ["__proto__"]: { polluted: true } },
      { useBigInt64: true },
    );
    await expect(helper().verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
  });
});

// ─── createEd25519ServerAuth ─────────────────────────────────

describe("createEd25519ServerAuth", () => {
  it("accepts a valid signature over the transcript", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const server = createEd25519ServerAuth({
      getPublicKey: async (id) => {
        if (id === "dev-1") return publicKey;
        throw new Error("unknown");
      },
    });
    const client = createEd25519ClientAuth({ privateKey, deviceId: "dev-1" });
    const proof = await client.sign!(transcript);
    const res = await server.verify!(proof, transcript);
    expect(res).toEqual({ auth: { deviceId: "dev-1", verified: true } });
  });

  it("rejects a tampered transcript", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const server = createEd25519ServerAuth({
      getPublicKey: async () => publicKey,
    });
    const client = createEd25519ClientAuth({ privateKey, deviceId: "d" });
    const proof = await client.sign!(transcript);
    const other = new TextEncoder().encode("not-the-signed-transcript");
    await expect(server.verify!(proof, other)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects when validateDevice returns false (before sig check)", async () => {
    const { publicKey } = await generateEd25519Keypair();
    let pubLookups = 0;
    const server = createEd25519ServerAuth({
      getPublicKey: () => {
        pubLookups++;
        return publicKey;
      },
      validateDevice: async () => false,
    });
    const proof = mpEncode({
      v: 1,
      deviceId: "blocked",
      sig: new Uint8Array(64),
    });
    await expect(server.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
    expect(pubLookups).toBe(0);
  });

  it("rejects a missing deviceId", async () => {
    const { publicKey } = await generateEd25519Keypair();
    const server = createEd25519ServerAuth({
      getPublicKey: async () => publicKey,
    });
    const proof = mpEncode({ v: 1, sig: new Uint8Array(64) });
    await expect(server.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects a signature of the wrong length", async () => {
    const { publicKey } = await generateEd25519Keypair();
    const server = createEd25519ServerAuth({
      getPublicKey: async () => publicKey,
    });
    const proof = mpEncode({
      v: 1,
      deviceId: "d",
      sig: new Uint8Array(32), // not 64
    });
    await expect(server.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects a non-bytes signature", async () => {
    const { publicKey } = await generateEd25519Keypair();
    const server = createEd25519ServerAuth({
      getPublicKey: async () => publicKey,
    });
    const proof = mpEncode({ v: 1, deviceId: "d", sig: "not-bytes" });
    await expect(server.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("fails with INTERNAL if getPublicKey() returns an invalid value", async () => {
    const { privateKey } = await generateEd25519Keypair();
    const server = createEd25519ServerAuth({
      // @ts-expect-error — exercise the runtime check
      getPublicKey: async () => "not-a-key",
    });
    const client = createEd25519ClientAuth({ privateKey, deviceId: "d" });
    const proof = await client.sign!(transcript);
    await expect(server.verify!(proof, transcript)).rejects.toMatchObject({
      code: "INTERNAL",
    });
  });

  it("rejects a signature made with the wrong key", async () => {
    const k1 = await generateEd25519Keypair();
    const k2 = await generateEd25519Keypair();
    const server = createEd25519ServerAuth({
      getPublicKey: async () => k2.publicKey, // points to wrong key
    });
    const client = createEd25519ClientAuth({
      privateKey: k1.privateKey,
      deviceId: "d",
    });
    const proof = await client.sign!(transcript);
    await expect(server.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });
});

// ─── createECDSAServerAuth ───────────────────────────────────

describe("createECDSAServerAuth", () => {
  it("accepts a valid ECDSA signature over the transcript", async () => {
    const { privateKey, publicKey } = await generateECDSAKeypair();
    const server = createECDSAServerAuth({
      getPublicKey: async () => publicKey,
    });
    const client = createECDSAClientAuth({ privateKey, identifier: "eA" });
    const proof = await client.sign!(transcript);
    const res = await server.verify!(proof, transcript);
    expect(res).toEqual({ auth: { identifier: "eA", verified: true } });
  });

  it("rejects when validateEntity returns false (before crypto verify)", async () => {
    const { publicKey } = await generateECDSAKeypair();
    let lookups = 0;
    const server = createECDSAServerAuth({
      getPublicKey: () => {
        lookups++;
        return publicKey;
      },
      validateEntity: async () => false,
    });
    const proof = mpEncode({
      v: 1,
      identifier: "blocked",
      sig: new Uint8Array(64),
    });
    await expect(server.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
    expect(lookups).toBe(0);
  });

  it("rejects a missing identifier", async () => {
    const { publicKey } = await generateECDSAKeypair();
    const server = createECDSAServerAuth({
      getPublicKey: async () => publicKey,
    });
    const proof = mpEncode({ v: 1, sig: new Uint8Array(64) });
    await expect(server.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects an empty signature", async () => {
    const { publicKey } = await generateECDSAKeypair();
    const server = createECDSAServerAuth({
      getPublicKey: async () => publicKey,
    });
    const proof = mpEncode({ v: 1, identifier: "e", sig: new Uint8Array(0) });
    await expect(server.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects a signature over a different transcript", async () => {
    const { privateKey, publicKey } = await generateECDSAKeypair();
    const server = createECDSAServerAuth({
      getPublicKey: async () => publicKey,
    });
    const client = createECDSAClientAuth({ privateKey, identifier: "e" });
    const proof = await client.sign!(transcript);
    const other = new TextEncoder().encode("a different transcript");
    await expect(server.verify!(proof, other)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects malformed msgpack payload", async () => {
    const { publicKey } = await generateECDSAKeypair();
    const server = createECDSAServerAuth({
      getPublicKey: async () => publicKey,
    });
    await expect(
      server.verify!(new Uint8Array([0xff]), transcript),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });
});
