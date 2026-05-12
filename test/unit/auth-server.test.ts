/**
 * Unit tests for server-side auth helpers (authServer.ts).
 *
 * Each helper exposes a `verify(proof, transcript)` function. These tests
 * call it directly with crafted payloads to exercise validation paths,
 * malformed input handling, transcript binding, and the optional gates
 * (validateDevice / validateEntity / validateSubject).
 */
import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";

import {
  createJWTServerAuth,
  createEd25519ServerAuth,
  createECDSAServerAuth,
  createCertificateServerAuth,
  createMultifactorServerAuth,
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

// ─── createCertificateServerAuth ─────────────────────────────

describe("createCertificateServerAuth", () => {
  /**
   * Build a happy-path config: verifyCertificate trusts any cert whose
   * first byte is 0xAA and returns the given signing key as the bound
   * subject key. Tests can override subject / pub on demand.
   */
  function mkConfig(opts: {
    publicKey: CryptoKey;
    subject?: Record<string, string>;
    validateSubject?: (subject: Record<string, string>) => boolean;
  }) {
    return {
      verifyCertificate: async (certBytes: Uint8Array) => {
        if (certBytes[0] !== 0xaa) throw new Error("bad cert chain");
        return {
          subject: opts.subject ?? { cn: "alice@example.com" },
          publicKey: opts.publicKey,
        };
      },
      validateSubject: opts.validateSubject,
    };
  }

  async function signOver(
    transcriptBytes: Uint8Array,
    key: CryptoKey,
  ): Promise<Uint8Array> {
    const sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      transcriptBytes as BufferSource,
    );
    return new Uint8Array(sig);
  }

  it("accepts a valid cert + transcript signature", async () => {
    const { privateKey, publicKey } = await generateECDSAKeypair();
    const server = createCertificateServerAuth(mkConfig({ publicKey }));
    const proof = mpEncode({
      cert: new Uint8Array([0xaa, 0xbb, 0xcc]),
      sig: await signOver(transcript, privateKey),
    });
    const res = (await server.verify!(proof, transcript)) as {
      auth: { subject: Record<string, string>; verified: boolean };
    };
    expect(res.auth.verified).toBe(true);
    expect(res.auth.subject.cn).toBe("alice@example.com");
  });

  it("rejects a missing cert", async () => {
    const { publicKey } = await generateECDSAKeypair();
    const server = createCertificateServerAuth(mkConfig({ publicKey }));
    const proof = mpEncode({ sig: new Uint8Array(64) });
    await expect(server.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects an empty cert", async () => {
    const { publicKey } = await generateECDSAKeypair();
    const server = createCertificateServerAuth(mkConfig({ publicKey }));
    const proof = mpEncode({
      cert: new Uint8Array(0),
      sig: new Uint8Array(64),
    });
    await expect(server.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects a missing signature", async () => {
    const { publicKey } = await generateECDSAKeypair();
    const server = createCertificateServerAuth(mkConfig({ publicKey }));
    const proof = mpEncode({ cert: new Uint8Array([0xaa]) });
    await expect(server.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("propagates verifyCertificate failures", async () => {
    const { privateKey, publicKey } = await generateECDSAKeypair();
    const server = createCertificateServerAuth(mkConfig({ publicKey }));
    const proof = mpEncode({
      cert: new Uint8Array([0x00]), // first byte ≠ 0xAA → verifyCertificate throws
      sig: await signOver(transcript, privateKey),
    });
    await expect(server.verify!(proof, transcript)).rejects.toThrow(
      /bad cert chain/,
    );
  });

  it("rejects when validateSubject returns false", async () => {
    const { privateKey, publicKey } = await generateECDSAKeypair();
    const server = createCertificateServerAuth(
      mkConfig({
        publicKey,
        subject: { cn: "denied@example.com" },
        validateSubject: (s) => s["cn"] === "alice@example.com",
      }),
    );
    const proof = mpEncode({
      cert: new Uint8Array([0xaa]),
      sig: await signOver(transcript, privateKey),
    });
    await expect(server.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects a signature that does not match the certificate's public key", async () => {
    const wrongKey = await generateECDSAKeypair();
    const certKey = await generateECDSAKeypair();
    // Server says "this cert binds wrongKey.publicKey" but client signs with certKey.privateKey.
    const server = createCertificateServerAuth(
      mkConfig({ publicKey: wrongKey.publicKey }),
    );
    const proof = mpEncode({
      cert: new Uint8Array([0xaa]),
      sig: await signOver(transcript, certKey.privateKey),
    });
    await expect(server.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects a signature over a different transcript (replay across handshakes)", async () => {
    const { privateKey, publicKey } = await generateECDSAKeypair();
    const server = createCertificateServerAuth(mkConfig({ publicKey }));
    const proof = mpEncode({
      cert: new Uint8Array([0xaa]),
      sig: await signOver(transcript, privateKey),
    });
    const other = new TextEncoder().encode("another-handshake-transcript");
    await expect(server.verify!(proof, other)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });
});

// ─── createMultifactorServerAuth ─────────────────────────────

describe("createMultifactorServerAuth", () => {
  it("merges both factors' auth into one (default combine)", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const primary = createJWTServerAuth({
      verifyToken: async (jwt) =>
        jwt === "tok" ? { sub: "u", role: "user" } : null,
    });
    const secondary = createEd25519ServerAuth({
      getPublicKey: async () => publicKey,
    });

    const mfa = createMultifactorServerAuth({ primary, secondary });

    const jwtPayload = await createJWTClientAuth({ getToken: () => "tok" })
      .sign!(transcript);
    const sigPayload = await createEd25519ClientAuth({
      privateKey,
      deviceId: "dev",
    }).sign!(transcript);

    const proof = mpEncode({ primary: jwtPayload, secondary: sigPayload });
    const res = (await mfa.verify!(proof, transcript)) as {
      auth: Record<string, unknown>;
    };
    expect(res.auth["sub"]).toBe("u");
    expect(res.auth["role"]).toBe("user");
    expect(res.auth["deviceId"]).toBe("dev");
    expect(res.auth["verified"]).toBe(true);
    expect(res.auth["multifactor"]).toBe(true);
  });

  it("uses combineAuth when provided", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const primary = createJWTServerAuth({
      verifyToken: async () => ({ sub: "u" }),
    });
    const secondary = createEd25519ServerAuth({
      getPublicKey: async () => publicKey,
    });
    const mfa = createMultifactorServerAuth({
      primary,
      secondary,
      combineAuth: (p, s) => ({
        principal: (p as { sub: string }).sub,
        device: (s as { deviceId: string }).deviceId,
        mfa: "2fa-strong",
      }),
    });

    const jwtPayload = await createJWTClientAuth({ getToken: () => "x" }).sign!(
      transcript,
    );
    const sigPayload = await createEd25519ClientAuth({
      privateKey,
      deviceId: "dev-mfa",
    }).sign!(transcript);
    const proof = mpEncode({ primary: jwtPayload, secondary: sigPayload });

    const res = (await mfa.verify!(proof, transcript)) as {
      auth: Record<string, unknown>;
    };
    expect(res.auth["principal"]).toBe("u");
    expect(res.auth["device"]).toBe("dev-mfa");
    expect(res.auth["mfa"]).toBe("2fa-strong");
    // combineAuth replaces the default merge — `multifactor: true` must NOT be auto-added
    expect(res.auth["multifactor"]).toBeUndefined();
  });

  it("constructor rejects non-function primary/secondary verify", () => {
    expect(() =>
      createMultifactorServerAuth({
        primary: {},
        secondary: { verify: () => undefined },
      }),
    ).toThrow(TypeError);
    expect(() =>
      createMultifactorServerAuth({
        primary: { verify: () => undefined },
        // @ts-expect-error — deliberately bad shape
        secondary: { verify: "nope" },
      }),
    ).toThrow(TypeError);
  });

  it("rejects when primary factor bytes are missing", async () => {
    const primary = { verify: async () => ({ auth: {} }) };
    const secondary = { verify: async () => ({ auth: {} }) };
    const mfa = createMultifactorServerAuth({ primary, secondary });
    const proof = mpEncode({ secondary: new Uint8Array([1, 2, 3]) });
    await expect(mfa.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects when secondary factor bytes are missing", async () => {
    const primary = { verify: async () => ({ auth: {} }) };
    const secondary = { verify: async () => ({ auth: {} }) };
    const mfa = createMultifactorServerAuth({ primary, secondary });
    const proof = mpEncode({ primary: new Uint8Array([1, 2, 3]) });
    await expect(mfa.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects when either factor is empty bytes", async () => {
    const primary = { verify: async () => ({ auth: {} }) };
    const secondary = { verify: async () => ({ auth: {} }) };
    const mfa = createMultifactorServerAuth({ primary, secondary });

    const proofA = mpEncode({
      primary: new Uint8Array(0),
      secondary: new Uint8Array([1]),
    });
    await expect(mfa.verify!(proofA, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });

    const proofB = mpEncode({
      primary: new Uint8Array([1]),
      secondary: new Uint8Array(0),
    });
    await expect(mfa.verify!(proofB, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects if the primary verifier throws (and does not call secondary)", async () => {
    let secondaryCalls = 0;
    const primary = {
      verify: async () => {
        throw new RPCError("UNAUTHORIZED", "bad primary");
      },
    };
    const secondary = {
      verify: async () => {
        secondaryCalls++;
        return { auth: {} };
      },
    };
    const mfa = createMultifactorServerAuth({ primary, secondary });
    const proof = mpEncode({
      primary: new Uint8Array([1]),
      secondary: new Uint8Array([2]),
    });
    await expect(mfa.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
    expect(secondaryCalls).toBe(0);
  });

  it("rejects if the secondary verifier throws (after primary OK)", async () => {
    const primary = { verify: async () => ({ auth: { sub: "u" } }) };
    const secondary = {
      verify: async () => {
        throw new RPCError("UNAUTHORIZED", "bad secondary");
      },
    };
    const mfa = createMultifactorServerAuth({ primary, secondary });
    const proof = mpEncode({
      primary: new Uint8Array([1]),
      secondary: new Uint8Array([2]),
    });
    await expect(mfa.verify!(proof, transcript)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("forwards the *same* transcript bytes to both verifiers", async () => {
    let pTr: Uint8Array | null = null;
    let sTr: Uint8Array | null = null;
    const primary = {
      verify: async (_proof: Uint8Array, t: Uint8Array) => {
        pTr = t;
        return { auth: {} };
      },
    };
    const secondary = {
      verify: async (_proof: Uint8Array, t: Uint8Array) => {
        sTr = t;
        return { auth: {} };
      },
    };
    const mfa = createMultifactorServerAuth({ primary, secondary });
    const proof = mpEncode({
      primary: new Uint8Array([1]),
      secondary: new Uint8Array([2]),
    });
    await mfa.verify!(proof, transcript);
    expect(pTr).not.toBeNull();
    expect(sTr).not.toBeNull();
    expect(Array.from(pTr!)).toEqual(Array.from(transcript));
    expect(Array.from(sTr!)).toEqual(Array.from(transcript));
  });
});
