/**
 * End-to-end integration tests for each auth helper.
 *
 * Each auth mode is exercised through a real handshake:
 *   - server + client constructed with the helper
 *   - one RPC call drives the handshake to completion
 *   - context returned by `verify` (if any) is reachable from the handler
 *
 * Negative cases exercise rejection paths: wrong key, blocked entity, etc.
 * Existing helper-level transcript-binding tests live in
 * `jwt-transcript-binding.test.ts`; this file focuses on the wire path.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";

import {
  chain,
  client,
  server,
  RPCError,
  mpEncode,
  createJWTClientAuth,
  createJWTServerAuth,
  createEd25519ClientAuth,
  createEd25519ServerAuth,
  createECDSAClientAuth,
  createECDSAServerAuth,
  createCertificateServerAuth,
  createMultifactorServerAuth,
  generateEd25519Keypair,
  generateECDSAKeypair,
  deriveSessionSecret,
  type Router,
  type Ctx,
} from "../../src/index.ts";
import { createChannelPair } from "../helpers/channels.ts";

const router: Router = {
  whoami: chain().handler(async ({ ctx }) => ctx),
  ping: chain().handler(async () => "pong"),
};

// ─── JWT ─────────────────────────────────────────────────────

describe("auth integration / JWT", () => {
  it("completes a handshake and exposes verified principal as ctx", async () => {
    const { a, b } = createChannelPair();
    const psk = randomBytes(32);
    const srv = server(router, a, {
      auth: {
        secret: () => psk,
        ...createJWTServerAuth({
          verifyToken: async (jwt) =>
            jwt === "good" ? { sub: "u_1", role: "admin" } : null,
        }),
      },
      onError: (e) => {
        throw e;
      },
    });
    const { api, destroy } = client<typeof router>(b, {
      auth: {
        secret: () => psk,
        ...createJWTClientAuth({ getToken: () => "good" }),
      },
    });

    const me = (await api["whoami"]!(undefined)) as {
      sub?: string;
      role?: string;
    };
    expect(me.sub).toBe("u_1");
    expect(me.role).toBe("admin");

    destroy();
    srv.destroy();
  });

  it("rejects the handshake when verifyToken refuses the token", async () => {
    const { a, b } = createChannelPair();
    const psk = randomBytes(32);
    const errors: RPCError[] = [];
    const srv = server(router, a, {
      auth: {
        secret: () => psk,
        ...createJWTServerAuth({ verifyToken: async () => null }),
      },
      onError: (e) => errors.push(e as RPCError),
    });
    const { api, destroy } = client<typeof router>(b, {
      auth: {
        secret: () => psk,
        ...createJWTClientAuth({ getToken: () => "bad" }),
      },
      timeout: 800,
      handshakeTimeout: 400,
    });

    await expect(api["ping"]!(undefined)).rejects.toBeInstanceOf(RPCError);
    expect(errors.some((e) => e.code === "UNAUTHORIZED")).toBe(true);

    destroy();
    srv.destroy();
  });
});

// ─── Ed25519 ─────────────────────────────────────────────────

describe("auth integration / Ed25519", () => {
  it("completes a handshake and surfaces deviceId in ctx", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const { a, b } = createChannelPair();
    const psk = randomBytes(32);

    const srv = server(router, a, {
      auth: {
        secret: () => psk,
        ...createEd25519ServerAuth({
          getPublicKey: async (id) => {
            if (id === "dev-A") return publicKey;
            throw new Error("unknown device");
          },
        }),
      },
      onError: (e) => {
        throw e;
      },
    });
    const { api, destroy } = client<typeof router>(b, {
      auth: {
        secret: () => psk,
        ...createEd25519ClientAuth({ privateKey, deviceId: "dev-A" }),
      },
    });

    const me = (await api["whoami"]!(undefined)) as Ctx;
    expect(me["deviceId"]).toBe("dev-A");
    expect(me["verified"]).toBe(true);

    destroy();
    srv.destroy();
  });

  it("rejects when validateDevice gates the device out", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const { a, b } = createChannelPair();
    const psk = randomBytes(32);
    const errors: RPCError[] = [];

    const srv = server(router, a, {
      auth: {
        secret: () => psk,
        ...createEd25519ServerAuth({
          getPublicKey: async () => publicKey,
          validateDevice: async () => false,
        }),
      },
      onError: (e) => errors.push(e as RPCError),
    });
    const { api, destroy } = client<typeof router>(b, {
      auth: {
        secret: () => psk,
        ...createEd25519ClientAuth({ privateKey, deviceId: "blocked" }),
      },
      timeout: 800,
      handshakeTimeout: 400,
    });

    await expect(api["ping"]!(undefined)).rejects.toBeInstanceOf(RPCError);
    expect(errors.some((e) => e.code === "UNAUTHORIZED")).toBe(true);

    destroy();
    srv.destroy();
  });

  it("rejects when the client signs with the wrong key", async () => {
    const honest = await generateEd25519Keypair();
    const attacker = await generateEd25519Keypair();
    const { a, b } = createChannelPair();
    const psk = randomBytes(32);
    const errors: RPCError[] = [];

    const srv = server(router, a, {
      auth: {
        secret: () => psk,
        ...createEd25519ServerAuth({
          getPublicKey: async () => honest.publicKey,
        }),
      },
      onError: (e) => errors.push(e as RPCError),
    });
    const { api, destroy } = client<typeof router>(b, {
      auth: {
        secret: () => psk,
        ...createEd25519ClientAuth({
          privateKey: attacker.privateKey,
          deviceId: "spoofed",
        }),
      },
      timeout: 800,
      handshakeTimeout: 400,
    });

    await expect(api["ping"]!(undefined)).rejects.toBeInstanceOf(RPCError);
    expect(errors.some((e) => e.code === "UNAUTHORIZED")).toBe(true);

    destroy();
    srv.destroy();
  });
});

// ─── ECDSA ───────────────────────────────────────────────────

describe("auth integration / ECDSA", () => {
  it("completes a handshake using a non-extractable WebCrypto keypair", async () => {
    const { privateKey, publicKey } = await generateECDSAKeypair();
    const { a, b } = createChannelPair();
    const psk = randomBytes(32);

    const srv = server(router, a, {
      auth: {
        secret: () => psk,
        ...createECDSAServerAuth({ getPublicKey: async () => publicKey }),
      },
      onError: (e) => {
        throw e;
      },
    });
    const { api, destroy } = client<typeof router>(b, {
      auth: {
        secret: () => psk,
        ...createECDSAClientAuth({ privateKey, identifier: "entity-1" }),
      },
    });

    const me = (await api["whoami"]!(undefined)) as Ctx;
    expect(me["identifier"]).toBe("entity-1");
    expect(me["verified"]).toBe(true);

    destroy();
    srv.destroy();
  });

  it("rejects when validateEntity blocks the identifier", async () => {
    const { privateKey, publicKey } = await generateECDSAKeypair();
    const { a, b } = createChannelPair();
    const psk = randomBytes(32);
    const errors: RPCError[] = [];

    const srv = server(router, a, {
      auth: {
        secret: () => psk,
        ...createECDSAServerAuth({
          getPublicKey: async () => publicKey,
          validateEntity: async () => false,
        }),
      },
      onError: (e) => errors.push(e as RPCError),
    });
    const { api, destroy } = client<typeof router>(b, {
      auth: {
        secret: () => psk,
        ...createECDSAClientAuth({ privateKey, identifier: "denied" }),
      },
      timeout: 800,
      handshakeTimeout: 400,
    });

    await expect(api["ping"]!(undefined)).rejects.toBeInstanceOf(RPCError);
    expect(errors.some((e) => e.code === "UNAUTHORIZED")).toBe(true);

    destroy();
    srv.destroy();
  });
});

// ─── Certificate ─────────────────────────────────────────────

describe("auth integration / Certificate", () => {
  it("completes a handshake when cert + transcript signature verify", async () => {
    const { privateKey, publicKey } = await generateECDSAKeypair();
    const { a, b } = createChannelPair();
    const psk = randomBytes(32);

    const srv = server(router, a, {
      auth: {
        secret: () => psk,
        ...createCertificateServerAuth({
          verifyCertificate: async (cert) => {
            if (cert[0] !== 0xaa) throw new Error("bad cert");
            return { subject: { cn: "alice" }, publicKey };
          },
        }),
      },
      onError: (e) => {
        throw e;
      },
    });

    // No client helper for certs — application supplies its own `sign`.
    const cert = new Uint8Array([0xaa, 0xbb, 0xcc]);
    const { api, destroy } = client<typeof router>(b, {
      auth: {
        secret: () => psk,
        sign: async (transcript) => {
          const sig = new Uint8Array(
            await crypto.subtle.sign(
              { name: "ECDSA", hash: "SHA-256" },
              privateKey,
              transcript as BufferSource,
            ),
          );
          return mpEncode({ cert, sig });
        },
      },
    });

    const me = (await api["whoami"]!(undefined)) as {
      subject?: { cn?: string };
      verified?: boolean;
    };
    expect(me.subject?.cn).toBe("alice");
    expect(me.verified).toBe(true);

    destroy();
    srv.destroy();
  });

  it("rejects when validateSubject denies the subject", async () => {
    const { privateKey, publicKey } = await generateECDSAKeypair();
    const { a, b } = createChannelPair();
    const psk = randomBytes(32);
    const errors: RPCError[] = [];

    const srv = server(router, a, {
      auth: {
        secret: () => psk,
        ...createCertificateServerAuth({
          verifyCertificate: async () => ({
            subject: { cn: "mallory" },
            publicKey,
          }),
          validateSubject: (s) => s["cn"] === "alice",
        }),
      },
      onError: (e) => errors.push(e as RPCError),
    });

    const { api, destroy } = client<typeof router>(b, {
      auth: {
        secret: () => psk,
        sign: async (transcript) => {
          const sig = new Uint8Array(
            await crypto.subtle.sign(
              { name: "ECDSA", hash: "SHA-256" },
              privateKey,
              transcript as BufferSource,
            ),
          );
          return mpEncode({ cert: new Uint8Array([0xaa]), sig });
        },
      },
      timeout: 800,
      handshakeTimeout: 400,
    });

    await expect(api["ping"]!(undefined)).rejects.toBeInstanceOf(RPCError);
    expect(errors.some((e) => e.code === "UNAUTHORIZED")).toBe(true);

    destroy();
    srv.destroy();
  });
});

// ─── Secret-only / session-derived secret ──────────────────────────

describe("auth integration / secret", () => {
  it("completes a handshake using a static shared secret", async () => {
    const { a, b } = createChannelPair();
    const psk = randomBytes(32);
    const srv = server(router, a, {
      auth: { secret: () => psk },
      onError: (e) => {
        throw e;
      },
    });
    const { api, destroy } = client<typeof router>(b, {
      auth: { secret: () => psk },
    });

    expect(await api["ping"]!(undefined)).toBe("pong");

    destroy();
    srv.destroy();
  });

  it("rejects an all-zero secret at handshake time (user error guard)", async () => {
    const { a, b } = createChannelPair();
    const errors: RPCError[] = [];
    const srv = server(router, a, {
      auth: { secret: () => new Uint8Array(32) }, // all zeros
      onError: (e) => errors.push(e as RPCError),
    });
    const { api, destroy } = client<typeof router>(b, {
      auth: { secret: () => new Uint8Array(32) },
      timeout: 800,
      handshakeTimeout: 400,
    });

    await expect(api["ping"]!(undefined)).rejects.toBeInstanceOf(RPCError);
    expect(errors.some((e) => e.code === "HANDSHAKE")).toBe(true);

    destroy();
    srv.destroy();
  });

  it("succeeds when both sides derive the secret from the same session ID", async () => {
    const secret = randomBytes(32);
    const sessionId = "session-2025-05-12";
    const { a, b } = createChannelPair();

    const srv = server(router, a, {
      auth: { secret: () => deriveSessionSecret(sessionId, secret) },
      onError: (e) => {
        throw e;
      },
    });
    const { api, destroy } = client<typeof router>(b, {
      auth: { secret: () => deriveSessionSecret(sessionId, secret) },
    });

    expect(await api["ping"]!(undefined)).toBe("pong");

    destroy();
    srv.destroy();
  });

  it("fails when the two sides derive from different session IDs (secret mismatch)", async () => {
    const secret = randomBytes(32);
    const { a, b } = createChannelPair();
    const errors: RPCError[] = [];

    const srv = server(router, a, {
      auth: { secret: () => deriveSessionSecret("session-A", secret) },
      onError: (e) => errors.push(e as RPCError),
    });
    const { api, destroy } = client<typeof router>(b, {
      auth: { secret: () => deriveSessionSecret("session-B", secret) },
      timeout: 800,
      handshakeTimeout: 400,
    });

    await expect(api["ping"]!(undefined)).rejects.toBeInstanceOf(RPCError);

    destroy();
    srv.destroy();
  });
});

// ─── Multifactor (JWT × Ed25519) ─────────────────────────────

describe("auth integration / Multifactor", () => {
  it("requires both factors to succeed; merges both principals into ctx", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const { a, b } = createChannelPair();
    const psk = randomBytes(32);

    const jwtServer = createJWTServerAuth({
      verifyToken: async (jwt) => (jwt === "tok" ? { sub: "u" } : null),
    });
    const edServer = createEd25519ServerAuth({
      getPublicKey: async () => publicKey,
    });

    const srv = server(router, a, {
      auth: {
        secret: () => psk,
        ...createMultifactorServerAuth({
          primary: jwtServer,
          secondary: edServer,
        }),
      },
      onError: (e) => {
        throw e;
      },
    });

    const jwtClient = createJWTClientAuth({ getToken: () => "tok" });
    const edClient = createEd25519ClientAuth({ privateKey, deviceId: "dev" });

    const { api, destroy } = client<typeof router>(b, {
      auth: {
        secret: () => psk,
        sign: async (transcript) => {
          const [primary, secondary] = await Promise.all([
            jwtClient.sign!(transcript),
            edClient.sign!(transcript),
          ]);
          return mpEncode({ primary, secondary });
        },
      },
    });

    const me = (await api["whoami"]!(undefined)) as Ctx;
    expect(me["sub"]).toBe("u");
    expect(me["deviceId"]).toBe("dev");
    expect(me["verified"]).toBe(true);
    expect(me["multifactor"]).toBe(true);

    destroy();
    srv.destroy();
  });

  it("rejects when the secondary factor fails (primary succeeds)", async () => {
    const honest = await generateEd25519Keypair();
    const attacker = await generateEd25519Keypair();
    const { a, b } = createChannelPair();
    const psk = randomBytes(32);
    const errors: RPCError[] = [];

    const srv = server(router, a, {
      auth: {
        secret: () => psk,
        ...createMultifactorServerAuth({
          primary: createJWTServerAuth({
            verifyToken: async () => ({ sub: "u" }),
          }),
          secondary: createEd25519ServerAuth({
            getPublicKey: async () => honest.publicKey,
          }),
        }),
      },
      onError: (e) => errors.push(e as RPCError),
    });

    const jwtClient = createJWTClientAuth({ getToken: () => "tok" });
    // Attacker forges with the wrong device key — secondary verify fails.
    const edClient = createEd25519ClientAuth({
      privateKey: attacker.privateKey,
      deviceId: "spoofed",
    });

    const { api, destroy } = client<typeof router>(b, {
      auth: {
        secret: () => psk,
        sign: async (transcript) => {
          const [primary, secondary] = await Promise.all([
            jwtClient.sign!(transcript),
            edClient.sign!(transcript),
          ]);
          return mpEncode({ primary, secondary });
        },
      },
      timeout: 800,
      handshakeTimeout: 400,
    });

    await expect(api["ping"]!(undefined)).rejects.toBeInstanceOf(RPCError);
    expect(errors.some((e) => e.code === "UNAUTHORIZED")).toBe(true);

    destroy();
    srv.destroy();
  });
});
