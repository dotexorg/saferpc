import { describe, it, expect } from "vitest";
import { sha256 } from "@noble/hashes/sha2.js";

import {
  chain,
  client,
  createJWTClientAuth,
  createJWTServerAuth,
  mpEncode,
  RPCError,
  server,
  type Router,
} from "../../src/index.ts";
import { createChannelPair } from "../helpers/channels.ts";

const router: Router = {
  whoami: chain().handler(async ({ ctx }) => ctx),
};

describe("JWT auth helper", () => {
  it("validates a fresh JWT bound to this handshake", async () => {
    const { a, b } = createChannelPair();
    const srv = server(router, a, {
      auth: {
        ...createJWTServerAuth({
          verifyToken: async (jwt) =>
            jwt === "good-jwt" ? { sub: "u_1" } : null,
        }),
      },
      onError: (e) => {
        throw e;
      },
    });
    const { api, destroy } = client<typeof router>(b, {
      auth: { ...createJWTClientAuth({ getToken: () => "good-jwt" }) },
    });

    const me = (await api["whoami"]!(undefined)) as { sub?: string };
    expect(me.sub).toBe("u_1");

    destroy();
    srv.destroy();
  });

  it("rejects a future-dated timestamp (forged signing function)", async () => {
    const { a, b } = createChannelPair();
    let lastError: RPCError | null = null;
    const srv = server(router, a, {
      auth: {
        ...createJWTServerAuth({
          verifyToken: async () => ({ sub: "u_1" }),
          maxAge: 5_000,
        }),
      },
      onError: (e) => {
        if (e instanceof RPCError) lastError = e;
      },
    });

    const { api, destroy } = client<typeof router>(b, {
      auth: {
        sign: async (transcript) =>
          mpEncode({
            v: 1,
            jwt: "good-jwt",
            ts: Date.now() + 60 * 60 * 1000, // 1 hour in the future
            th: sha256(transcript),
          }),
      },
    });

    await expect(api["whoami"]!(undefined)).rejects.toBeInstanceOf(RPCError);
    expect(lastError).not.toBeNull();
    expect(lastError!.code).toBe("UNAUTHORIZED");

    destroy();
    srv.destroy();
  });

  it("rejects a payload with a tampered transcript hash", async () => {
    const { a, b } = createChannelPair();
    let lastError: RPCError | null = null;
    const srv = server(router, a, {
      auth: {
        ...createJWTServerAuth({
          verifyToken: async () => ({ sub: "u_1" }),
        }),
      },
      onError: (e) => {
        if (e instanceof RPCError) lastError = e;
      },
    });

    const { api, destroy } = client<typeof router>(b, {
      auth: {
        sign: async () =>
          mpEncode({
            v: 1,
            jwt: "good-jwt",
            ts: Date.now(),
            th: new Uint8Array(32), // all-zero — does not match real transcript
          }),
      },
    });

    await expect(api["whoami"]!(undefined)).rejects.toBeInstanceOf(RPCError);
    expect(lastError).not.toBeNull();
    expect(lastError!.code).toBe("UNAUTHORIZED");

    destroy();
    srv.destroy();
  });
});
