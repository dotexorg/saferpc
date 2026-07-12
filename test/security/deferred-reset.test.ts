/**
 * D1 — deferred reset.
 *
 * A hello opens a handshake ATTEMPT on attempt-local state. The live session
 * keeps serving throughout and is torn down only when the attempt fully
 * validates and publishes. So a garbage or unauthenticated hello injected by
 * a MITM can no longer displace an established session (the pre-0.7.0 server
 * reset unconditionally on every incoming hello, before any validation).
 *
 * Regression signal: under the old behavior these tests re-handshake
 * (helloCount === 2) and/or drop the in-flight call; under D1 the session
 * survives (helloCount === 1).
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  chain,
  client,
  server,
  mpEncode,
  concatBytes,
  x25519,
  createEd25519ClientAuth,
  createEd25519ServerAuth,
  generateEd25519Keypair,
  RPCError,
  type Router,
} from "../../src/index.ts";
import { createMitmChannelPair } from "../helpers/channels.ts";

const clientHellos = (
  captures: Array<{ dir: "AtoB" | "BtoA"; data: Uint8Array }>,
): number =>
  captures.filter((c) => c.dir === "BtoA" && c.data[0] === 0x00).length;

describe("security / D1 deferred reset", () => {
  it("a garbage hello does not displace an established PSK session", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    const errors: RPCError[] = [];
    const router: Router = {
      ping: chain().handler(async () => "pong"),
    };
    const srv = server(router, a, {
      auth: { secret: () => psk },
      onError: (e) => errors.push(e as RPCError),
    });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      expect(await api.ping({})).toBe("pong");
      expect(clientHellos(mitm.state.captures)).toBe(1);

      // Inject a garbage hello straight to the server (bad public key).
      const garbage = mpEncode({
        pub: new Uint8Array(16),
        nonce: randomBytes(32),
        epoch: 1,
      });
      mitm.injectToA(concatBytes(new Uint8Array([0x00]), garbage));
      await new Promise((r) => setTimeout(r, 40));
      expect(errors.some((e) => e.code === "HANDSHAKE")).toBe(true);

      // Session still serves; the client never had to re-handshake.
      expect(await api.ping({})).toBe("pong");
      expect(clientHellos(mitm.state.captures)).toBe(1);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("keeps an in-flight call alive across an injected garbage hello", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    const router: Router = {
      slow: chain().handler(
        async () =>
          new Promise<string>((r) => setTimeout(() => r("done"), 200)),
      ),
      ping: chain().handler(async () => "pong"),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 2000,
    });
    try {
      // Drive the handshake, then start a slow in-flight call.
      expect(await api.ping({})).toBe("pong");
      const inflight = api.slow({});
      await new Promise((r) => setTimeout(r, 20));

      // Attacker injects a garbage hello mid-flight.
      const garbage = mpEncode({
        pub: new Uint8Array(16),
        nonce: randomBytes(32),
        epoch: 2,
      });
      mitm.injectToA(concatBytes(new Uint8Array([0x00]), garbage));

      // The in-flight call still completes — its session was never reset.
      expect(await inflight).toBe("done");
      expect(clientHellos(mitm.state.captures)).toBe(1);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("an unauthenticated hello cannot displace a session when verify is configured", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    const errors: RPCError[] = [];
    const router: Router = {
      ping: chain().handler(async () => "pong"),
    };
    const srv = server(router, a, {
      auth: {
        secret: () => psk,
        ...createEd25519ServerAuth({ getPublicKey: async () => publicKey }),
      },
      onError: (e) => errors.push(e as RPCError),
    });
    const { api, destroy } = client(b, {
      auth: {
        secret: () => psk,
        ...createEd25519ClientAuth({ privateKey, deviceId: "dev-A" }),
      },
      timeout: 1000,
    });
    try {
      expect(await api.ping({})).toBe("pong");
      expect(clientHellos(mitm.state.captures)).toBe(1);

      // Shape-valid hello (real x25519 pub, right sizes) but a bogus auth
      // payload — reaches auth.verify and fails there, AFTER the pre-verify
      // shape checks. Without D1 the session would already be gone by now.
      const attackerPriv = x25519.utils.randomSecretKey();
      const attackerPub = x25519.getPublicKey(attackerPriv);
      const forged = mpEncode({
        pub: attackerPub,
        nonce: randomBytes(32),
        epoch: 1,
        auth: randomBytes(96),
      });
      mitm.injectToA(concatBytes(new Uint8Array([0x00]), forged));
      await new Promise((r) => setTimeout(r, 40));
      expect(errors.length).toBeGreaterThanOrEqual(1);

      // Established session is untouched.
      expect(await api.ping({})).toBe("pong");
      expect(clientHellos(mitm.state.captures)).toBe(1);
    } finally {
      destroy();
      srv.destroy();
    }
  });
});
