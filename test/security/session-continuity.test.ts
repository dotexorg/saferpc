/**
 * Session continuity (make-before-break).
 *
 * A validated hello is installed as a CANDIDATE that runs alongside the live
 * session. The live key is retired only when a frame decrypts under the
 * candidate — proof the counterparty holds the key material. Therefore a
 * duplicate/stale hello (bytes the server already processed) can at most
 * create a candidate that expires unconfirmed; it can never retire the live
 * session.
 *
 * This is strictly stronger than D1 (deferred-reset.test.ts), which only
 * proved that an UNVALIDATED (garbage / bad-signature) hello is harmless. The
 * case below replays a BYTE-IDENTICAL VALID hello, which re-verifies and
 * reaches the install step — the exact input that displaced the live session
 * before make-before-break.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  chain,
  client,
  server,
  createEd25519ClientAuth,
  createEd25519ServerAuth,
  generateEd25519Keypair,
  RPCError,
  type Router,
} from "../../src/index.ts";
import { createMitmChannelPair } from "../helpers/channels.ts";

// Client → server hellos are captured on the "BtoA" leg with tag 0x00.
const clientHellos = (
  captures: Array<{ dir: "AtoB" | "BtoA"; data: Uint8Array }>,
): Uint8Array[] =>
  captures
    .filter((c) => c.dir === "BtoA" && c.data[0] === 0x00)
    .map((c) => c.data);

describe("security / session continuity (make-before-break)", () => {
  it("a duplicate VALID PSK hello does not retire the live session", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    const errors: RPCError[] = [];
    const router: Router = { ping: chain().handler(async () => "pong") };
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
      const hellos = clientHellos(mitm.state.captures);
      expect(hellos.length).toBe(1);

      // Replay the exact client hello the server already accepted.
      mitm.injectToA(hellos[0]!.slice());
      await new Promise((r) => setTimeout(r, 40));

      // The live session still serves; the client never re-handshook.
      expect(await api.ping({})).toBe("pong");
      expect(clientHellos(mitm.state.captures).length).toBe(1);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("a duplicate VALID signed hello does not retire the live session", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    const router: Router = { ping: chain().handler(async () => "pong") };
    const srv = server(router, a, {
      auth: {
        secret: () => psk,
        ...createEd25519ServerAuth({ getPublicKey: async () => publicKey }),
      },
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
      const hellos = clientHellos(mitm.state.captures);
      expect(hellos.length).toBe(1);

      // Replay the exact signed hello — it re-verifies, yet must not displace.
      mitm.injectToA(hellos[0]!.slice());
      await new Promise((r) => setTimeout(r, 40));

      expect(await api.ping({})).toBe("pong");
      expect(clientHellos(mitm.state.captures).length).toBe(1);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("a genuine rekey promotes and the FIRST call after it gets a reply", async () => {
    // Regression for the reqEpoch capture-timing bug: promotion advances
    // `epoch` while handling the confirming frame, so reqEpoch must be
    // captured AFTER promotion or this first post-rekey call times out.
    const psk = randomBytes(32);
    const { a, b } = createMitmChannelPair();
    const router: Router = { ping: chain().handler(async () => "pong") };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, abortPending, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      expect(await api.ping({})).toBe("pong");

      // Force the client to drop its session and lazily re-handshake with a
      // fresh ephemeral key on the next call.
      abortPending();

      // The FIRST call after the genuine rekey must resolve, not time out.
      expect(await api.ping({})).toBe("pong");
      // And the session keeps serving afterwards.
      expect(await api.ping({})).toBe("pong");
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("an unconfirmed candidate from a replay expires, leaving the live session intact", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    const errors: RPCError[] = [];
    const router: Router = { ping: chain().handler(async () => "pong") };
    const srv = server(router, a, {
      auth: { secret: () => psk },
      handshakeTimeout: 100,
      onError: (e) => errors.push(e as RPCError),
    });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      expect(await api.ping({})).toBe("pong");
      const hellos = clientHellos(mitm.state.captures);

      // Replay creates a candidate that no one can confirm (the replayer
      // holds no key material). It must expire on the confirmation timer.
      mitm.injectToA(hellos[0]!.slice());
      await new Promise((r) => setTimeout(r, 200));

      // Candidate expiry surfaces as a HANDSHAKE error — proof a candidate
      // was created then dropped — while the live session is untouched.
      expect(errors.some((e) => e.code === "HANDSHAKE")).toBe(true);
      expect(await api.ping({})).toBe("pong");
      expect(clientHellos(mitm.state.captures).length).toBe(1);
    } finally {
      destroy();
      srv.destroy();
    }
  });
});
