/**
 * Server-identity / handshake-proof attacks.
 *
 *   - A MITM (or rogue server without the PSK) cannot produce a valid HMAC
 *     proof, so the client's handshake fails.
 *   - A single-byte-off proof is rejected (constant-time comparison).
 *   - A reply with a wrong-sized public key is rejected.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  chain,
  client,
  server,
  RPCError,
  mpEncode,
  mpDecode,
  concatBytes,
  TAG_HELLO,
  KEY_LEN,
  x25519,
  type Router,
} from "../../src/index.ts";
import {
  createMitmChannelPair,
  createChannelPair,
} from "../helpers/channels.ts";

describe("security / handshake proof", () => {
  it("rejects a hello reply with a forged proof", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    const errors: unknown[] = [];
    const srv = server(
      { ping: chain().handler(async () => "pong") } as Router,
      a,
      { auth: { psk: () => psk }, onError: (e) => errors.push(e) },
    );

    mitm.transformAtoB((data) => {
      if (data[0] !== TAG_HELLO) return data;
      const decoded = mpDecode(data.subarray(1)) as {
        pub: Uint8Array;
        proof: Uint8Array;
        epoch: number;
      };
      const tamperedProof = decoded.proof.slice();
      tamperedProof[0] = (tamperedProof[0]! ^ 0x01) & 0xff;
      const reEncoded = mpEncode({
        pub: decoded.pub,
        proof: tamperedProof,
        epoch: decoded.epoch,
      });
      return concatBytes(new Uint8Array([TAG_HELLO]), reEncoded);
    });

    const { api, destroy } = client(b, {
      auth: { psk: () => psk },
      timeout: 600,
      handshakeTimeout: 400,
    });
    try {
      try {
        await api.ping({});
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RPCError);
        const code = (err as RPCError).code;
        expect(["HANDSHAKE", "TIMEOUT", "SESSION"]).toContain(code);
      }
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("rogue server (no PSK knowledge) cannot complete the handshake", async () => {
    const { a, b } = createChannelPair();
    const unsubscribe = a.receive(async (data) => {
      if (data[0] !== TAG_HELLO) return;
      const fakePriv = x25519.utils.randomSecretKey();
      const fakePub = x25519.getPublicKey(fakePriv);
      const decoded = mpDecode(data.subarray(1)) as { epoch: number };
      const reply = mpEncode({
        pub: fakePub,
        proof: randomBytes(32),
        epoch: decoded.epoch,
      });
      await a.send(concatBytes(new Uint8Array([TAG_HELLO]), reply));
    });

    const { api, destroy } = client(b, {
      auth: { psk: () => randomBytes(32) },
      timeout: 600,
      handshakeTimeout: 400,
    });
    try {
      try {
        await api.ping({});
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RPCError);
        const code = (err as RPCError).code;
        expect(["HANDSHAKE", "TIMEOUT", "SESSION"]).toContain(code);
      }
    } finally {
      destroy();
      unsubscribe();
    }
  });

  it("rejects a hello reply with a wrong-sized public key", async () => {
    const psk = randomBytes(32);
    const { a, b, mitm } = createMitmChannelPair();
    const srv = server(
      { ping: chain().handler(async () => "pong") } as Router,
      a,
      { auth: { psk: () => psk } },
    );

    mitm.transformAtoB((data) => {
      if (data[0] !== TAG_HELLO) return data;
      const decoded = mpDecode(data.subarray(1)) as {
        pub: Uint8Array;
        proof: Uint8Array;
        epoch: number;
      };
      const reply = mpEncode({
        pub: decoded.pub.slice(0, KEY_LEN - 1),
        proof: decoded.proof,
        epoch: decoded.epoch,
      });
      return concatBytes(new Uint8Array([TAG_HELLO]), reply);
    });

    const { api, destroy } = client(b, {
      auth: { psk: () => psk },
      timeout: 600,
      handshakeTimeout: 400,
    });
    try {
      try {
        await api.ping({});
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(RPCError);
        const code = (err as RPCError).code;
        expect(["HANDSHAKE", "TIMEOUT", "SESSION"]).toContain(code);
      }
    } finally {
      destroy();
      srv.destroy();
    }
  });
});
