/**
 * F-002 regression: x25519 low-order public keys must be rejected.
 *
 * Pins the dependency contract that backs the asymmetric-only-mode
 * forward-secrecy argument in spec/security.md. If a future version of
 * @noble/curves silently accepts a low-order pub (returning zero output
 * instead of throwing), an active MITM can drive both sides to a
 * deterministic session_key derived from HKDF(zeros, EMPTY_PSK, ...) and
 * decrypt the session. The defense is implicit in the dep — this test
 * makes it explicit and CI-checked.
 *
 * Two halves:
 *   1. Library invariant — every known RFC 7748 §6.1 low-order point
 *      causes x25519.getSharedSecret to throw.
 *   2. End-to-end invariant — a forged hello carrying a low-order
 *      `pub` aborts the handshake on the server (no reply, no session).
 *
 * If either half breaks, the finding reopens.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  chain,
  server,
  RPCError,
  TAG_HELLO,
  mpEncode,
  concatBytes,
  x25519,
  type Router,
} from "../../src/index.ts";
import { createMitmChannelPair } from "../helpers/channels.ts";

// RFC 7748 §6.1 small-subgroup elements (little-endian, 32 bytes each).
const LOW_ORDER_POINTS_HEX = [
  // identity / order 1
  "0000000000000000000000000000000000000000000000000000000000000000",
  // order 1
  "0100000000000000000000000000000000000000000000000000000000000000",
  // order 8
  "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
  "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
  // p - 1, p, p + 1 (with high bit ignored per RFC 7748)
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

describe("security / F-002 low-order x25519 pubkey rejection", () => {
  it("getSharedSecret throws for every known low-order point (dep contract)", () => {
    const priv = x25519.utils.randomSecretKey();
    for (const hex of LOW_ORDER_POINTS_HEX) {
      const pub = fromHex(hex);
      expect(
        () => x25519.getSharedSecret(priv, pub),
        `low-order pub ${hex.slice(0, 8)}… must throw`,
      ).toThrow();
    }
  });

  it("server aborts handshake when client hello carries a low-order pub", async () => {
    const psk = randomBytes(32);
    const router: Router = { ping: chain().handler(async () => "pong") };
    const { a, mitm } = createMitmChannelPair();
    const errors: RPCError[] = [];
    const srv = server(router, a, {
      auth: { secret: () => psk },
      onError: (e) => {
        if (e instanceof RPCError) errors.push(e);
      },
    });

    try {
      for (const hex of LOW_ORDER_POINTS_HEX) {
        errors.length = 0;
        mitm.clearCaptures();

        const forged = concatBytes(
          new Uint8Array([TAG_HELLO]),
          mpEncode({
            pub: fromHex(hex),
            nonce: randomBytes(32),
            epoch: 1,
          }),
        );
        mitm.injectToA(forged);

        // Let the server's async handshake path settle.
        await new Promise((r) => setTimeout(r, 30));

        // Server must NOT send a reply: no TAG_HELLO frame leaves the server.
        const replies = mitm.state.captures.filter(
          (c) => c.dir === "AtoB" && c.data[0] === TAG_HELLO,
        );
        expect(
          replies.length,
          `server replied to a low-order-pub hello (${hex.slice(0, 8)}…)`,
        ).toBe(0);

        // Server must surface a HANDSHAKE error via onError.
        expect(
          errors.length,
          `server did not report HANDSHAKE for low-order-pub hello (${hex.slice(0, 8)}…)`,
        ).toBeGreaterThanOrEqual(1);
        expect(errors[0]!.code).toBe("HANDSHAKE");
      }
    } finally {
      srv.destroy();
    }
  });
});
