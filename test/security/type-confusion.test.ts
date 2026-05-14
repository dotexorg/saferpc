/**
 * Type confusion via msgpack extension types.
 *
 *   - mpDecode rejects the built-in Timestamp ext (-1) (override registered).
 *   - sanitize rejects ExtData and any other non-plain object.
 *   - End-to-end: a client that forges a TAG_MSG with a Date payload
 *     (encoded via the default codec → ext -1) is dropped by the server;
 *     no handler runs.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import { encode as rawEncode, ExtensionCodec } from "@msgpack/msgpack";
import { xsalsa20poly1305 } from "@noble/ciphers/salsa.js";
import {
  chain,
  client,
  server,
  mpDecode,
  RPCError,
  TAG_MSG,
  NONCE_LEN,
  concatBytes,
  type Router,
} from "../../src/index.ts";
import { createMitmChannelPair } from "../helpers/channels.ts";
import { manualHandshake } from "../helpers/protocol.ts";

describe("security / msgpack ext type rejection at the codec layer", () => {
  it("rejects the built-in Timestamp ext (-1)", () => {
    const blob = rawEncode(new Date(0));
    expect(() => mpDecode(blob)).toThrow(RPCError);
  });

  it("returns ExtData for unregistered ext types (then sanitized away)", () => {
    class Evil {}
    const codec = new ExtensionCodec();
    codec.register({
      type: 0x42,
      encode: (v) => (v instanceof Evil ? new Uint8Array([0xee]) : null),
      decode: () => ({ malicious: true }),
    });
    const blob = rawEncode(new Evil(), { extensionCodec: codec });
    const decoded = mpDecode(blob);
    expect(
      (decoded as { constructor: { name: string } }).constructor.name,
    ).toBe("ExtData");
  });
});

describe("security / type confusion in a live session", () => {
  it("a forged TAG_MSG with a Date input is dropped — no handler runs", async () => {
    const psk = randomBytes(32);
    const { a, b } = createMitmChannelPair();

    let invocations = 0;
    const errors: unknown[] = [];
    const router: Router = {
      ping: chain().handler(async () => {
        invocations++;
        return "pong";
      }),
    };
    const srv = server(router, a, {
      auth: { secret: () => psk },
      onError: (e) => errors.push(e),
    });

    const session = await manualHandshake(b, psk);
    expect(session.proofOk).toBe(true);

    // Encode plaintext with the default codec → emits ext -1 for Date.
    const evilPayload = rawEncode({
      t: 1,
      id: "evil",
      p: "ping",
      i: new Date(0),
    });
    const nonce = randomBytes(NONCE_LEN);
    const ct = xsalsa20poly1305(session.sessionKey, nonce).encrypt(evilPayload);
    const frame = concatBytes(new Uint8Array([TAG_MSG]), nonce, ct);
    await b.send(frame);

    await new Promise((r) => setTimeout(r, 80));
    // Server's decryptor calls mpDecode → throws → silent drop. Zero handlers.
    expect(invocations).toBe(0);

    srv.destroy();
  });
});
