/**
 * Malformed response discriminator (Protocol § Request/response framing).
 *
 * The protocol defines exactly two response forms: `ok: true` and
 * `ok: false`. Any other `ok` value is a malformed envelope and MUST be
 * dropped silently — before the pending entry is consumed, so the call
 * keeps waiting for a well-formed response under its own timer. A client
 * that settled on garbage would diverge observably from a strict port
 * (immediate RemoteRPCError vs timeout/drop).
 *
 * The test runs a real client against a hand-rolled server that answers
 * one RPC with a burst of malformed envelopes followed by a valid one:
 * the call must resolve on the valid response, proving the malformed
 * ones did not consume the pending entry.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  client,
  x25519,
  mpDecode,
  deriveSessionKey,
  computeProof,
  createEncryptor,
  createDecryptor,
  concatBytes,
  mpEncode,
  TAG_HELLO,
  TAG_MSG,
  RemoteRPCError,
  type Channel,
} from "../../src/index.ts";
import { createChannelPair } from "../helpers/channels.ts";

interface FakeServer {
  /** Called with each decrypted request; returns envelopes to send back. */
  respond: (req: { id: string; p: string }) => Record<string, unknown>[];
}

/** Minimal protocol-correct server: one session, scripted responses. */
function fakeServer(
  channel: Channel,
  secret: Uint8Array,
  script: FakeServer,
): void {
  let encrypt: ((data: unknown) => Uint8Array) | null = null;
  let decrypt: ((payload: Uint8Array) => unknown) | null = null;

  channel.receive((data) => {
    if (data[0] === TAG_HELLO) {
      const hello = mpDecode(data.subarray(1)) as {
        pub: Uint8Array;
        nonce: Uint8Array;
        epoch: number;
      };
      const priv = x25519.utils.randomSecretKey();
      const pub = x25519.getPublicKey(priv);
      const rawShared = x25519.getSharedSecret(priv, hello.pub);
      const sessionKey = deriveSessionKey(rawShared, secret);
      const proof = computeProof(sessionKey, pub, hello.pub, hello.nonce);
      encrypt = createEncryptor(sessionKey);
      decrypt = createDecryptor(sessionKey);
      const reply = mpEncode({ pub, proof, epoch: hello.epoch });
      void channel.send(concatBytes(new Uint8Array([TAG_HELLO]), reply));
      return;
    }
    if (data[0] === TAG_MSG && decrypt !== null && encrypt !== null) {
      const req = decrypt(data) as { id: string; p: string };
      for (const envelope of script.respond(req)) {
        void channel.send(encrypt(envelope));
      }
    }
  });
}

describe("security / malformed response discriminator", () => {
  it("drops responses whose ok is not strictly boolean; the pending call survives", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();

    fakeServer(a, psk, {
      respond: (req) => [
        // Malformed: each of these must be silently dropped.
        { t: 2, id: req.id, d: "garbage-absent-ok", e: null },
        { t: 2, id: req.id, ok: null, d: "garbage-null", e: null },
        { t: 2, id: req.id, ok: 1, d: "garbage-one", e: null },
        { t: 2, id: req.id, ok: "false", d: null, e: { c: "X", m: "no" } },
        // Malformed outer shapes: required d/e fields and their pairing.
        { t: 2, id: req.id, ok: true, e: null },
        { t: 2, id: req.id, ok: true, d: "wrong", e: {} },
        { t: 2, id: req.id, ok: false, d: "wrong", e: { c: "X" } },
        { t: 2, id: req.id, ok: false, d: null, e: [] },
        // Valid: must still find the pending entry and resolve it.
        { t: 2, id: req.id, ok: true, d: "real-answer", e: null },
      ],
    });

    const { api } = client(b, {
      auth: { secret: () => psk },
      timeout: 2_000,
    });
    const result = await (
      api as { ping: (i: unknown) => Promise<unknown> }
    ).ping({});
    expect(result).toBe("real-answer");
  });

  it("ok: false still settles as RemoteRPCError (failure form untouched)", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();

    fakeServer(a, psk, {
      respond: (req) => [
        { t: 2, id: req.id, ok: false, d: null, e: { c: "BOOM", m: "nope" } },
      ],
    });

    const { api } = client(b, {
      auth: { secret: () => psk },
      timeout: 2_000,
    });
    await expect(
      (api as { ping: (i: unknown) => Promise<unknown> }).ping({}),
    ).rejects.toMatchObject({
      constructor: RemoteRPCError,
      code: "BOOM",
      message: "nope",
    });
  });
});
