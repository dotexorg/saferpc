/** Regression coverage for authenticated malformed-frame replay bounds and response framing limits. */
import { describe, expect, it, vi } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  chain,
  client,
  server,
  type Channel,
  type Router,
} from "../../src/index.ts";
import * as common from "../../src/common.ts";
import { createChannelPair } from "../helpers/channels.ts";
import { encryptRaw, manualHandshake } from "../helpers/protocol.ts";

function countSends(ch: Channel): { ch: Channel; sends: () => number } {
  let count = 0;
  return {
    ch: {
      send(data) {
        count++;
        return ch.send(data);
      },
      receive: (cb) => ch.receive(cb),
    },
    sends: () => count,
  };
}

describe("security / authenticated malformed frames", () => {
  it("records the nonce before a duplicate can repeat decode work", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const srv = server({ ping: chain().handler(async () => "pong") }, a, {
      auth: { secret: () => psk },
      replayWindow: 16,
    });
    const decodeSpy = vi.spyOn(common, "decodePlaintext");
    try {
      const sess = await manualHandshake(b, psk);
      const junk = encryptRaw(sess.sessionKey, new Uint8Array([0xc1]));

      b.send(junk);
      b.send(junk);
      await Promise.resolve();

      // The second copy is rejected by the pre-decrypt nonce check. Before
      // the fix both copies reached decodePlaintext.
      expect(decodeSpy).toHaveBeenCalledTimes(1);
    } finally {
      decodeSpy.mockRestore();
      srv.destroy();
    }
  });
});

describe("security / response framing limits", () => {
  it("does not hand an oversized encrypted response to the channel", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const wrapped = countSends(a);
    const errors: unknown[] = [];
    const router: Router = {
      big: chain().handler(async () => "x".repeat(2000)),
    };
    const srv = server(router, wrapped.ch, {
      auth: { secret: () => psk },
      maxMessageBytes: 128,
      onError: (error) => errors.push(error),
    });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 300,
      maxMessageBytes: 4096,
    });
    try {
      await expect(api.big({})).rejects.toMatchObject({ code: "TIMEOUT" });
      expect(wrapped.sends()).toBe(1); // handshake reply only
      expect(errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            code: "INVALID_DATA",
            message: "Response exceeds maxMessageBytes",
          }),
        ]),
      );
    } finally {
      destroy();
      srv.destroy();
    }
  });
});
