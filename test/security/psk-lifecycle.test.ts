import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";

import { chain, client, server, type Router } from "../../src/index.ts";
import { createChannelPair } from "../helpers/channels.ts";

/**
 * Regression: eRPC must never mutate the PSK buffer the caller returned.
 * A `() => sharedSecret` pattern is documented; zeroing that buffer would
 * silently downgrade subsequent handshakes to EMPTY_PSK.
 */
describe("PSK lifecycle", () => {
  const router: Router = {
    ping: chain().handler(async () => "pong"),
  };

  it("does not zero the caller's PSK buffer after a handshake", async () => {
    const psk = randomBytes(32);
    const snapshot = new Uint8Array(psk);

    const { a, b } = createChannelPair();
    const srv = server(router, a, { auth: { psk: () => psk } });
    const { api, destroy } = client<typeof router>(b, {
      auth: { psk: () => psk },
    });

    await api["ping"]!(undefined);
    expect(Array.from(psk)).toEqual(Array.from(snapshot));

    destroy();
    srv.destroy();
  });

  it("re-handshakes successfully when psk() returns the same buffer twice", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const srv = server(router, a, { auth: { psk: () => psk } });
    const { api, destroy } = client<typeof router>(b, {
      auth: { psk: () => psk },
    });

    expect(await api["ping"]!(undefined)).toBe("pong");
    // Force a fresh handshake by destroying + recreating the client.
    destroy();
    const c2 = client<typeof router>(b, { auth: { psk: () => psk } });
    expect(await c2.api["ping"]!(undefined)).toBe("pong");
    c2.destroy();
    srv.destroy();
  });
});
