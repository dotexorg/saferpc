import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";

import { chain, client, server, type Router } from "../../src/index.ts";
import { createChannelPair } from "../helpers/channels.ts";

/**
 * Regression: eRPC must never mutate the secret buffer the caller returned.
 * A `() => sharedSecret` pattern is documented; zeroing that buffer would
 * silently downgrade subsequent handshakes to EMPTY_SECRET.
 */
describe("secret lifecycle", () => {
  const router: Router = {
    ping: chain().handler(async () => "pong"),
  };

  it("does not zero the caller's secret buffer after a handshake", async () => {
    const secret = randomBytes(32);
    const snapshot = new Uint8Array(secret);

    const { a, b } = createChannelPair();
    const srv = server(router, a, { auth: { secret: () => secret } });
    const { api, destroy } = client<typeof router>(b, {
      auth: { secret: () => secret },
    });

    await api["ping"]!(undefined);
    expect(Array.from(secret)).toEqual(Array.from(snapshot));

    destroy();
    srv.destroy();
  });

  it("re-handshakes successfully when secret() returns the same buffer twice", async () => {
    const secret = randomBytes(32);
    const { a, b } = createChannelPair();
    const srv = server(router, a, { auth: { secret: () => secret } });
    const { api, destroy } = client<typeof router>(b, {
      auth: { secret: () => secret },
    });

    expect(await api["ping"]!(undefined)).toBe("pong");
    // Force a fresh handshake by destroying + recreating the client.
    destroy();
    const c2 = client<typeof router>(b, { auth: { secret: () => secret } });
    expect(await c2.api["ping"]!(undefined)).toBe("pong");
    c2.destroy();
    srv.destroy();
  });
});
