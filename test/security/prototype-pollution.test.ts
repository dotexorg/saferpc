/**
 * Prototype pollution: malicious __proto__/constructor/prototype keys in
 * inputs and outputs MUST not pollute the global Object.prototype, and
 * MUST NOT reach handlers as own properties.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  chain,
  client,
  server,
  sanitize,
  mpEncode,
  mpDecode,
  type Router,
} from "../../src/index.ts";
import { createChannelPair } from "../helpers/channels.ts";

describe("security / prototype pollution via inputs", () => {
  it("strips __proto__ before the handler sees it", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    let received: unknown = null;
    const router: Router = {
      sink: chain().handler(async ({ input }) => {
        received = input;
        return "ok";
      }),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      const payload = mpDecode(
        mpEncode({ a: 1, __proto__: { polluted: "yes" } }),
      ) as Record<string, unknown>;
      const before = (Object.prototype as Record<string, unknown>).polluted;

      await api.sink(payload);

      expect((Object.prototype as Record<string, unknown>).polluted).toBe(
        before,
      );
      expect(received).not.toBeNull();
      expect(Object.prototype.hasOwnProperty.call(received, "__proto__")).toBe(
        false,
      );
      expect((received as { a: number }).a).toBe(1);
    } finally {
      destroy();
      srv.destroy();
      delete (Object.prototype as Record<string, unknown>).polluted;
    }
  });

  it("strips constructor and prototype keys", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    let received: Record<string, unknown> | null = null;
    const router: Router = {
      sink: chain().handler(async ({ input }) => {
        received = input as Record<string, unknown>;
        return "ok";
      }),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      const payload = mpDecode(
        mpEncode({
          good: 1,
          constructor: "evil",
          prototype: "also-evil",
          nested: { constructor: "evil" },
        }),
      ) as Record<string, unknown>;

      await api.sink(payload);

      expect(received).not.toBeNull();
      const r = received as unknown as Record<string, unknown>;
      expect(Object.prototype.hasOwnProperty.call(r, "constructor")).toBe(
        false,
      );
      expect(Object.prototype.hasOwnProperty.call(r, "prototype")).toBe(false);
      expect(
        Object.prototype.hasOwnProperty.call(
          r.nested as Record<string, unknown>,
          "constructor",
        ),
      ).toBe(false);
      expect(r.good).toBe(1);
    } finally {
      destroy();
      srv.destroy();
    }
  });

  it("sanitize returns null-prototype objects", () => {
    const out = sanitize({ x: 1 }) as Record<string, unknown>;
    expect(Object.getPrototypeOf(out)).toBeNull();
    expect(out.x).toBe(1);
  });
});

describe("security / prototype pollution via outputs", () => {
  it("malicious return value does not pollute the client global", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();
    const router: Router = {
      poison: chain().handler(async () =>
        mpDecode(mpEncode({ ok: true, __proto__: { stolen: "yes" } })),
      ),
    };
    const srv = server(router, a, { auth: { secret: () => psk } });
    const { api, destroy } = client(b, {
      auth: { secret: () => psk },
      timeout: 1000,
    });
    try {
      const before = (Object.prototype as Record<string, unknown>).stolen;
      const result = (await api.poison({})) as Record<string, unknown>;
      expect((Object.prototype as Record<string, unknown>).stolen).toBe(before);
      expect(Object.prototype.hasOwnProperty.call(result, "__proto__")).toBe(
        false,
      );
      expect(result.ok).toBe(true);
    } finally {
      destroy();
      srv.destroy();
      delete (Object.prototype as Record<string, unknown>).stolen;
    }
  });
});
