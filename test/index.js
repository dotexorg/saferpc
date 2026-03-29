import { should, describe } from "micro-should";
import { deepStrictEqual, throws, strictEqual, ok } from "node:assert";
import { randomBytes } from "@noble/ciphers/webcrypto/utils";
import {
  RPCError,
  zero,
  sanitize,
  mpEncode,
  mpDecode,
  validatePSK,
  chain,
  createEncryptor,
  createDecryptor,
  deriveSessionKey,
  computeProof,
  KEY_LEN,
  client,
  server,
} from "../esm/index.js";

// ─── Helpers ─────────────────────────────────────────────

function createChannelPair() {
  let aCb = null;
  let bCb = null;
  const a = {
    send(data) {
      if (bCb) bCb(data);
    },
    receive(cb) {
      aCb = cb;
      return () => { aCb = null; };
    },
  };
  const b = {
    send(data) {
      if (aCb) aCb(data);
    },
    receive(cb) {
      bCb = cb;
      return () => { bCb = null; };
    },
  };
  return { a, b };
}

// ─── RPCError ────────────────────────────────────────────

describe("RPCError", () => {
  should("construct with code, message, data", () => {
    const err = new RPCError("TEST", "test message", { x: 1 });
    strictEqual(err.code, "TEST");
    strictEqual(err.message, "test message");
    deepStrictEqual(err.data, { x: 1 });
    ok(err instanceof Error);
  });

  should("default data to null", () => {
    const err = new RPCError("TEST", "msg");
    strictEqual(err.data, null);
  });

  should("reject empty code", () => {
    throws(() => new RPCError("", "msg"), TypeError);
  });

  should("reject non-string message", () => {
    throws(() => new RPCError("CODE", 123), TypeError);
  });
});

// ─── zero ────────────────────────────────────────────────

describe("zero", () => {
  should("zero out Uint8Array", () => {
    const buf = new Uint8Array([1, 2, 3, 4]);
    zero(buf);
    deepStrictEqual(buf, new Uint8Array(4));
  });

  should("zero out ArrayBuffer", () => {
    const ab = new ArrayBuffer(4);
    new Uint8Array(ab).set([1, 2, 3]);
    zero(ab);
    deepStrictEqual(new Uint8Array(ab), new Uint8Array(4));
  });
});

// ─── sanitize ────────────────────────────────────────────

describe("sanitize", () => {
  should("pass through primitives", () => {
    strictEqual(sanitize(42), 42);
    strictEqual(sanitize("hello"), "hello");
    strictEqual(sanitize(null), null);
    strictEqual(sanitize(undefined), undefined);
    strictEqual(sanitize(true), true);
  });

  should("pass through Uint8Array", () => {
    const buf = new Uint8Array([1, 2, 3]);
    strictEqual(sanitize(buf), buf);
  });

  should("sanitize arrays recursively", () => {
    deepStrictEqual(sanitize([1, [2, 3]]), [1, [2, 3]]);
  });

  should("strip __proto__, constructor, prototype keys", () => {
    const malicious = { a: 1, __proto__: { x: 1 }, constructor: "bad", prototype: "bad" };
    const result = sanitize(malicious);
    strictEqual(result.a, 1);
    strictEqual(result.__proto__, undefined);
    strictEqual(result.constructor, undefined);
    strictEqual(result.prototype, undefined);
  });

  should("throw on excessive depth", () => {
    let obj = { v: 1 };
    for (let i = 0; i < 40; i++) obj = { nested: obj };
    throws(() => sanitize(obj));
  });
});

// ─── mpEncode / mpDecode ─────────────────────────────────

describe("msgpack", () => {
  should("roundtrip objects", () => {
    const data = { a: 1, b: "hello", c: [1, 2, 3], d: new Uint8Array([0xff]) };
    const encoded = mpEncode(data);
    ok(encoded instanceof Uint8Array);
    const decoded = mpDecode(encoded);
    deepStrictEqual(decoded.a, 1);
    deepStrictEqual(decoded.b, "hello");
    deepStrictEqual(decoded.c, [1, 2, 3]);
  });

  should("roundtrip BigInt via useBigInt64", () => {
    const data = { n: 9007199254740993n };
    const decoded = mpDecode(mpEncode(data));
    strictEqual(decoded.n, 9007199254740993n);
  });
});

// ─── validatePSK ─────────────────────────────────────────

describe("validatePSK", () => {
  should("accept valid PSK", () => {
    validatePSK(randomBytes(32));
  });

  should("reject short PSK", () => {
    throws(() => validatePSK(randomBytes(16)), TypeError);
  });

  should("reject non-Uint8Array", () => {
    throws(() => validatePSK("not-bytes"), TypeError);
  });
});

// ─── chain builder ───────────────────────────────────────

describe("chain", () => {
  should("build a procedure with handler", () => {
    const proc = chain()
      .handler(async ({ input }) => input);
    ok(proc._handler);
    ok(Array.isArray(proc._steps));
    strictEqual(proc._steps.length, 0);
  });

  should("add middleware steps", () => {
    const proc = chain()
      .use(async ({ next }) => next())
      .handler(async ({ input }) => input);
    strictEqual(proc._steps.length, 1);
    strictEqual(proc._steps[0].t, "m");
  });

  should("reject non-function handler", () => {
    throws(() => chain().handler("not a fn"), TypeError);
  });

  should("reject non-function use", () => {
    throws(() => chain().use("not a fn"), TypeError);
  });

  should("freeze the procedure", () => {
    const proc = chain().handler(async () => null);
    throws(() => { proc._handler = null; }, TypeError);
    throws(() => { proc._steps.push({}); }, TypeError);
  });
});

// ─── Encrypt / Decrypt roundtrip ─────────────────────────

describe("encrypt/decrypt", () => {
  should("roundtrip data with session key", () => {
    const key = randomBytes(KEY_LEN);
    const encrypt = createEncryptor(key);
    const decrypt = createDecryptor(key);

    const data = { method: "greet", args: ["world"] };
    const encrypted = encrypt(data);
    ok(encrypted instanceof Uint8Array);
    ok(encrypted.length > 0);

    const decrypted = decrypt(encrypted);
    deepStrictEqual(decrypted.method, "greet");
    deepStrictEqual(decrypted.args, ["world"]);
  });

  should("fail to decrypt with wrong key", () => {
    const key1 = randomBytes(KEY_LEN);
    const key2 = randomBytes(KEY_LEN);
    const encrypt = createEncryptor(key1);
    const decrypt = createDecryptor(key2);

    const encrypted = encrypt({ x: 1 });
    throws(() => decrypt(encrypted));
  });
});

// ─── Key derivation ──────────────────────────────────────

describe("deriveSessionKey", () => {
  should("produce deterministic 32-byte key", () => {
    const shared = randomBytes(32);
    const psk = randomBytes(32);
    const k1 = deriveSessionKey(shared, psk);
    const k2 = deriveSessionKey(shared, psk);
    strictEqual(k1.length, KEY_LEN);
    deepStrictEqual(k1, k2);
  });

  should("differ with different PSK", () => {
    const shared = randomBytes(32);
    const k1 = deriveSessionKey(shared, randomBytes(32));
    const k2 = deriveSessionKey(shared, randomBytes(32));
    ok(k1.some((v, i) => v !== k2[i]));
  });
});

// ─── computeProof ────────────────────────────────────────

describe("computeProof", () => {
  should("produce deterministic 32-byte proof", () => {
    const sessionKey = randomBytes(32);
    const sPub = randomBytes(32);
    const cPub = randomBytes(32);
    const nonce = randomBytes(32);
    const p1 = computeProof(sessionKey, sPub, cPub, nonce);
    const p2 = computeProof(sessionKey, sPub, cPub, nonce);
    strictEqual(p1.length, 32);
    deepStrictEqual(p1, p2);
  });
});

// ─── Integration: client ↔ server ────────────────────────

describe("client ↔ server", () => {
  should("complete handshake and RPC call", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();

    const router = {
      greet: chain().handler(async ({ input }) => {
        return { message: `Hello, ${input.name}!` };
      }),
      add: chain().handler(async ({ input }) => {
        return { sum: input.a + input.b };
      }),
    };

    const srv = server(router, a, { psk });
    const { api, destroy } = client(b, { psk, timeout: 2000 });

    try {
      const result = await api.greet({ name: "world" });
      deepStrictEqual(result, { message: "Hello, world!" });

      const sum = await api.add({ a: 3, b: 4 });
      deepStrictEqual(sum, { sum: 7 });
    } finally {
      destroy();
      srv.destroy();
    }
  });

  should("handle unknown procedure", async () => {
    const psk = randomBytes(32);
    const { a, b } = createChannelPair();

    const router = {};
    const srv = server(router, a, { psk });
    const { api, destroy } = client(b, { psk, timeout: 2000 });

    try {
      await api.nonexistent({});
      throw new Error("Should have thrown");
    } catch (err) {
      strictEqual(err.code, "NOT_FOUND");
    } finally {
      destroy();
      srv.destroy();
    }
  });

  should("reject mismatched PSK", async () => {
    const { a, b } = createChannelPair();

    const router = {
      ping: chain().handler(async () => "pong"),
    };

    const srv = server(router, a, { psk: randomBytes(32) });
    const { api, destroy } = client(b, {
      psk: randomBytes(32),
      timeout: 1000,
      handshakeTimeout: 1000,
    });

    try {
      await api.ping({});
      throw new Error("Should have thrown");
    } catch (err) {
      ok(err instanceof RPCError);
    } finally {
      destroy();
      srv.destroy();
    }
  });
});

should.run();
