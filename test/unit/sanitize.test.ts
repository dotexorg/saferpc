import { describe, it, expect } from "vitest";
import { sanitize, RPCError } from "../../src/index.ts";

describe("sanitize / primitives", () => {
  it("passes through numbers, strings, booleans", () => {
    expect(sanitize(42)).toBe(42);
    expect(sanitize(-1.5)).toBe(-1.5);
    expect(sanitize("hello")).toBe("hello");
    expect(sanitize(true)).toBe(true);
    expect(sanitize(false)).toBe(false);
  });

  it("passes through null and undefined", () => {
    expect(sanitize(null)).toBeNull();
    expect(sanitize(undefined)).toBeUndefined();
  });

  it("passes Uint8Array through by reference (no copy)", () => {
    const buf = new Uint8Array([1, 2, 3]);
    expect(sanitize(buf)).toBe(buf);
  });

  it("passes through bigint", () => {
    expect(sanitize(9007199254740993n)).toBe(9007199254740993n);
  });
});

describe("sanitize / arrays", () => {
  it("recurses into nested arrays", () => {
    expect(sanitize([1, [2, [3]]])).toEqual([1, [2, [3]]]);
  });

  it("strips __proto__ keys nested inside array elements", () => {
    const malicious = [
      JSON.parse('{"ok": "yes", "__proto__": {"polluted": 1}}'),
    ];
    const out = sanitize(malicious) as Array<Record<string, unknown>>;
    expect(out[0]!.ok).toBe("yes");
    expect(Object.prototype.hasOwnProperty.call(out[0], "__proto__")).toBe(false);
  });

  it("preserves array order and length", () => {
    const arr = ["a", "b", "c", "d"];
    const out = sanitize(arr) as string[];
    expect(out).toEqual(arr);
    expect(out.length).toBe(4);
  });
});

describe("sanitize / objects + prototype pollution", () => {
  it("strips __proto__, constructor, prototype keys", () => {
    const malicious = JSON.parse(
      '{"a": 1, "__proto__": {"x": 1}, "constructor": "bad", "prototype": "bad"}',
    );
    const out = sanitize(malicious) as Record<string, unknown>;
    expect(out.a).toBe(1);
    expect(Object.getPrototypeOf(out)).toBeNull();
    expect(Object.prototype.hasOwnProperty.call(out, "__proto__")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(out, "constructor")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(out, "prototype")).toBe(false);
  });

  it("does not pollute Object.prototype after sanitizing __proto__ payload", () => {
    const before = (Object.prototype as Record<string, unknown>).polluted;
    const malicious = JSON.parse('{"__proto__": {"polluted": "yes"}}');
    sanitize(malicious);
    expect((Object.prototype as Record<string, unknown>).polluted).toBe(before);
    delete (Object.prototype as Record<string, unknown>).polluted;
  });

  it("returns objects with null prototype", () => {
    const out = sanitize({ a: 1 }) as Record<string, unknown>;
    expect(Object.getPrototypeOf(out)).toBeNull();
  });
});

describe("sanitize / non-plain object rejection", () => {
  it("rejects Date with INVALID_DATA", () => {
    expect(() => sanitize(new Date(0))).toThrow(RPCError);
    try {
      sanitize(new Date(0));
    } catch (err) {
      expect((err as RPCError).code).toBe("INVALID_DATA");
    }
  });

  it("rejects Map", () => {
    expect(() => sanitize(new Map())).toThrow(RPCError);
  });

  it("rejects Set", () => {
    expect(() => sanitize(new Set())).toThrow(RPCError);
  });

  it("rejects custom class instances", () => {
    class Foo {
      x = 1;
    }
    expect(() => sanitize(new Foo())).toThrow(RPCError);
  });

  it("accepts a plain object built from Object.create(null)", () => {
    const o = Object.create(null) as Record<string, unknown>;
    o.a = 1;
    expect(sanitize(o)).toEqual({ a: 1 });
  });
});

describe("sanitize / depth limit", () => {
  it("accepts deeply nested but bounded objects (≤ MAX_DEPTH)", () => {
    let obj: { v?: number; n?: unknown } = { v: 1 };
    for (let i = 0; i < 30; i++) obj = { n: obj };
    let cur = sanitize(obj) as { n?: { v?: number; n?: unknown } } | unknown;
    for (let i = 0; i < 30; i++) cur = (cur as { n: unknown }).n;
    expect((cur as { v: number }).v).toBe(1);
  });

  it("throws RPCError(INVALID_DATA) on a depth bomb", () => {
    let obj: { v?: number; n?: unknown } = { v: 1 };
    for (let i = 0; i < 50; i++) obj = { n: obj };
    try {
      sanitize(obj);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(RPCError);
      expect((err as RPCError).code).toBe("INVALID_DATA");
    }
  });

  it("throws on a depth bomb made of arrays", () => {
    let arr: unknown = [1];
    for (let i = 0; i < 50; i++) arr = [arr];
    expect(() => sanitize(arr)).toThrow(RPCError);
  });
});
