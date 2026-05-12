import { describe, it, expect } from "vitest";
import { encode as rawEncode, ExtensionCodec } from "@msgpack/msgpack";
import { mpEncode, mpDecode, RPCError } from "../../src/index.ts";

describe("mpEncode / mpDecode", () => {
  it("roundtrips primitives", () => {
    expect(mpDecode(mpEncode(42))).toBe(42);
    expect(mpDecode(mpEncode("hello"))).toBe("hello");
    expect(mpDecode(mpEncode(true))).toBe(true);
    expect(mpDecode(mpEncode(null))).toBeNull();
  });

  it("roundtrips plain objects", () => {
    const data = { a: 1, b: "hello", c: [1, 2, 3] };
    expect(mpDecode(mpEncode(data))).toEqual(data);
  });

  it("roundtrips Uint8Array fields", () => {
    const data = { d: new Uint8Array([0xde, 0xad, 0xbe, 0xef]) };
    const decoded = mpDecode(mpEncode(data)) as { d: Uint8Array };
    expect(decoded.d).toBeInstanceOf(Uint8Array);
    expect(Array.from(decoded.d)).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it("roundtrips BigInt via useBigInt64", () => {
    const data = { n: 9007199254740993n };
    const out = mpDecode(mpEncode(data)) as { n: bigint };
    expect(out.n).toBe(9007199254740993n);
  });

  it("emits a Uint8Array", () => {
    expect(mpEncode({ x: 1 })).toBeInstanceOf(Uint8Array);
  });

  it("rejects the built-in Timestamp ext type (-1)", () => {
    const dateBlob = rawEncode(new Date(0));
    try {
      mpDecode(dateBlob);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(RPCError);
      expect((err as RPCError).code).toBe("INVALID_DATA");
      expect((err as RPCError).message).toContain("Timestamp");
    }
  });

  it("returns ExtData (raw) for unregistered ext types — caught downstream by sanitize", () => {
    class Evil {}
    const codec = new ExtensionCodec();
    codec.register({
      type: 0x42,
      encode: (v) => (v instanceof Evil ? new Uint8Array([0xee]) : null),
      decode: () => ({ malicious: true }),
    });
    const blob = rawEncode(new Evil(), { extensionCodec: codec });
    const decoded = mpDecode(blob);
    // mpDecode itself does not throw for unknown ext types; ExtData
    // surfaces, and sanitize() rejects it as a non-plain object.
    expect(typeof decoded).toBe("object");
    expect(decoded).not.toBeNull();
    expect(
      (decoded as { constructor: { name: string } }).constructor.name,
    ).toBe("ExtData");
  });
});
