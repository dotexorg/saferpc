import { describe, it, expect } from "vitest";
import { zero } from "../../src/index.ts";

describe("zero", () => {
  it("zeroes a Uint8Array in place", () => {
    const buf = new Uint8Array([1, 2, 3, 4]);
    zero(buf);
    expect(Array.from(buf)).toEqual([0, 0, 0, 0]);
  });

  it("zeroes an ArrayBuffer in place", () => {
    const ab = new ArrayBuffer(4);
    new Uint8Array(ab).set([1, 2, 3, 4]);
    zero(ab);
    expect(Array.from(new Uint8Array(ab))).toEqual([0, 0, 0, 0]);
  });

  it("handles empty buffers without throwing", () => {
    expect(() => zero(new Uint8Array(0))).not.toThrow();
    expect(() => zero(new ArrayBuffer(0))).not.toThrow();
  });

  it("zeroes large buffers", () => {
    const buf = new Uint8Array(1024 * 1024);
    buf.fill(0xff);
    zero(buf);
    expect(buf.every((b) => b === 0)).toBe(true);
  });
});
