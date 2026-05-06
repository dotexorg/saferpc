import { describe, it, expect } from "vitest";
import { RPCError, RemoteRPCError } from "../../src/index.ts";

describe("RPCError", () => {
  it("constructs with code, message, data", () => {
    const err = new RPCError("TEST", "test message", { x: 1 });
    expect(err.code).toBe("TEST");
    expect(err.message).toBe("test message");
    expect(err.data).toEqual({ x: 1 });
    expect(err).toBeInstanceOf(Error);
  });

  it("defaults data to null when omitted", () => {
    expect(new RPCError("TEST", "msg").data).toBeNull();
  });

  it("defaults data to null when explicitly undefined", () => {
    expect(new RPCError("TEST", "msg", undefined).data).toBeNull();
  });

  it("preserves falsy data values that are not undefined", () => {
    expect(new RPCError("X", "y", 0).data).toBe(0);
    expect(new RPCError("X", "y", "").data).toBe("");
    expect(new RPCError("X", "y", false).data).toBe(false);
    expect(new RPCError("X", "y", null).data).toBeNull();
  });

  it("rejects empty code", () => {
    expect(() => new RPCError("", "msg")).toThrow(TypeError);
  });

  it("rejects non-string code", () => {
    expect(() => new RPCError(42 as unknown as string, "msg")).toThrow(TypeError);
    expect(() => new RPCError(null as unknown as string, "msg")).toThrow(TypeError);
    expect(() => new RPCError(undefined as unknown as string, "msg")).toThrow(TypeError);
  });

  it("rejects non-string message", () => {
    expect(() => new RPCError("CODE", 123 as unknown as string)).toThrow(TypeError);
    expect(() => new RPCError("CODE", null as unknown as string)).toThrow(TypeError);
    expect(() => new RPCError("CODE", { msg: "x" } as unknown as string)).toThrow(TypeError);
  });
});

describe("RemoteRPCError", () => {
  it("extends RPCError", () => {
    const err = new RemoteRPCError("REMOTE", "boom", { foo: 1 });
    expect(err).toBeInstanceOf(RPCError);
    expect(err).toBeInstanceOf(RemoteRPCError);
    expect(err).toBeInstanceOf(Error);
    expect(err.code).toBe("REMOTE");
    expect(err.message).toBe("boom");
    expect(err.data).toEqual({ foo: 1 });
  });

  it("is distinguishable from a plain RPCError via instanceof", () => {
    const local = new RPCError("LOCAL", "x");
    const remote = new RemoteRPCError("REMOTE", "x");
    expect(local).not.toBeInstanceOf(RemoteRPCError);
    expect(remote).toBeInstanceOf(RPCError);
  });
});
