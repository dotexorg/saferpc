import { describe, it, expect } from "vitest";
import { z } from "zod";
import { chain } from "../../src/index.ts";

describe("chain / handler", () => {
  it("builds a procedure with no steps", () => {
    const proc = chain().handler(async ({ input }) => input);
    expect(proc._handler).toBeTypeOf("function");
    expect(Array.isArray(proc._steps)).toBe(true);
    expect(proc._steps.length).toBe(0);
  });

  it("freezes the procedure object and steps array", () => {
    const proc = chain().handler(async () => null);
    expect(() => {
      (proc as unknown as { _handler: unknown })._handler = null;
    }).toThrow(TypeError);
    expect(() => {
      (proc._steps as unknown as unknown[]).push({});
    }).toThrow(TypeError);
  });

  it("rejects non-function handler", () => {
    expect(() => chain().handler("nope" as unknown as () => Promise<unknown>)).toThrow(TypeError);
    expect(() => chain().handler(null as unknown as () => Promise<unknown>)).toThrow(TypeError);
    expect(() => chain().handler(undefined as unknown as () => Promise<unknown>)).toThrow(TypeError);
    expect(() => chain().handler(42 as unknown as () => Promise<unknown>)).toThrow(TypeError);
  });
});

describe("chain / use (middleware)", () => {
  it("records middleware steps in order", () => {
    const proc = chain()
      .use(async ({ next }) => next())
      .use(async ({ next }) => next({ extra: 1 }))
      .handler(async ({ input }) => input);

    expect(proc._steps.length).toBe(2);
    expect(proc._steps[0]!.t).toBe("m");
    expect(proc._steps[1]!.t).toBe("m");
  });

  it("forks rather than mutates on each method call", () => {
    const base = chain().use(async ({ next }) => next());
    const a = base.handler(async () => "a");
    const b = base.use(async ({ next }) => next()).handler(async () => "b");
    expect(a._steps.length).toBe(1);
    expect(b._steps.length).toBe(2);
  });

  it("rejects non-function use()", () => {
    expect(() => chain().use("not a fn" as unknown as never)).toThrow(TypeError);
    expect(() => chain().use(null as unknown as never)).toThrow(TypeError);
    expect(() => chain().use(undefined as unknown as never)).toThrow(TypeError);
  });
});

describe("chain / input + output schemas", () => {
  it("records input and output steps", () => {
    const proc = chain()
      .input(z.object({ x: z.number() }))
      .output(z.string())
      .handler(async () => "ok");
    expect(proc._steps.length).toBe(2);
    expect(proc._steps[0]!.t).toBe("i");
    expect(proc._steps[1]!.t).toBe("o");
  });

  it("rejects non-Zod schemas", () => {
    expect(() => chain().input(null as unknown as z.ZodType)).toThrow(TypeError);
    expect(() => chain().input(undefined as unknown as z.ZodType)).toThrow(TypeError);
    expect(() => chain().input({} as unknown as z.ZodType)).toThrow(TypeError);
    expect(() => chain().input("nope" as unknown as z.ZodType)).toThrow(TypeError);
    expect(() => chain().output(null as unknown as z.ZodType)).toThrow(TypeError);
    expect(() => chain().output({} as unknown as z.ZodType)).toThrow(TypeError);
  });
});

describe("chain / mixed pipelines", () => {
  it("preserves declaration order across use/input/output", () => {
    const proc = chain()
      .use(async ({ next }) => next())
      .input(z.string())
      .use(async ({ next }) => next())
      .output(z.string())
      .handler(async ({ input }) => input);

    expect(proc._steps.map((s) => s.t)).toEqual(["m", "i", "m", "o"]);
  });
});
