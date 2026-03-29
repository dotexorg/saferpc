/**
 * drpc/common — Shared types, crypto primitives, and chain builder
 *
 * This module contains everything shared between server and client:
 * constants, security utilities, crypto helpers, error types, the
 * Channel interface, procedure/router types, and the chain builder.
 */
import { type ZodType } from "zod";
import type { z } from "zod";
export { x25519 } from "@noble/curves/ed25519";
export { concatBytes } from "@noble/ciphers/utils";
export declare const NONCE_LEN = 24;
export declare const KEY_LEN = 32;
export declare const TAG_HELLO = 0;
export declare const TAG_MSG = 1;
export declare const MAX_MSG_BYTES = 1048576;
export declare const MAX_HELLO_BYTES = 256;
export declare const HANDSHAKE_TIMEOUT = 5000;
export declare function zero(buf: Uint8Array | ArrayBuffer): void;
export declare function sanitize(v: unknown, depth?: number): unknown;
export declare function mpEncode(data: unknown): Uint8Array;
export declare function mpDecode(buf: Uint8Array): unknown;
export declare function deriveSessionKey(rawShared: Uint8Array, psk: Uint8Array): Uint8Array;
export declare function computeProof(sessionKey: Uint8Array, serverPub: Uint8Array, clientPub: Uint8Array, nonce: Uint8Array): Uint8Array;
export declare function createEncryptor(sessionKey: Uint8Array): (data: unknown) => Uint8Array;
export declare function createDecryptor(sessionKey: Uint8Array): (payload: Uint8Array) => unknown;
export declare function validatePSK(psk: Uint8Array): void;
export declare class RPCError extends Error {
    readonly code: string;
    readonly data: unknown;
    constructor(code: string, message: string, data?: unknown);
}
export type Ctx = Record<string, unknown>;
export type MwFn = (opts: {
    ctx: Ctx;
    input: unknown;
    next: (extra?: Ctx) => Promise<unknown>;
}) => Promise<unknown>;
export type Step = {
    t: "m";
    fn: MwFn;
} | {
    t: "i";
    schema: ZodType;
} | {
    t: "o";
    schema: ZodType;
};
export type HandlerFn = (opts: {
    ctx: Ctx;
    input: unknown;
}) => Promise<unknown>;
export interface Procedure {
    readonly _steps: ReadonlyArray<Step>;
    readonly _handler: HandlerFn;
}
export type Router = Record<string, Procedure>;
export interface Channel {
    send(data: Uint8Array): void | Promise<void>;
    receive(cb: (data: Uint8Array) => void): () => void;
}
export interface Chain<TCtx extends Ctx = {}, TIn = unknown, TOut = unknown> {
    use<E extends Ctx = {}>(fn: (opts: {
        ctx: TCtx;
        input: TIn;
        next: (extra?: E) => Promise<unknown>;
    }) => Promise<unknown>): Chain<TCtx & E, TIn, TOut>;
    input<T extends ZodType>(schema: T): Chain<TCtx, z.output<T>, TOut>;
    output<T extends ZodType>(schema: T): Chain<TCtx, TIn, z.output<T>>;
    handler(fn: (opts: {
        ctx: TCtx;
        input: TIn;
    }) => Promise<TOut>): Procedure;
}
export declare function chain(steps?: Step[]): Chain;
//# sourceMappingURL=common.d.ts.map