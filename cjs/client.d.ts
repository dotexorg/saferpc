/**
 * drpc/client — Lazy RPC client with auto-retry
 *
 * LIFECYCLE: Handshake triggers lazily on first RPC call. On session
 * failure (timeout/send error), resets and retries once with a fresh
 * handshake — transparent to the caller. Concurrent calls coordinate
 * via epoch to avoid redundant resets.
 */
import { RPCError, type Router, type Channel } from "./common";
/**
 * Error received from the remote peer. Distinct from local RPCError
 * so callers can distinguish local failures (TIMEOUT, SESSION, CLIENT)
 * from remote failures. Remote error codes and messages are UNTRUSTED —
 * the remote peer can send arbitrary strings.
 */
export declare class RemoteRPCError extends RPCError {
    constructor(code: string, message: string, data?: unknown);
}
export type Client<T extends Router> = {
    [K in keyof T & string]: (input: unknown) => Promise<unknown>;
};
export interface ClientOptions {
    /** Pre-shared key for authentication. REQUIRED. Minimum 32 bytes. */
    psk: Uint8Array;
    /** Per-RPC-call timeout. Default: 10000ms. */
    timeout?: number;
    /** Max concurrent pending RPC calls. Default: 256. */
    maxPending?: number;
    /**
     * Max time (ms) to complete the handshake from when the client hello
     * is sent. Triggered lazily by the first RPC call, or on retry after
     * a previous handshake failure / reset. Default: 5000ms.
     */
    handshakeTimeout?: number;
    maxMessageBytes?: number;
}
export declare function client<T extends Router>(channel: Channel, opts: ClientOptions): {
    api: Client<T>;
    destroy: () => void;
};
//# sourceMappingURL=client.d.ts.map