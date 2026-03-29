/**
 * drpc/server — Resilient RPC server
 *
 * LIFECYCLE: Survives handshake failures and re-handshakes. Resets to
 * waiting on timeout, failure, or new hello (even in ready state).
 * Only explicit destroy() is permanent.
 */
import { type Ctx, type Router, type Channel } from "./common";
export interface ServeOptions {
    /** Pre-shared key for authentication. REQUIRED. Minimum 32 bytes. */
    psk: Uint8Array;
    /**
     * Factory called per-request to create context for handlers.
     * MUST NOT hang — there is no server-side per-request timeout
     * (consistent with tRPC/oRPC). A blocking context() will accumulate
     * hanging closures until the client-side timeout fires.
     */
    context?: () => Ctx | Promise<Ctx>;
    /**
     * Max time (ms) to complete a handshake AFTER a client hello arrives.
     * The server waits indefinitely for a client to connect — this timeout
     * only governs the exchange once a hello is received.
     * On timeout the server resets to waiting (does NOT destroy).
     * Default: 5000ms.
     */
    handshakeTimeout?: number;
    maxMessageBytes?: number;
    /**
     * Called on handshake failures and non-fatal internal errors.
     * The server does NOT destroy on handshake failure — it resets to
     * waiting and accepts the next hello. Use this for logging/monitoring.
     */
    onError?: (err: unknown) => void;
}
export declare function server<T extends Router>(router: T, channel: Channel, opts: ServeOptions): {
    destroy: () => void;
};
//# sourceMappingURL=server.d.ts.map