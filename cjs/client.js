"use strict";
/**
 * drpc/client — Lazy RPC client with auto-retry
 *
 * LIFECYCLE: Handshake triggers lazily on first RPC call. On session
 * failure (timeout/send error), resets and retries once with a fresh
 * handshake — transparent to the caller. Concurrent calls coordinate
 * via epoch to avoid redundant resets.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.RemoteRPCError = void 0;
exports.client = client;
const utils_1 = require("@noble/ciphers/utils");
const common_1 = require("./common");
// ─── Client constants ─────────────────────────────────────
const PROOF_LEN = 32;
const MAX_PENDING = 256;
const DEFAULT_TIMEOUT = 10_000;
// ─── Client utilities ─────────────────────────────────────
function constTimeEqual(a, b) {
    if (a.length !== b.length)
        return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) {
        d |= a[i] ^ b[i];
    }
    return d === 0;
}
// ─── Client types ─────────────────────────────────────────
/**
 * Error received from the remote peer. Distinct from local RPCError
 * so callers can distinguish local failures (TIMEOUT, SESSION, CLIENT)
 * from remote failures. Remote error codes and messages are UNTRUSTED —
 * the remote peer can send arbitrary strings.
 */
class RemoteRPCError extends common_1.RPCError {
    constructor(code, message, data) {
        super(code, message, data);
    }
}
exports.RemoteRPCError = RemoteRPCError;
// ─── Client ──────────────────────────────────────────────
function client(channel, opts) {
    if (typeof channel.send !== "function") {
        throw new TypeError("client() channel.send must be a function");
    }
    if (typeof channel.receive !== "function") {
        throw new TypeError("client() channel.receive must be a function");
    }
    (0, common_1.validatePSK)(opts.psk);
    const psk = opts.psk;
    const timeout = opts.timeout !== undefined ? opts.timeout : DEFAULT_TIMEOUT;
    const maxPending = opts.maxPending !== undefined ? opts.maxPending : MAX_PENDING;
    const hsTimeout = opts.handshakeTimeout !== undefined
        ? opts.handshakeTimeout
        : common_1.HANDSHAKE_TIMEOUT;
    const maxBytes = opts.maxMessageBytes !== undefined ? opts.maxMessageBytes : common_1.MAX_MSG_BYTES;
    // ── State machine: idle → handshaking → ready, or closed ──
    // idle:        no session. Next RPC call triggers handshake.
    // handshaking: hello sent, waiting for server reply.
    //              All RPC calls await the same handshakePromise.
    // ready:       session key established. RPC calls go through.
    // closed:      destroyed. All calls throw.
    //
    // RETRY: On handshake failure, state → idle. Next call retries.
    // AUTO-RESET: On RPC timeout or send error while ready, zeros crypto
    //   and goes idle. Pending calls keep their timers — they retry
    //   individually when they time out. Epoch prevents redundant resets.
    let state = "idle";
    // Ephemeral keys — regenerated per handshake attempt
    let privateKey = null;
    let publicKey = null;
    let clientNonce = null;
    let sessionKey = null;
    let encrypt = null;
    let decrypt = null;
    // Epoch — incremented per handshake attempt, prevents stale replies
    let epoch = 0;
    // Handshake coordination — multiple calls share one promise
    let handshakePromise = null;
    let handshakeResolve = null;
    let handshakeReject = null;
    let hsTimer = null;
    // Pending RPC responses
    const pending = new Map();
    let counter = 0;
    const knownProcedures = new Set();
    function clearHsTimer() {
        if (hsTimer !== null) {
            clearTimeout(hsTimer);
            hsTimer = null;
        }
    }
    function zeroKeys() {
        if (privateKey !== null) {
            (0, common_1.zero)(privateKey);
            privateKey = null;
        }
        if (publicKey !== null) {
            (0, common_1.zero)(publicKey);
            publicKey = null;
        }
        if (clientNonce !== null) {
            (0, common_1.zero)(clientNonce);
            clientNonce = null;
        }
        if (sessionKey !== null) {
            (0, common_1.zero)(sessionKey);
            sessionKey = null;
        }
        encrypt = null;
        decrypt = null;
    }
    function rejectPending(err) {
        for (const [, entry] of pending) {
            clearTimeout(entry.timer);
            entry.reject(err);
        }
        pending.clear();
    }
    function failHandshake(err) {
        clearHsTimer();
        const rej = handshakeReject;
        handshakePromise = null;
        handshakeResolve = null;
        handshakeReject = null;
        zeroKeys();
        state = "idle";
        if (rej !== null) {
            rej(err instanceof common_1.RPCError
                ? err
                : new common_1.RPCError("HANDSHAKE", "Handshake failed"));
        }
    }
    function startHandshake() {
        privateKey = common_1.x25519.utils.randomSecretKey();
        publicKey = common_1.x25519.getPublicKey(privateKey);
        clientNonce = (0, utils_1.randomBytes)(common_1.KEY_LEN);
        epoch++;
        state = "handshaking";
        const currentEpoch = epoch;
        handshakePromise = new Promise(function hsExecutor(resolve, reject) {
            handshakeResolve = resolve;
            handshakeReject = reject;
        });
        hsTimer = setTimeout(function onHsTimeout() {
            if (state !== "handshaking" || epoch !== currentEpoch)
                return;
            failHandshake(new common_1.RPCError("HANDSHAKE", "Handshake timeout"));
        }, hsTimeout);
        const helloPayload = (0, common_1.mpEncode)({
            pub: publicKey,
            nonce: clientNonce,
            epoch: currentEpoch,
        });
        const hello = (0, common_1.concatBytes)(new Uint8Array([common_1.TAG_HELLO]), helloPayload);
        (0, common_1.zero)(helloPayload);
        Promise.resolve(channel.send(hello)).catch(function onSendError(err) {
            if (state !== "handshaking" || epoch !== currentEpoch)
                return;
            failHandshake(err);
        });
        return handshakePromise;
    }
    function ensureHandshake() {
        if (state === "ready")
            return Promise.resolve();
        if (state === "closed") {
            return Promise.reject(new common_1.RPCError("SESSION", "Session destroyed"));
        }
        if (state === "handshaking" && handshakePromise !== null) {
            return handshakePromise;
        }
        return startHandshake();
    }
    // ── Persistent message listener ───────────────────────────
    const unsubscribe = channel.receive(function onMessage(data) {
        if (state === "closed" || data.length === 0)
            return;
        const tag = data[0];
        // ── Handshake response ──
        if (tag === common_1.TAG_HELLO && state === "handshaking") {
            if (data.length > common_1.MAX_HELLO_BYTES)
                return;
            if (privateKey === null || publicKey === null || clientNonce === null) {
                return;
            }
            const currentEpoch = epoch;
            const priv = privateKey;
            const pub = publicKey;
            const nonce = clientNonce;
            try {
                const raw = (0, common_1.sanitize)((0, common_1.mpDecode)(data.subarray(1)));
                if (typeof raw !== "object" || raw === null) {
                    throw new common_1.RPCError("HANDSHAKE", "Invalid hello");
                }
                // TODO: Strict
                const hello = raw;
                // Epoch check — drop stale replies from previous attempts
                const replyEpoch = typeof hello.epoch === "number" ? hello.epoch : 0;
                if (replyEpoch !== currentEpoch)
                    return;
                const serverPub = hello.pub;
                if (!(serverPub instanceof Uint8Array) ||
                    serverPub.length !== common_1.KEY_LEN) {
                    throw new common_1.RPCError("HANDSHAKE", "Invalid public key");
                }
                const proof = hello.proof;
                if (!(proof instanceof Uint8Array) || proof.length !== PROOF_LEN) {
                    throw new common_1.RPCError("HANDSHAKE", "Invalid proof");
                }
                const rawShared = common_1.x25519.getSharedSecret(priv, serverPub);
                sessionKey = (0, common_1.deriveSessionKey)(rawShared, psk);
                (0, common_1.zero)(rawShared);
                const expected = (0, common_1.computeProof)(sessionKey, serverPub, pub, nonce);
                if (!constTimeEqual(proof, expected)) {
                    (0, common_1.zero)(expected);
                    throw new common_1.RPCError("HANDSHAKE", "Authentication failed");
                }
                (0, common_1.zero)(expected);
                encrypt = (0, common_1.createEncryptor)(sessionKey);
                decrypt = (0, common_1.createDecryptor)(sessionKey);
                clearHsTimer();
                const res = handshakeResolve;
                handshakePromise = null;
                handshakeResolve = null;
                handshakeReject = null;
                state = "ready";
                if (res !== null)
                    res();
            }
            catch (err) {
                if (epoch !== currentEpoch)
                    return;
                failHandshake(err);
            }
            return;
        }
        // ── RPC response ──
        if (tag === common_1.TAG_MSG && state === "ready" && decrypt !== null) {
            if (data.length > maxBytes)
                return;
            let raw;
            try {
                raw = decrypt(data);
            }
            catch {
                return; // poly1305 auth failed → silent drop
            }
            try {
                if (typeof raw !== "object" || raw === null)
                    return;
                const msg = raw; // @TODO: strict
                if (msg.t !== 2)
                    return;
                if (typeof msg.id !== "string")
                    return;
                const entry = pending.get(msg.id);
                if (entry === undefined)
                    return;
                pending.delete(msg.id);
                clearTimeout(entry.timer);
                if (msg.ok === true) {
                    entry.resolve(msg.d);
                }
                else {
                    const e = msg.e; // @TODO Stirct
                    if (typeof e !== "object" || e === null) {
                        entry.reject(new RemoteRPCError("UNKNOWN", "Unknown error"));
                    }
                    else {
                        entry.reject(new RemoteRPCError(String(e.c), String(e.m), e.d));
                    }
                }
            }
            catch {
                // Unexpected processing error — silent drop, call times out
            }
        }
    });
    // ── Send a single RPC request, returns promise for the response ──
    function sendRequest(prop, input) {
        const enc = encrypt;
        if (state === "closed" || enc === null) {
            return Promise.reject(new common_1.RPCError("SESSION", "Session destroyed"));
        }
        if (pending.size >= maxPending) {
            return Promise.reject(new common_1.RPCError("CLIENT", "Too many pending requests"));
        }
        const id = String(++counter);
        const encrypted = enc({ t: 1, id, p: prop, i: input });
        return new Promise(function rpcExec(res, rej) {
            const timer = setTimeout(function onRpcTimeout() {
                pending.delete(id);
                rej(new common_1.RPCError("TIMEOUT", "Timed out: " + prop));
            }, timeout);
            pending.set(id, { resolve: res, reject: rej, timer });
            Promise.resolve(channel.send(encrypted)).catch(function onSendError(err) {
                pending.delete(id);
                clearTimeout(timer);
                rej(err);
            });
        });
    }
    // ── API proxy ─────────────────────────────────────────────
    const api = new Proxy(Object.create(null), {
        get(_target, prop) {
            if (typeof prop !== "string")
                return undefined;
            if (prop === "then")
                return undefined;
            return async function call(input) {
                if (state === "closed") {
                    throw new common_1.RPCError("SESSION", "Session destroyed");
                }
                await ensureHandshake();
                knownProcedures.add(prop);
                // Capture epoch before sending — used to detect stale failures.
                const sentEpoch = epoch;
                try {
                    return await sendRequest(prop, input);
                }
                catch (err) {
                    // If session was ready and the call failed (timeout, send error),
                    // the server likely died. Auto-reset and retry ONCE with a fresh
                    // handshake — transparent to the caller.
                    if (state === "closed")
                        throw err; // @TODO: Invistigae error
                    // Don't retry RemoteRPCError — the server responded, session is fine
                    if (err instanceof RemoteRPCError)
                        throw err;
                    // Only reset if still in the same session. If epoch moved on,
                    // another call already reset — just ride the new handshake.
                    if (epoch === sentEpoch) {
                        reset();
                    }
                    await ensureHandshake();
                    return sendRequest(prop, input);
                }
            };
        },
        has(_target, prop) {
            return typeof prop === "string" && knownProcedures.has(prop);
        },
        ownKeys() {
            return [...knownProcedures];
        },
        getOwnPropertyDescriptor(_target, prop) {
            if (typeof prop === "string" && knownProcedures.has(prop)) {
                return {
                    configurable: true,
                    enumerable: true,
                    writable: false,
                };
            }
            return undefined;
        },
    });
    // ── Auto-reset ─────────────────────────────────────────────
    // Called when a call's sendRequest fails (timeout or send error).
    // Only zeros crypto and returns to idle — pending calls are left
    // untouched. They'll time out naturally and retry individually
    // through the same catch → epoch-check → ensureHandshake path.
    // If another call already reset (epoch advanced), latecomers skip
    // this and just join the in-progress handshake.
    function reset() {
        if (state !== "ready")
            return;
        zeroKeys();
        state = "idle";
    }
    // ── Destroy ───────────────────────────────────────────────
    function destroy() {
        if (state === "closed")
            return;
        const wasHandshaking = state === "handshaking";
        state = "closed";
        clearHsTimer();
        zeroKeys();
        unsubscribe();
        if (wasHandshaking && handshakeReject !== null) {
            const rej = handshakeReject;
            handshakePromise = null;
            handshakeResolve = null;
            handshakeReject = null;
            rej(new common_1.RPCError("SESSION", "Session destroyed"));
        }
        rejectPending(new common_1.RPCError("SESSION", "Session destroyed"));
    }
    return { api, destroy };
}
//# sourceMappingURL=client.js.map