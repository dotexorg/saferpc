"use strict";
/**
 * drpc/server — Resilient RPC server
 *
 * LIFECYCLE: Survives handshake failures and re-handshakes. Resets to
 * waiting on timeout, failure, or new hello (even in ready state).
 * Only explicit destroy() is permanent.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.server = server;
const common_1 = require("./common");
// ─── Pipeline executor ───────────────────────────────────
function execute(steps, handler, baseCtx, rawInput) {
    let ctx = Object.assign(Object.create(null), baseCtx);
    let input = rawInput;
    let tip = function runHandler() {
        return handler({ ctx, input });
    };
    for (let i = steps.length - 1; i >= 0; i--) {
        const step = steps[i];
        const next = tip;
        switch (step.t) {
            case "i": {
                const schema = step.schema;
                tip = function runInput() {
                    const r = schema.safeParse(input);
                    if (!r.success) {
                        throw new common_1.RPCError("INPUT_VALIDATION", "Input validation failed", r.error.flatten());
                    }
                    input = r.data;
                    return next();
                };
                break;
            }
            case "o": {
                const schema = step.schema;
                tip = async function runOutput() {
                    const result = await next();
                    const r = schema.safeParse(result);
                    if (!r.success) {
                        throw new common_1.RPCError("OUTPUT_VALIDATION", "Output validation failed", r.error.flatten());
                    }
                    return r.data;
                };
                break;
            }
            case "m": {
                const mw = step.fn;
                tip = function runMiddleware() {
                    let called = false;
                    return mw({
                        ctx,
                        input,
                        next(extra) {
                            if (called) {
                                throw new common_1.RPCError("MIDDLEWARE", "next() called more than once");
                            }
                            called = true;
                            if (extra !== undefined) {
                                if (typeof extra !== "object" || extra === null) {
                                    throw new common_1.RPCError("MIDDLEWARE", "next() extra must be an object");
                                }
                                ctx = Object.assign(Object.create(null), ctx, extra);
                            }
                            return next();
                        },
                    });
                };
                break;
            }
            default:
                throw new common_1.RPCError("INTERNAL", "Unknown step type");
        }
    }
    return tip();
}
// ─── Server ───────────────────────────────────────────────
// RESILIENT HANDSHAKE: The server survives handshake failures.
//
// States:
//   waiting — accepting hellos, no session yet
//   pending — hello reply sent, waiting for first valid encrypted msg
//   ready   — session established (first valid TAG_MSG decrypted)
//
// Transitions:
//   waiting → pending:  hello processed, reply sent
//   pending → ready:    first valid TAG_MSG decrypted (session confirmed)
//   pending → waiting:  timeout OR new hello arrives (client retry)
//   ready   → waiting:  new hello arrives (client re-handshaking)
//
// On handshake failure or timeout, the server resets with fresh
// ephemeral keys and waits for the next hello. An epoch counter
// guards against stale async operations from previous attempts.
function server(router, channel, opts) {
    if (typeof router !== "object" || router === null) {
        throw new TypeError("server() requires a router object");
    }
    if (typeof channel.send !== "function") {
        throw new TypeError("channel.send must be a function");
    }
    if (typeof channel.receive !== "function") {
        throw new TypeError("channel.receive must be a function");
    }
    (0, common_1.validatePSK)(opts.psk);
    const frozen = Object.freeze(Object.assign(Object.create(null), router));
    const psk = opts.psk;
    const hsTimeout = opts.handshakeTimeout !== undefined
        ? opts.handshakeTimeout
        : common_1.HANDSHAKE_TIMEOUT;
    const maxBytes = opts.maxMessageBytes !== undefined ? opts.maxMessageBytes : common_1.MAX_MSG_BYTES;
    const onError = opts.onError ?? null;
    let state = "waiting";
    let epoch = 0;
    let privateKey = common_1.x25519.utils.randomSecretKey();
    let publicKey = common_1.x25519.getPublicKey(privateKey);
    let sessionKey = null;
    let encrypt = null;
    let decrypt = null;
    let destroyed = false;
    let hsTimer = null;
    function clearHsTimer() {
        if (hsTimer !== null) {
            clearTimeout(hsTimer);
            hsTimer = null;
        }
    }
    /** Zero current keys, regenerate fresh ephemeral pair, return to waiting. */
    function resetHandshake() {
        clearHsTimer();
        epoch++;
        if (sessionKey !== null) {
            (0, common_1.zero)(sessionKey);
            sessionKey = null;
        }
        encrypt = null;
        decrypt = null;
        (0, common_1.zero)(privateKey);
        (0, common_1.zero)(publicKey);
        privateKey = common_1.x25519.utils.randomSecretKey();
        publicKey = common_1.x25519.getPublicKey(privateKey);
        state = "waiting";
    }
    function destroy() {
        if (destroyed)
            return;
        destroyed = true;
        clearHsTimer();
        (0, common_1.zero)(privateKey);
        (0, common_1.zero)(publicKey);
        if (sessionKey !== null) {
            (0, common_1.zero)(sessionKey);
            sessionKey = null;
        }
        encrypt = null;
        decrypt = null;
        if (unsubscribe !== null) {
            unsubscribe();
            unsubscribe = null;
        }
    }
    let unsubscribe = channel.receive(function onMessage(data) {
        if (destroyed || data.length === 0)
            return;
        const tag = data[0];
        // Accept hello in any active state. In "pending" or "ready",
        // reset the current session first — the client is re-handshaking.
        if (tag === common_1.TAG_HELLO) {
            if (data.length > common_1.MAX_HELLO_BYTES)
                return;
            // Reset any existing session for the new handshake attempt.
            if (state === "pending" || state === "ready") {
                resetHandshake();
            }
            const myEpoch = epoch;
            // Handshake timeout covers hello processing + waiting for
            // first encrypted message (session confirmation).
            hsTimer = setTimeout(function onHsTimeout() {
                if (epoch !== myEpoch || destroyed)
                    return;
                resetHandshake();
                if (onError !== null) {
                    onError(new common_1.RPCError("HANDSHAKE", "Handshake timeout"));
                }
            }, hsTimeout);
            (async function handleHello() {
                // Capture keys locally — safe against future code changes
                // that might add an await before key usage.
                const myPriv = privateKey;
                const myPub = publicKey;
                const raw = (0, common_1.sanitize)((0, common_1.mpDecode)(data.subarray(1)));
                if (typeof raw !== "object" || raw === null) {
                    throw new common_1.RPCError("HANDSHAKE", "Invalid hello");
                }
                const hello = raw; // @TODO
                const clientPub = hello.pub;
                if (!(clientPub instanceof Uint8Array) ||
                    clientPub.length !== common_1.KEY_LEN) {
                    throw new common_1.RPCError("HANDSHAKE", "Invalid public key");
                }
                const nonce = hello.nonce;
                if (!(nonce instanceof Uint8Array) || nonce.length !== common_1.KEY_LEN) {
                    throw new common_1.RPCError("HANDSHAKE", "Invalid nonce");
                }
                // Client epoch — echoed in reply so client can discard
                // stale responses from previous handshake attempts.
                const clientEpoch = typeof hello.epoch === "number" ? hello.epoch : 0;
                const rawShared = common_1.x25519.getSharedSecret(myPriv, clientPub);
                sessionKey = (0, common_1.deriveSessionKey)(rawShared, psk);
                (0, common_1.zero)(rawShared);
                const proof = (0, common_1.computeProof)(sessionKey, myPub, clientPub, nonce);
                // Set encrypt/decrypt BEFORE sending reply so synchronous
                // transports (e.g. MessageChannel) can process the client's
                // first TAG_MSG that arrives during channel.send().
                // State → "pending": accept TAG_MSG but session not confirmed.
                encrypt = (0, common_1.createEncryptor)(sessionKey);
                decrypt = (0, common_1.createDecryptor)(sessionKey);
                state = "pending";
                const replyPayload = (0, common_1.mpEncode)({
                    pub: myPub,
                    proof,
                    epoch: clientEpoch,
                });
                const reply = (0, common_1.concatBytes)(new Uint8Array([common_1.TAG_HELLO]), replyPayload);
                (0, common_1.zero)(replyPayload);
                (0, common_1.zero)(proof);
                await channel.send(reply);
                // Epoch guard: if a new hello arrived during await (client retry),
                // this attempt is stale — abort silently.
                if (epoch !== myEpoch || destroyed)
                    return;
                // Timer continues running — waiting for first valid TAG_MSG
                // to transition pending → ready. Total budget = hsTimeout.
            })().catch(function onHsError(err) {
                if (epoch !== myEpoch || destroyed)
                    return;
                resetHandshake();
                if (onError !== null) {
                    onError(err instanceof common_1.RPCError
                        ? err
                        : new common_1.RPCError("HANDSHAKE", "Handshake failed"));
                }
            });
            return;
        }
        if (tag === common_1.TAG_MSG && decrypt !== null && encrypt !== null) {
            if (data.length > maxBytes)
                return;
            const reqEpoch = epoch;
            (async function handleRequest() {
                if (decrypt === null || encrypt === null)
                    return;
                let raw;
                try {
                    raw = decrypt(data);
                }
                catch {
                    return; // poly1305 failure → silently drop
                }
                // First valid decrypt confirms the session.
                // The client proved it has the correct sessionKey (which
                // requires the correct PSK) by producing a valid ciphertext.
                if (state === "pending") {
                    clearHsTimer();
                    state = "ready";
                }
                if (typeof raw !== "object" || raw === null)
                    return;
                const msg = raw; // @TODO
                if (msg.t !== 1)
                    return;
                if (typeof msg.id !== "string" || msg.id.length === 0) {
                    return;
                }
                if (typeof msg.p !== "string" || msg.p.length === 0) {
                    return;
                }
                const id = msg.id;
                const procedure = msg.p;
                let res;
                try {
                    if (!(procedure in frozen)) {
                        throw new common_1.RPCError("NOT_FOUND", "Unknown: " + procedure);
                    }
                    const proc = frozen[procedure];
                    const ctx = opts.context !== undefined
                        ? await opts.context()
                        : Object.create(null);
                    const result = await execute(proc._steps, proc._handler, ctx, msg.i);
                    res = { t: 2, id, ok: true, d: result, e: null };
                }
                catch (err) {
                    if (err instanceof common_1.RPCError) {
                        res = {
                            t: 2,
                            id,
                            ok: false,
                            d: null,
                            e: { c: err.code, m: err.message, d: (0, common_1.sanitize)(err.data) },
                        };
                    }
                    else {
                        res = {
                            t: 2,
                            id,
                            ok: false,
                            d: null,
                            e: { c: "INTERNAL", m: "Internal error", d: null },
                        };
                    }
                }
                // Epoch guard: if a reset/re-handshake happened while the
                // handler was running, this response belongs to a dead session.
                // Drop it — the client already timed out and retried.
                if (epoch !== reqEpoch || destroyed)
                    return;
                const enc = encrypt;
                if (enc === null)
                    return;
                await channel.send(enc(res));
            })().catch(function onSendError(err) {
                if (onError !== null)
                    onError(err);
            });
        }
    });
    return { destroy };
}
//# sourceMappingURL=server.js.map