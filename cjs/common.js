"use strict";
/**
 * drpc/common — Shared types, crypto primitives, and chain builder
 *
 * This module contains everything shared between server and client:
 * constants, security utilities, crypto helpers, error types, the
 * Channel interface, procedure/router types, and the chain builder.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.RPCError = exports.HANDSHAKE_TIMEOUT = exports.MAX_HELLO_BYTES = exports.MAX_MSG_BYTES = exports.TAG_MSG = exports.TAG_HELLO = exports.KEY_LEN = exports.NONCE_LEN = exports.concatBytes = exports.x25519 = void 0;
exports.zero = zero;
exports.sanitize = sanitize;
exports.mpEncode = mpEncode;
exports.mpDecode = mpDecode;
exports.deriveSessionKey = deriveSessionKey;
exports.computeProof = computeProof;
exports.createEncryptor = createEncryptor;
exports.createDecryptor = createDecryptor;
exports.validatePSK = validatePSK;
exports.chain = chain;
const salsa_1 = require("@noble/ciphers/salsa");
const msgpack_1 = require("@msgpack/msgpack");
const utils_1 = require("@noble/ciphers/utils");
const hkdf_1 = require("@noble/hashes/hkdf");
const sha2_1 = require("@noble/hashes/sha2");
const hmac_1 = require("@noble/hashes/hmac");
// Re-export crypto primitives needed by both server.ts and client.ts
var ed25519_1 = require("@noble/curves/ed25519");
Object.defineProperty(exports, "x25519", { enumerable: true, get: function () { return ed25519_1.x25519; } });
var utils_2 = require("@noble/ciphers/utils");
Object.defineProperty(exports, "concatBytes", { enumerable: true, get: function () { return utils_2.concatBytes; } });
// ─── Constants ────────────────────────────────────────────
exports.NONCE_LEN = 24;
exports.KEY_LEN = 32;
exports.TAG_HELLO = 0x00;
exports.TAG_MSG = 0x01;
exports.MAX_MSG_BYTES = 1_048_576;
exports.MAX_HELLO_BYTES = 256;
exports.HANDSHAKE_TIMEOUT = 5_000;
const MAX_DEPTH = 32;
const KDF_INFO = new TextEncoder().encode("drpc-v1");
/**
 * Empty ExtensionCodec — rejects ALL msgpack extension types including
 * the default Timestamp (-1). This prevents type confusion attacks where
 * a malicious payload uses extension types to inject Date, Map, or Set
 * objects that bypass sanitize().
 */
const SAFE_CODEC = new msgpack_1.ExtensionCodec();
// ─── Security utilities ──────────────────────────────────
function zero(buf) {
    const view = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
    view.fill(0);
}
const POISON = new Set(["__proto__", "constructor", "prototype"]);
function sanitize(v, depth = 0) {
    if (depth > MAX_DEPTH) {
        throw new RPCError("INVALID_DATA", "Max nesting depth exceeded");
    }
    if (v === null || v === undefined)
        return v;
    if (typeof v !== "object")
        return v;
    if (v instanceof Uint8Array)
        return v;
    if (Array.isArray(v)) {
        const out = [];
        for (let i = 0; i < v.length; i++) {
            out[i] = sanitize(v[i], depth + 1);
        }
        return out;
    }
    const out = Object.create(null);
    const keys = Object.keys(v);
    for (let i = 0; i < keys.length; i++) {
        const k = keys[i];
        if (POISON.has(k))
            continue;
        out[k] = sanitize(v[k], depth + 1);
    }
    return out;
}
// ─── Safe msgpack wrappers ──────────────────────────────
function mpEncode(data) {
    return (0, msgpack_1.encode)(data, { extensionCodec: SAFE_CODEC, useBigInt64: true });
}
function mpDecode(buf) {
    return (0, msgpack_1.decode)(buf, { extensionCodec: SAFE_CODEC, useBigInt64: true });
}
// ─── Key derivation ──────────────────────────────────────
function deriveSessionKey(rawShared, psk) {
    return (0, hkdf_1.hkdf)(sha2_1.sha256, rawShared, psk, KDF_INFO, exports.KEY_LEN);
}
function computeProof(sessionKey, serverPub, clientPub, nonce) {
    const msg = (0, utils_1.concatBytes)(serverPub, clientPub, nonce);
    const result = (0, hmac_1.hmac)(sha2_1.sha256, sessionKey, msg);
    zero(msg);
    return result;
}
// ─── Encrypted message helpers ───────────────────────────
function createEncryptor(sessionKey) {
    return function encrypt(data) {
        const nonce = (0, utils_1.randomBytes)(exports.NONCE_LEN);
        const encoded = mpEncode(data);
        const cipher = (0, salsa_1.xsalsa20poly1305)(sessionKey, nonce);
        const ct = cipher.encrypt(encoded);
        const payload = (0, utils_1.concatBytes)(new Uint8Array([exports.TAG_MSG]), nonce, ct);
        zero(nonce);
        zero(encoded);
        zero(ct);
        return payload;
    };
}
function createDecryptor(sessionKey) {
    return function decrypt(payload) {
        const nonce = payload.slice(1, 1 + exports.NONCE_LEN);
        const ct = payload.slice(1 + exports.NONCE_LEN);
        const cipher = (0, salsa_1.xsalsa20poly1305)(sessionKey, nonce);
        const encoded = cipher.decrypt(ct);
        const data = mpDecode(encoded);
        zero(nonce);
        zero(ct);
        zero(encoded);
        zero(payload);
        return sanitize(data);
    };
}
// ─── PSK validation ──────────────────────────────────────
function validatePSK(psk) {
    if (!(psk instanceof Uint8Array)) {
        throw new TypeError("psk must be a Uint8Array");
    }
    if (psk.length < exports.KEY_LEN) {
        throw new TypeError(`psk must be at least ${exports.KEY_LEN} bytes`);
    }
}
// ─── Error ────────────────────────────────────────────────
class RPCError extends Error {
    code;
    data;
    constructor(code, message, data) {
        if (typeof code !== "string" || code.length === 0) {
            throw new TypeError("RPCError: code must be a non-empty string");
        }
        if (typeof message !== "string") {
            throw new TypeError("RPCError: message must be a string");
        }
        super(message);
        this.code = code;
        this.data = data !== undefined ? data : null;
    }
}
exports.RPCError = RPCError;
function chain(steps = []) {
    return {
        use(fn) {
            if (typeof fn !== "function") {
                throw new TypeError("use() requires a function");
            }
            return chain([...steps, { t: "m", fn }]);
        },
        input(schema) {
            if (schema === null ||
                schema === undefined ||
                typeof schema.safeParse !== "function") {
                throw new TypeError("input() requires a Zod schema");
            }
            return chain([...steps, { t: "i", schema }]);
        },
        output(schema) {
            if (schema === null ||
                schema === undefined ||
                typeof schema.safeParse !== "function") {
                throw new TypeError("output() requires a Zod schema");
            }
            return chain([...steps, { t: "o", schema }]);
        },
        handler(fn) {
            if (typeof fn !== "function") {
                throw new TypeError("handler() requires a function");
            }
            return Object.freeze({
                _steps: Object.freeze([...steps]),
                _handler: fn,
            });
        },
    };
}
//# sourceMappingURL=common.js.map