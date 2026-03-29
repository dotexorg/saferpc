"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.server = exports.RemoteRPCError = exports.client = exports.chain = exports.RPCError = exports.validatePSK = exports.createDecryptor = exports.createEncryptor = exports.computeProof = exports.deriveSessionKey = exports.mpDecode = exports.mpEncode = exports.sanitize = exports.zero = exports.concatBytes = exports.x25519 = exports.HANDSHAKE_TIMEOUT = exports.MAX_HELLO_BYTES = exports.MAX_MSG_BYTES = exports.TAG_MSG = exports.TAG_HELLO = exports.KEY_LEN = exports.NONCE_LEN = void 0;
var common_1 = require("./common");
// Constants
Object.defineProperty(exports, "NONCE_LEN", { enumerable: true, get: function () { return common_1.NONCE_LEN; } });
Object.defineProperty(exports, "KEY_LEN", { enumerable: true, get: function () { return common_1.KEY_LEN; } });
Object.defineProperty(exports, "TAG_HELLO", { enumerable: true, get: function () { return common_1.TAG_HELLO; } });
Object.defineProperty(exports, "TAG_MSG", { enumerable: true, get: function () { return common_1.TAG_MSG; } });
Object.defineProperty(exports, "MAX_MSG_BYTES", { enumerable: true, get: function () { return common_1.MAX_MSG_BYTES; } });
Object.defineProperty(exports, "MAX_HELLO_BYTES", { enumerable: true, get: function () { return common_1.MAX_HELLO_BYTES; } });
Object.defineProperty(exports, "HANDSHAKE_TIMEOUT", { enumerable: true, get: function () { return common_1.HANDSHAKE_TIMEOUT; } });
// Crypto re-exports
Object.defineProperty(exports, "x25519", { enumerable: true, get: function () { return common_1.x25519; } });
Object.defineProperty(exports, "concatBytes", { enumerable: true, get: function () { return common_1.concatBytes; } });
// Security utilities
Object.defineProperty(exports, "zero", { enumerable: true, get: function () { return common_1.zero; } });
Object.defineProperty(exports, "sanitize", { enumerable: true, get: function () { return common_1.sanitize; } });
// Msgpack
Object.defineProperty(exports, "mpEncode", { enumerable: true, get: function () { return common_1.mpEncode; } });
Object.defineProperty(exports, "mpDecode", { enumerable: true, get: function () { return common_1.mpDecode; } });
// Key derivation
Object.defineProperty(exports, "deriveSessionKey", { enumerable: true, get: function () { return common_1.deriveSessionKey; } });
Object.defineProperty(exports, "computeProof", { enumerable: true, get: function () { return common_1.computeProof; } });
// Encryption
Object.defineProperty(exports, "createEncryptor", { enumerable: true, get: function () { return common_1.createEncryptor; } });
Object.defineProperty(exports, "createDecryptor", { enumerable: true, get: function () { return common_1.createDecryptor; } });
// PSK
Object.defineProperty(exports, "validatePSK", { enumerable: true, get: function () { return common_1.validatePSK; } });
// Error
Object.defineProperty(exports, "RPCError", { enumerable: true, get: function () { return common_1.RPCError; } });
// Chain builder
Object.defineProperty(exports, "chain", { enumerable: true, get: function () { return common_1.chain; } });
var client_1 = require("./client");
Object.defineProperty(exports, "client", { enumerable: true, get: function () { return client_1.client; } });
Object.defineProperty(exports, "RemoteRPCError", { enumerable: true, get: function () { return client_1.RemoteRPCError; } });
var server_1 = require("./server");
Object.defineProperty(exports, "server", { enumerable: true, get: function () { return server_1.server; } });
//# sourceMappingURL=index.js.map