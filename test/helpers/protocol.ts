/**
 * Low-level protocol helpers — used by security tests to forge or
 * inspect handshake/RPC messages without going through client/server.
 */

import { randomBytes } from "@noble/ciphers/utils.js";
import {
  TAG_HELLO,
  TAG_MSG,
  KEY_LEN,
  x25519,
  concatBytes,
  mpEncode,
  mpDecode,
  deriveSessionKey,
  computeProof,
  createEncryptor,
  createDecryptor,
  type Channel,
} from "../../src/index.ts";

export { TAG_HELLO, TAG_MSG, KEY_LEN };

/** Build a forged client hello with the given fields (defaults filled in). */
export function forgeHello(
  opts: {
    pub?: Uint8Array;
    nonce?: Uint8Array;
    epoch?: number;
  } = {},
): Uint8Array {
  const pub = opts.pub ?? randomBytes(KEY_LEN);
  const nonce = opts.nonce ?? randomBytes(KEY_LEN);
  const epoch = opts.epoch ?? 1;
  const payload = mpEncode({ pub, nonce, epoch });
  return concatBytes(new Uint8Array([TAG_HELLO]), payload);
}

export interface ManualSession {
  sessionKey: Uint8Array;
  encrypt: (data: unknown) => Uint8Array;
  decrypt: (payload: Uint8Array) => unknown;
  serverPub: Uint8Array;
  clientPub: Uint8Array;
  clientPriv: Uint8Array;
  clientNonce: Uint8Array;
  proofOk: boolean;
  rawReply: Uint8Array;
}

/**
 * Run the client side of the handshake against a plain `channel` and
 * return the derived session, plus everything you might want to forge
 * follow-up messages.
 */
export async function manualHandshake(
  channel: Channel,
  psk: Uint8Array,
  opts: { epoch?: number } = {},
): Promise<ManualSession> {
  const epoch = opts.epoch ?? 1;
  const priv = x25519.utils.randomSecretKey();
  const pub = x25519.getPublicKey(priv);
  const nonce = randomBytes(KEY_LEN);

  const replyPromise = new Promise<Uint8Array>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("handshake timeout")), 2000);
    const unsubscribe = channel.receive((data) => {
      if (data[0] !== TAG_HELLO) return;
      clearTimeout(t);
      unsubscribe();
      resolve(data);
    });
  });

  const helloPayload = mpEncode({ pub, nonce, epoch });
  await channel.send(concatBytes(new Uint8Array([TAG_HELLO]), helloPayload));

  const reply = await replyPromise;
  const decoded = mpDecode(reply.subarray(1)) as {
    pub: Uint8Array;
    proof: Uint8Array;
    epoch: number;
  };

  const rawShared = x25519.getSharedSecret(priv, decoded.pub);
  const sessionKey = deriveSessionKey(rawShared, psk);
  const expectedProof = computeProof(sessionKey, decoded.pub, pub, nonce);
  const proofOk =
    decoded.proof.length === expectedProof.length &&
    decoded.proof.every((b, i) => b === expectedProof[i]);

  return {
    sessionKey,
    encrypt: createEncryptor(sessionKey),
    decrypt: createDecryptor(sessionKey),
    serverPub: decoded.pub,
    clientPub: pub,
    clientPriv: priv,
    clientNonce: nonce,
    proofOk,
    rawReply: reply,
  };
}
