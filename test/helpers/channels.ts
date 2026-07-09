/**
 * Channel implementations for tests:
 *   - createChannelPair        — in-memory two-way pair (synchronous)
 *   - createAsyncChannelPair   — same, but send() resolves on next tick
 *   - createMitmChannelPair    — middlebox you can stop/tamper/inject through
 *   - createFaultChannelPair   — pair whose link can go down/up; while down
 *                                both endpoints queue their sends (adapter
 *                                lifecycle contract) and flush in order on up
 *   - portChannel              — wrap a worker_threads MessagePort
 *   - wsChannel                — wrap a `ws` WebSocket
 */

import type { Channel } from "../../src/index.ts";

export function createChannelPair(): { a: Channel; b: Channel } {
  let aCb: ((data: Uint8Array) => void) | null = null;
  let bCb: ((data: Uint8Array) => void) | null = null;
  const a: Channel = {
    send(data) {
      if (bCb) bCb(data);
    },
    receive(cb) {
      aCb = cb;
      return () => {
        aCb = null;
      };
    },
  };
  const b: Channel = {
    send(data) {
      if (aCb) aCb(data);
    },
    receive(cb) {
      bCb = cb;
      return () => {
        bCb = null;
      };
    },
  };
  return { a, b };
}

export function createAsyncChannelPair(): { a: Channel; b: Channel } {
  let aCb: ((data: Uint8Array) => void) | null = null;
  let bCb: ((data: Uint8Array) => void) | null = null;
  const a: Channel = {
    async send(data) {
      await Promise.resolve();
      if (bCb) bCb(data);
    },
    receive(cb) {
      aCb = cb;
      return () => {
        aCb = null;
      };
    },
  };
  const b: Channel = {
    async send(data) {
      await Promise.resolve();
      if (aCb) aCb(data);
    },
    receive(cb) {
      bCb = cb;
      return () => {
        bCb = null;
      };
    },
  };
  return { a, b };
}

export interface MitmState {
  dropAtoB: number;
  dropBtoA: number;
  transformAtoB: ((d: Uint8Array) => Uint8Array | null) | null;
  transformBtoA: ((d: Uint8Array) => Uint8Array | null) | null;
  captures: Array<{ dir: "AtoB" | "BtoA"; data: Uint8Array }>;
}

export interface Mitm {
  state: MitmState;
  dropNextAtoB: (n?: number) => void;
  dropNextBtoA: (n?: number) => void;
  transformAtoB: (fn: (d: Uint8Array) => Uint8Array | null) => void;
  transformBtoA: (fn: (d: Uint8Array) => Uint8Array | null) => void;
  injectToA: (data: Uint8Array) => void;
  injectToB: (data: Uint8Array) => void;
  clearCaptures: () => void;
}

/**
 * Middlebox between client and server. State and helpers let tests drop
 * frames, mutate them in flight, capture them for later inspection, or
 * inject forged frames at either side.
 */
export function createMitmChannelPair(): {
  a: Channel;
  b: Channel;
  mitm: Mitm;
} {
  let aCb: ((data: Uint8Array) => void) | null = null;
  let bCb: ((data: Uint8Array) => void) | null = null;
  const state: MitmState = {
    dropAtoB: 0,
    dropBtoA: 0,
    transformAtoB: null,
    transformBtoA: null,
    captures: [],
  };

  const a: Channel = {
    send(data) {
      state.captures.push({ dir: "AtoB", data: data.slice() });
      if (state.dropAtoB > 0) {
        state.dropAtoB--;
        return;
      }
      const out = state.transformAtoB ? state.transformAtoB(data) : data;
      if (out !== null && bCb) bCb(out);
    },
    receive(cb) {
      aCb = cb;
      return () => {
        aCb = null;
      };
    },
  };
  const b: Channel = {
    send(data) {
      state.captures.push({ dir: "BtoA", data: data.slice() });
      if (state.dropBtoA > 0) {
        state.dropBtoA--;
        return;
      }
      const out = state.transformBtoA ? state.transformBtoA(data) : data;
      if (out !== null && aCb) aCb(out);
    },
    receive(cb) {
      bCb = cb;
      return () => {
        bCb = null;
      };
    },
  };

  const mitm: Mitm = {
    state,
    dropNextAtoB(n = 1) {
      state.dropAtoB += n;
    },
    dropNextBtoA(n = 1) {
      state.dropBtoA += n;
    },
    transformAtoB(fn) {
      state.transformAtoB = fn;
    },
    transformBtoA(fn) {
      state.transformBtoA = fn;
    },
    injectToA(data) {
      if (aCb) aCb(data);
    },
    injectToB(data) {
      if (bCb) bCb(data);
    },
    clearCaptures() {
      state.captures.length = 0;
    },
  };

  return { a, b, mitm };
}

export interface FaultLink {
  goDown: () => void;
  goUp: () => void;
  isUp: () => boolean;
}

/**
 * In-memory pair whose link can be taken down and brought back. Models a
 * transport adapter that follows the lifecycle contract (common.ts
 * `Channel` jsdoc): while the link is down, `send` never throws — frames
 * queue at the sender (they provably never left) and flush in order on
 * `goUp()`. Frames delivered while up are synchronous, like
 * `createChannelPair`.
 */
export function createFaultChannelPair(): {
  a: Channel;
  b: Channel;
  link: FaultLink;
} {
  let aCb: ((data: Uint8Array) => void) | null = null;
  let bCb: ((data: Uint8Array) => void) | null = null;
  let up = true;
  const fromA: Uint8Array[] = [];
  const fromB: Uint8Array[] = [];

  const a: Channel = {
    send(data) {
      if (!up) {
        fromA.push(data.slice());
        return;
      }
      if (bCb) bCb(data);
    },
    receive(cb) {
      aCb = cb;
      return () => {
        if (aCb === cb) aCb = null;
      };
    },
  };
  const b: Channel = {
    send(data) {
      if (!up) {
        fromB.push(data.slice());
        return;
      }
      if (aCb) aCb(data);
    },
    receive(cb) {
      bCb = cb;
      return () => {
        if (bCb === cb) bCb = null;
      };
    },
  };

  const link: FaultLink = {
    goDown() {
      up = false;
    },
    goUp() {
      if (up) return;
      up = true;
      while (fromA.length > 0) {
        const frame = fromA.shift() as Uint8Array;
        if (bCb) bCb(frame);
      }
      while (fromB.length > 0) {
        const frame = fromB.shift() as Uint8Array;
        if (aCb) aCb(frame);
      }
    },
    isUp: () => up,
  };

  return { a, b, link };
}

/** Wrap a worker_threads MessagePort. */
export function portChannel(port: {
  postMessage: (data: unknown) => void;
  on: (event: string, cb: (data: unknown) => void) => void;
  off: (event: string, cb: (data: unknown) => void) => void;
}): Channel {
  return {
    send(data) {
      port.postMessage(data);
    },
    receive(cb) {
      const handler = (data: unknown): void => {
        if (data instanceof Uint8Array) cb(data);
        else if (data instanceof ArrayBuffer) cb(new Uint8Array(data));
        else if (
          data &&
          typeof data === "object" &&
          (data as { buffer?: unknown }).buffer instanceof ArrayBuffer
        ) {
          const v = data as {
            buffer: ArrayBuffer;
            byteOffset: number;
            byteLength: number;
          };
          cb(new Uint8Array(v.buffer, v.byteOffset, v.byteLength));
        }
      };
      port.on("message", handler);
      return () => port.off("message", handler);
    },
  };
}

/** Wrap a `ws` WebSocket. */
export function wsChannel(ws: {
  send: (data: Uint8Array, opts?: { binary?: boolean }) => void;
  on: (ev: string, cb: (data: unknown) => void) => void;
  off: (ev: string, cb: (data: unknown) => void) => void;
}): Channel {
  return {
    send(data) {
      ws.send(data, { binary: true });
    },
    receive(cb) {
      const handler = (data: unknown): void => {
        if (data instanceof Uint8Array) cb(data);
        else if (typeof Buffer !== "undefined" && Buffer.isBuffer(data)) {
          const b = data as Buffer;
          cb(new Uint8Array(b.buffer, b.byteOffset, b.byteLength));
        } else if (data instanceof ArrayBuffer) {
          cb(new Uint8Array(data));
        }
      };
      ws.on("message", handler);
      return () => ws.off("message", handler);
    },
  };
}
