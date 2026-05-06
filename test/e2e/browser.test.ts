/**
 * Browser E2E — Puppeteer drives a real Chromium with two iframes
 * communicating in-memory through eRPC. Confirms the bundle works
 * unchanged in a browser. The iframe channel adapter for postMessage
 * is documented in spec/integrations.md; here we drive an in-memory
 * pair to keep the test focused on bundle correctness.
 *
 * Skipped automatically if `puppeteer` is not installed.
 */
import { describe, it, expect } from "vitest";
import { createServer, type Server } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { AddressInfo } from "node:net";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..", "..");

let puppeteer: typeof import("puppeteer") | null = null;
try {
  puppeteer = (await import("puppeteer")).default as never;
} catch {
  /* skip */
}

const MIME: Record<string, string> = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".map": "application/json",
};

function makeStaticServer(): Promise<{ port: number; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const srv: Server = createServer(async (req, res) => {
      const url = new URL(req.url ?? "/", "http://localhost");
      if (url.pathname === "/host.html") {
        res.setHeader("Content-Type", "text/html");
        res.end(HOST_HTML);
        return;
      }
      try {
        const safe = url.pathname.replace(/\.\.+/g, "");
        const filePath = join(ROOT, safe);
        const content = await readFile(filePath);
        const ext = safe.slice(safe.lastIndexOf("."));
        res.setHeader("Content-Type", MIME[ext] ?? "application/octet-stream");
        res.end(content);
      } catch {
        res.statusCode = 404;
        res.end("not found");
      }
    });
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as AddressInfo;
      resolve({
        port,
        close: () => new Promise<void>((r) => srv.close(() => r())),
      });
    });
  });
}

const HOST_HTML = `<!doctype html>
<html><head><meta charset="utf-8" /></head>
<body>
<script type="importmap">
{
  "imports": {
    "zod": "/node_modules/zod/v4/index.js",
    "@msgpack/msgpack": "/node_modules/@msgpack/msgpack/dist.es5+esm/index.mjs",
    "@noble/curves/ed25519.js": "/node_modules/@noble/curves/ed25519.js",
    "@noble/ciphers/salsa.js": "/node_modules/@noble/ciphers/salsa.js",
    "@noble/ciphers/utils.js": "/node_modules/@noble/ciphers/utils.js",
    "@noble/hashes/hkdf.js": "/node_modules/@noble/hashes/hkdf.js",
    "@noble/hashes/sha2.js": "/node_modules/@noble/hashes/sha2.js",
    "@noble/hashes/hmac.js": "/node_modules/@noble/hashes/hmac.js"
  }
}
</script>
<script type="module">
import { chain, client, server } from "/esm/index.js";
window.__erpc = { chain, client, server };
window.__ready = true;
</script>
</body></html>`;

const describeMaybe = puppeteer ? describe : describe.skip;

describeMaybe("browser / puppeteer", () => {
  it("performs a handshake and RPC call inside Chromium", async () => {
    const stat = await makeStaticServer();
    const browser = await puppeteer!.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });
    try {
      const page = await browser.newPage();
      page.on("pageerror", (err: unknown) => console.error("[pageerror]", err));
      await page.goto(`http://127.0.0.1:${stat.port}/host.html`);
      await page.waitForFunction(
        () => (window as unknown as { __ready?: boolean }).__ready === true,
        { timeout: 15000 },
      );

      const result = await page.evaluate(async () => {
        const erpc = (window as unknown as {
          __erpc: {
            chain: typeof import("../../src/index.ts").chain;
            client: typeof import("../../src/index.ts").client;
            server: typeof import("../../src/index.ts").server;
          };
        }).__erpc;

        let aCb: ((d: Uint8Array) => void) | null = null;
        let bCb: ((d: Uint8Array) => void) | null = null;
        const a = {
          send(d: Uint8Array) {
            if (bCb) bCb(d);
          },
          receive(cb: (d: Uint8Array) => void) {
            aCb = cb;
            return () => {
              aCb = null;
            };
          },
        };
        const b = {
          send(d: Uint8Array) {
            if (aCb) aCb(d);
          },
          receive(cb: (d: Uint8Array) => void) {
            bCb = cb;
            return () => {
              bCb = null;
            };
          },
        };

        const psk = crypto.getRandomValues(new Uint8Array(32));
        const router = {
          greet: erpc
            .chain()
            .handler(async ({ input }: { input: unknown }) => ({
              message:
                "Hello, " + (input as { name: string }).name + "!",
            })),
        };
        const srv = erpc.server(router, a, { psk });
        const { api, destroy } = erpc.client(b, { psk, timeout: 3000 });
        try {
          return await api.greet({ name: "browser" });
        } finally {
          destroy();
          srv.destroy();
        }
      });

      expect(result).toEqual({ message: "Hello, browser!" });
    } finally {
      await browser.close();
      await stat.close();
    }
  }, 60_000);
});
