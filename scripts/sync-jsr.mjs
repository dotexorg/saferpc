#!/usr/bin/env node
// Syncs jsr.json from package.json: name, version, exports, imports.
// Fields not derived from package.json (publish, license, etc.) are preserved.

import { readFileSync, writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkgPath = resolve(root, "package.json");
const jsrPath = resolve(root, "jsr.json");

const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
const jsr = JSON.parse(readFileSync(jsrPath, "utf8"));

jsr.name = pkg.name;
jsr.version = pkg.version;

const exports = {};
for (const [key, value] of Object.entries(pkg.exports ?? {})) {
  const target =
    typeof value === "string"
      ? value
      : (value.import ?? value.default ?? value.require);
  if (!target) continue;
  exports[key] = target
    .replace(/^\.\/(esm|cjs|dist|lib)\//, "./src/")
    .replace(/\.(js|mjs|cjs)$/, ".ts");
}
jsr.exports = exports;

const imports = {};
for (const [name, range] of Object.entries(pkg.dependencies ?? {})) {
  if (["noble", "zod"].some((p) => name.includes(p))) {
    imports[name] = `jsr:${name === "zod" ? "@zod/zod" : name}@${range}`;
  } else {
    imports[name] = `npm:${name}@${range}`;
  }
}
jsr.imports = imports;

writeFileSync(jsrPath, JSON.stringify(jsr, null, 2) + "\n");
console.log(`Synced ${jsrPath} from ${pkgPath}`);
