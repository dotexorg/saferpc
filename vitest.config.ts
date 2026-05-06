import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    exclude: [
      "test/e2e/browser.test.ts", // browser/puppeteer suite — opt-in
      "node_modules/**",
      "esm/**",
      "cjs/**",
    ],
    testTimeout: 15_000,
    hookTimeout: 15_000,
    pool: "threads",
    typecheck: {
      tsconfig: "./tsconfig.test.json",
    },
  },
});
