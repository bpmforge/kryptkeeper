import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  workers: 1,
  retries: 0,
  timeout: 120_000,
  reporter: "list",
  use: {
    baseURL: process.env.KK_E2E_BASE_URL ?? "http://localhost:3000",
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
