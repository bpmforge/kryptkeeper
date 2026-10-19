import { configDefaults, defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
    // next-themes calls useContext against whatever React it resolves. Vite
    // pre-bundles it separately from the app, which handed it a SECOND React
    // instance whose context registry is empty — ThemeProvider then threw
    // "Cannot read properties of null (reading 'useContext')" on first
    // render. Unit tests never caught it because vitest does not pre-bundle
    // the same way; it only appears in a real browser.
    dedupe: ["react", "react-dom"],
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
    globals: true,
    // Playwright specs live under e2e/ and are run by `npm run e2e`.
    exclude: [...configDefaults.exclude, "e2e/**"],
    css: true,
  },
  server: {
    proxy: {
      "/api": "http://localhost:8080",
    },
  },
  // scripts/dev/local-review-env.sh says to review against the PRODUCTION
  // bundle rather than `npm run dev`, because main.tsx starts MSW whenever
  // import.meta.env.DEV and the dev server then answers from fixtures. That
  // advice was unfollowable: `vite preview` has its own proxy config and
  // this file only set the dev one, so a prod bundle could not reach the
  // API at all.
  preview: {
    proxy: {
      "/api": "http://localhost:8080",
    },
  },
});
