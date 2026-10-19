import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { apiRequest, expect, loginAs, test } from "./index";

test("admin can load the dashboard", async ({ page, request }) => {
  await loginAs(page, "admin");
  await page.goto("/");
  // The page body is a lazy chunk; allow it longer than the default 5s.
  await expect(page.locator("main").getByRole("heading").first()).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.getByRole("navigation").first()).toBeVisible();

  const res = await apiRequest(request, "admin", "GET", "/authz-check");
  expect(res.status()).toBe(200);
  const body = (await res.json()) as {
    role?: string;
    data?: { role?: string };
  };
  expect(body.role ?? body.data?.role).toBeTruthy();
});

test("minted viewer key authenticates as viewer", async ({ request }) => {
  const res = await apiRequest(request, "viewer", "GET", "/authz-check");
  expect(res.status()).toBe(200);
  const body = (await res.json()) as {
    role?: string;
    data?: { role?: string };
  };
  expect(body.role ?? body.data?.role).toBe("viewer");
});

test("no credentials committed", () => {
  const e2eRoot = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
  );
  const hits: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === ".auth") continue; // gitignored runtime output
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (
        /\.(ts|js|json|md)$/.test(entry.name) &&
        entry.name !== "smoke.spec.ts"
      ) {
        const text = fs.readFileSync(full, "utf8");
        if (
          /kk_[A-Za-z0-9]{20,}/.test(text) ||
          /password\s*[:=]\s*["'`][^"'`]+["'`]/i.test(text)
        )
          hits.push(full);
      }
    }
  };
  walk(e2eRoot);
  expect(hits).toEqual([]);
});
