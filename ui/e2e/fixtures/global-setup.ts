import fs from "node:fs";
import path from "node:path";
import { request, type FullConfig } from "@playwright/test";
import { KEYS_FILE, adminToken, type Role } from "./index";

const MINTED_ROLES: Exclude<Role, "admin">[] = ["pki-admin", "pki-operator", "viewer", "requester"];

async function waitForHealthy(base: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let last = "no response";
  const ctx = await request.newContext();
  try {
    while (Date.now() < deadline) {
      try {
        const res = await ctx.get(`${base}/healthz`);
        if (res.ok()) return;
        last = `HTTP ${res.status()}`;
      } catch (e) {
        last = e instanceof Error ? e.message : String(e);
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
  } finally {
    await ctx.dispose();
  }
  throw new Error(`hub not healthy at ${base}/healthz within ${timeoutMs / 1000}s (${last})`);
}

export default async function globalSetup(config: FullConfig): Promise<void> {
  const base = (config.projects[0]?.use.baseURL ?? process.env.KK_E2E_BASE_URL ?? "http://localhost:3000").replace(/\/$/, "");
  await waitForHealthy(base, 120_000);

  const ctx = await request.newContext({
    baseURL: base,
    extraHTTPHeaders: { Authorization: `Bearer ${adminToken()}` },
  });
  try {
    const listed = await ctx.get("/api/v1/api-keys");
    if (!listed.ok()) throw new Error(`list api-keys failed: HTTP ${listed.status()} (is APP_API_KEY_AUTH_ENABLED=true and the admin token correct?)`);
    const existing = ((await listed.json()) as { data: { kid: string; name?: string; active: boolean }[] }).data;

    const keys: Partial<Record<Role, string>> = {};
    for (const role of MINTED_ROLES) {
      const name = `e2e-${role}`;
      // Rerun against the same stack: revoke the stale key (its secret is gone) and mint a fresh one.
      for (const k of existing.filter((e) => e.name === name && e.active)) {
        const del = await ctx.delete(`/api/v1/api-keys/${k.kid}`);
        if (!del.ok()) throw new Error(`revoke stale key ${name} failed: HTTP ${del.status()}`);
      }
      const res = await ctx.post("/api/v1/api-keys", {
        data: { name, principal_id: name, role },
      });
      if (res.status() !== 201) throw new Error(`mint ${role} key failed: HTTP ${res.status()} ${await res.text()}`);
      const token = ((await res.json()) as { data: { token: string } }).data.token;
      if (!token) throw new Error(`mint ${role} key: response had no token`);
      keys[role] = token;
    }

    fs.mkdirSync(path.dirname(KEYS_FILE), { recursive: true });
    fs.writeFileSync(KEYS_FILE, JSON.stringify(keys), { mode: 0o600 });
  } finally {
    await ctx.dispose();
  }
}
