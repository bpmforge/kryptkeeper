import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  test as base,
  expect,
  type APIRequestContext,
  type APIResponse,
  type Page,
} from "@playwright/test";

export type Role = "admin" | "pki-admin" | "pki-operator" | "viewer" | "requester";

const here = path.dirname(fileURLToPath(import.meta.url));
export const KEYS_FILE = path.join(here, ".auth", "keys.json");

/** Bootstrap token that authenticates as the super-admin. */
export function adminToken(): string {
  const t = process.env.KK_E2E_BOOTSTRAP_TOKEN ?? process.env.APP_BOOTSTRAP_TOKEN;
  if (!t) {
    throw new Error(
      "admin token missing: set KK_E2E_BOOTSTRAP_TOKEN (or APP_BOOTSTRAP_TOKEN) to the hub's bootstrap token",
    );
  }
  return t;
}

/** Token for a role: the bootstrap token for admin, else an API key minted by global-setup. */
export function tokenFor(role: Role): string {
  if (role === "admin") return adminToken();
  if (!fs.existsSync(KEYS_FILE)) {
    throw new Error(`no API keys at ${KEYS_FILE}: global-setup has not run`);
  }
  const keys = JSON.parse(fs.readFileSync(KEYS_FILE, "utf8")) as Partial<Record<Role, string>>;
  const token = keys[role];
  if (!token) throw new Error(`no API key minted for role "${role}"`);
  return token;
}

/** Marks the page as logged in (RequireAuth + Bearer token) before any app script runs. */
export async function loginAs(page: Page, role: Role): Promise<void> {
  const token = tokenFor(role);
  await page.addInitScript((t: string) => {
    sessionStorage.setItem("kk_session", "1");
    sessionStorage.setItem("auth_token", t);
  }, token);
}

export async function apiRequest(
  request: APIRequestContext,
  role: Role,
  method: string,
  apiPath: string,
  body?: unknown,
): Promise<APIResponse> {
  const base = process.env.KK_E2E_BASE_URL ?? "http://localhost:3000";
  return request.fetch(`${base}/api/v1${apiPath}`, {
    method,
    headers: { Authorization: `Bearer ${tokenFor(role)}` },
    data: body,
  });
}

export const test = base;
export { expect };
