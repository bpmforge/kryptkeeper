import { execFileSync } from "node:child_process";
import type { APIRequestContext } from "@playwright/test";
import { apiRequest } from "../fixtures";

export type Seeded = { caId: string; templateId: string };

type Named = { id: string; status?: string; active?: boolean };

async function listData(request: APIRequestContext, path: string): Promise<Named[]> {
  const res = await apiRequest(request, "admin", "GET", path);
  if (res.status() !== 200) throw new Error(`GET ${path} -> HTTP ${res.status()} ${await res.text()}`);
  return ((await res.json()) as { data: Named[] }).data ?? [];
}

/** Reuse an active CA and an active template; create them (bodies match Onboarding.tsx) only when absent. */
export async function ensureCaAndTemplate(request: APIRequestContext): Promise<Seeded> {
  let ca = (await listData(request, "/cas")).find((c) => c.status === "active");
  if (!ca) {
    const res = await apiRequest(request, "admin", "POST", "/cas", {
      type: "root",
      subject_cn: "kk e2e root",
      subject_org: "kk-e2e",
      algorithm: "ECDSA-P256",
      validity: "10y",
    });
    if (res.status() !== 201) throw new Error(`create CA -> HTTP ${res.status()} ${await res.text()}`);
    ca = ((await res.json()) as { data: Named }).data;
  }
  let tpl = (await listData(request, "/templates")).find((t) => t.active !== false);
  if (!tpl) {
    const res = await apiRequest(request, "admin", "POST", "/templates", {
      name: "kk-e2e-server",
      display_name: "kk-e2e-server",
      key_usage: ["digitalSignature", "keyEncipherment"],
      extended_key_usage: ["serverAuth"],
      allowed_algorithms: ["ECDSA", "RSA"],
      validity_period: "90d",
      auto_enroll: false,
      active: true,
    });
    if (res.status() !== 201) throw new Error(`create template -> HTTP ${res.status()} ${await res.text()}`);
    tpl = ((await res.json()) as { data: Named }).data;
  }
  return { caId: ca.id, templateId: tpl.id };
}

function csrFor(cn: string): string {
  return execFileSync("openssl", [
    "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
    "-nodes", "-keyout", "/dev/null", "-subj", `/CN=${cn}`,
  ], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
}

/** Issue n certificates with CN `<prefix>-<i>.example.test`; returns their SHA-256 fingerprints. */
export async function issueCerts(
  request: APIRequestContext,
  seeded: Seeded,
  n: number,
  prefix: string,
): Promise<string[]> {
  const fps: string[] = [];
  for (let i = 0; i < n; i++) {
    const res = await apiRequest(request, "admin", "POST", "/certificates", {
      ca_id: seeded.caId,
      template_id: seeded.templateId,
      csr_pem: csrFor(`${prefix}-${i}.example.test`),
    });
    if (res.status() !== 201) {
      throw new Error(
        `issue ${prefix}-${i}: expected 201, got HTTP ${res.status()} (202 means an approval policy is pending) ${await res.text()}`,
      );
    }
    const fp = ((await res.json()) as { data: { fingerprint_sha256: string } }).data.fingerprint_sha256;
    if (!fp) throw new Error(`issue ${prefix}-${i}: response had no fingerprint_sha256`);
    fps.push(fp);
  }
  return fps;
}
