// W32-03: TypeScript SDK contract smoke. Uses ONLY the generated client
// (sdk/api-ts); the spec declares no response schemas, so bodies are read
// from the raw fetch Response returned by the generated *Raw() methods.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { CertificatesApi, Configuration } from "../../../../sdk/api-ts/src/index";

function fail(msg: string): never {
  console.error(`[sdk-smoke ts] FAIL ${msg}`);
  process.exit(1);
}

function env(name: string): string {
  const v = process.env[name];
  if (!v) fail(`${name} must be set`);
  return v;
}

async function main() {
  const hub = env("HUB_URL"), token = env("HUB_TOKEN"), caId = env("CA_ID"), templateId = env("TEMPLATE_ID"), csrDir = env("CSR_DIR");
  const api = new CertificatesApi(new Configuration({ basePath: `${hub}/api/v1`, accessToken: token }));

  const issued = new Set<string>();
  let first = "";
  for (let i = 1; i <= 5; i++) {
    const csrPem = readFileSync(join(csrDir, `csr-${i}.pem`), "utf8");
    const res = await api.issueCertificateRaw({ issueCertificateRequest: { caId, templateId, csrPem } });
    const text = await res.raw.text();
    if (res.raw.status !== 201) fail(`issue ${i}: status ${res.raw.status} (want 201): ${text}`);
    const fp = JSON.parse(text)?.data?.fingerprint_sha256;
    if (!fp) fail(`issue ${i}: no fingerprint in ${text}`);
    issued.add(fp);
    if (!first) first = fp;
  }

  const seen = new Set<string>();
  let requests = 0;
  let cursor: number | undefined;
  for (;;) {
    const res = await api.listCertificatesRaw({ limit: 2, cursor });
    requests++;
    const page = JSON.parse(await res.raw.text());
    for (const c of page?.data ?? []) seen.add(c.fingerprint_sha256);
    const next = page?.meta?.next_cursor;
    if (next === null || next === undefined || next === "") break;
    cursor = Number(next);
    if (!Number.isInteger(cursor)) fail(`list: non-integer next_cursor ${next}`);
    if (requests > 100) fail("list: pagination did not terminate");
  }
  if (requests < 3) fail(`list: ${requests} requests, want >= 3 (>= 2 pages)`);
  for (const fp of issued) if (!seen.has(fp)) fail(`list: issued fingerprint ${fp} not seen across pages`);

  const rev = await api.revokeCertificateRaw({ fingerprint: first, revokeCertificateRequest: { reasonCode: 1 } });
  const revText = await rev.raw.text();
  if (rev.raw.status !== 200) fail(`revoke: status ${rev.raw.status} (want 200, no approval gate expected): ${revText}`);
  const got = await api.getCertificateRaw({ fingerprint: first });
  const gotText = await got.raw.text();
  const d = JSON.parse(gotText)?.data;
  if (d?.renewal_status !== "revoked" || !d?.revoked_at) fail(`get after revoke: renewal_status ${d?.renewal_status}, body ${gotText}`)
  console.log(`[sdk-smoke ts] ok: issued 5, listed in ${requests} requests, revoked 1`);
}

main().catch((e) => fail(String(e?.stack ?? e)));
