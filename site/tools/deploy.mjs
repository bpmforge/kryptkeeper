// The only supported way to deploy kryptkeeper.io. Checks the site, stages the
// deploy payload (payload.mjs) into a temporary folder, scans every staged file
// for private references and secrets, and only then uploads that folder.
// Usage: node site/tools/deploy.mjs [--branch <name>] [--dry-run] [--allow-dirty]
//   --branch     Pages branch (default main; any other name is a preview deploy)
//   --dry-run    stage and scan, print the payload size, upload nothing
//   --allow-dirty  deploy with uncommitted changes under site/ (preview only)
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadPrivateRef, scanPayload, stagePayload } from "./payload.mjs";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const SITE = path.join(ROOT, "site");
const CONFIG = path.join(os.homedir(), ".config", "kryptkeeper-site");
const WRANGLER = "wrangler@4.144.0";

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const branch = opt("--branch") ?? "main";
const dryRun = args.includes("--dry-run");
const fail = (msg) => { console.error(`deploy: ${msg}`); process.exit(1); };
const run = (cmd, argv, extra = {}) => spawnSync(cmd, argv, { cwd: ROOT, stdio: "inherit", ...extra });
const git = (...a) => spawnSync("git", a, { cwd: ROOT, encoding: "utf8" }).stdout.trim();

// The lab-name pattern must be present: a deploy is never guarded by the generic
// fallback alone.
const ref = loadPrivateRef(SITE);
if (!ref) fail("site/tools/private-ref.txt is missing; deploy from the development repository");

if (git("status", "--porcelain", "--", "site") && !args.includes("--allow-dirty")) {
  fail("uncommitted changes under site/; commit them or pass --allow-dirty for a preview");
}
if (branch === "main" && args.includes("--allow-dirty")) fail("--allow-dirty is for preview branches only");

const checks = branch === "main" ? ["--check", "--check-release"] : ["--check"];
if (run(process.execPath, [path.join(SITE, "tools", "build.mjs"), ...checks]).status !== 0) {
  fail(`build.mjs ${checks.join(" ")} failed`);
}

const tokenFile = path.join(CONFIG, "cloudflare-token");
const token = process.env.CLOUDFLARE_API_TOKEN ?? (fs.existsSync(tokenFile) ? fs.readFileSync(tokenFile, "utf8").trim() : "");
const accountFile = path.join(CONFIG, "account-id");
const account = process.env.CLOUDFLARE_ACCOUNT_ID ?? (fs.existsSync(accountFile) ? fs.readFileSync(accountFile, "utf8").trim() : "");

const stage = fs.mkdtempSync(path.join(os.tmpdir(), "kk-site-deploy-"));
const files = stagePayload(SITE, stage);
const problems = scanPayload(stage, files, ref, [token, account]);
if (problems.length) {
  fs.rmSync(stage, { recursive: true, force: true });
  fail(`refusing to deploy, ${problems.length} problem(s):\n  ${problems.join("\n  ")}`);
}
const bytes = files.reduce((n, f) => n + fs.statSync(path.join(stage, f)).size, 0);
console.log(`deploy: payload ${files.length} files, ${(bytes / 1048576).toFixed(1)} MiB, scan clean`);

if (dryRun) {
  fs.rmSync(stage, { recursive: true, force: true });
  process.exit(0);
}
if (!token) fail(`no Cloudflare token (set CLOUDFLARE_API_TOKEN or create ${tokenFile})`);
if (!account) fail(`no Cloudflare account id (set CLOUDFLARE_ACCOUNT_ID or create ${accountFile})`);

const res = run("npx", ["-y", WRANGLER, "pages", "deploy", stage, "--project-name", "kryptkeeper-site",
  "--branch", branch, "--commit-hash", git("rev-parse", "HEAD"), "--commit-message", git("log", "-1", "--format=%s")],
  { env: { ...process.env, CLOUDFLARE_API_TOKEN: token, CLOUDFLARE_ACCOUNT_ID: account } });
fs.rmSync(stage, { recursive: true, force: true });
process.exit(res.status ?? 1);
