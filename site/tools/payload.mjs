// Decides which files under site/ are uploaded to Cloudflare Pages, and scans that
// exact payload for private references and secrets before anything is deployed.
// Used by deploy.mjs (the only supported way to deploy) and by build.mjs --check.
import fs from "node:fs";
import path from "node:path";

// Top-level folders that are build inputs or tooling, never web content.
const NEVER_TOP = new Set(["tools", "content"]);
// Editor, OS and scratch leftovers, wherever they are.
const JUNK = /(\.bak|\.orig|\.rej|\.swp|\.tmp|~)$|^\.DS_Store$|^Thumbs\.db$/i;

// Returns the site-relative paths (forward slashes) that make up the deploy payload.
export function payloadFiles(siteDir) {
  const files = [];
  const walk = (dir, rel) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (!rel && NEVER_TOP.has(e.name)) continue;
      // Dotfiles stay out, except RFC 8615 .well-known (security.txt).
      if (e.name.startsWith(".") && r !== ".well-known") continue;
      // Underscore files are Pages config only at the top (_headers, _redirects);
      // elsewhere they are scratch pages such as shots/_sheet.html.
      if (rel && e.name.startsWith("_")) continue;
      if (JUNK.test(e.name)) continue;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) walk(path.join(dir, e.name), r);
      else if (e.isFile()) files.push(r);
    }
  };
  walk(siteDir, "");
  return files.sort();
}

// Copies the payload into outDir (created fresh) and returns the file list.
export function stagePayload(siteDir, outDir) {
  fs.rmSync(outDir, { recursive: true, force: true });
  const files = payloadFiles(siteDir);
  for (const f of files) {
    const dst = path.join(outDir, f);
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    fs.copyFileSync(path.join(siteDir, f), dst);
  }
  return files;
}

// Generic checks that hold in any checkout: local paths and private addresses.
const GENERIC_REF = String.raw`192\.168\.\d|\b10\.\d+\.\d+\.\d+|\/Users\/|claude-\d+`;

// The full lab-name pattern lives in site/tools/private-ref.txt, which the public
// snapshot leaves out (it names the lab). Returns null when the file is absent.
export function loadPrivateRef(siteDir) {
  const f = path.join(siteDir, "tools", "private-ref.txt");
  return fs.existsSync(f) ? new RegExp(fs.readFileSync(f, "utf8").trim(), "i") : null;
}

export function privateRef(siteDir) {
  return loadPrivateRef(siteDir) ?? new RegExp(GENERIC_REF, "i");
}

const SECRETS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "private key block"],
  [/\bAKIA[0-9A-Z]{16}\b/, "AWS access key id"],
  [/\bgh[pousr]_[A-Za-z0-9]{36,}\b/, "GitHub token"],
  [/\bxox[abposr]-[A-Za-z0-9-]{10,}/, "Slack token"],
  [/CLOUDFLARE_API_TOKEN\s*=\s*\S/, "Cloudflare token assignment"],
];

// Scans every payload file (binary files too, read as latin1, so metadata such as an
// image's embedded path is caught). `literals` are exact strings that must never
// appear, such as the deploy token itself. Returns a list of problems.
export function scanPayload(dir, files, ref, literals = []) {
  const problems = [];
  for (const f of files) {
    const text = fs.readFileSync(path.join(dir, f)).toString("latin1");
    const m = text.match(ref);
    if (m) problems.push(`${f}: private lab or local reference ("${m[0]}")`);
    for (const [re, what] of SECRETS) if (re.test(text)) problems.push(`${f}: ${what}`);
    for (const lit of literals) if (lit && text.includes(lit)) problems.push(`${f}: contains a deploy secret`);
  }
  return problems;
}
