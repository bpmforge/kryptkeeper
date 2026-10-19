#!/usr/bin/env node
// Validates RFC 9116 security.txt copies and the SECURITY.md supported-versions table.
// Usage: node scripts/check-security-txt.mjs [paths...] [--self-test]
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_PATHS = ["site/.well-known/security.txt", "ui/public/.well-known/security.txt"];
const MAX_DAYS = 366;

function parseFields(text) {
  const fields = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith("#")) continue;
    const m = line.match(/^([A-Za-z-]+):\s*(.+)$/);
    if (m) fields.push([m[1].toLowerCase(), m[2].trim()]);
  }
  return fields;
}

export function checkSecurityTxt(text, now = new Date()) {
  const errs = [];
  const f = parseFields(text);
  const get = (k) => f.filter(([n]) => n === k).map(([, v]) => v);
  const contacts = get("contact");
  const expires = get("expires");
  const canon = get("canonical");
  const policy = get("policy");
  if (!contacts.length) errs.push("missing Contact");
  for (const c of contacts) {
    if (!c.startsWith("mailto:") && !c.startsWith("https://")) errs.push(`Contact must be mailto: or https://: ${c}`);
  }
  if (expires.length !== 1) errs.push(`need exactly one Expires, found ${expires.length}`);
  if (!canon.length) errs.push("missing Canonical");
  for (const c of canon) {
    if (!c.startsWith("https://")) errs.push(`Canonical must be https://: ${c}`);
    if (!c.endsWith("/.well-known/security.txt")) errs.push(`Canonical must end with /.well-known/security.txt: ${c}`);
  }
  if (!policy.length) errs.push("missing Policy");
  for (const p of policy) if (!p.startsWith("https://")) errs.push(`Policy must be https://: ${p}`);
  if (expires.length === 1) {
    const d = new Date(expires[0]);
    if (Number.isNaN(d.getTime())) errs.push(`Expires not ISO 8601: ${expires[0]}`);
    else if (d <= now) errs.push(`Expires is in the past: ${expires[0]}`);
    else if ((d - now) / 86400000 > MAX_DAYS) errs.push(`Expires more than ${MAX_DAYS} days out: ${expires[0]}`);
  }
  return errs;
}

function parseVer(v) {
  const m = v.match(/^(\d+)\.(\d+)/);
  return m ? [Number(m[1]), Number(m[2])] : null;
}

export function checkSupportedTable(md, latest) {
  const errs = [];
  const sec = md.match(/## Supported Versions([\s\S]*?)(?=\n## |$)/);
  if (!sec) return ["no Supported Versions section"];
  const rows = sec[1].split("\n").filter((l) => l.trim().startsWith("|"))
    .map((l) => l.split("|").slice(1, -1).map((c) => c.trim()))
    .filter((c) => c.length >= 2 && !/^[-: ]+$/.test(c[0]) && c[0] !== "Version");
  const yes = rows.filter((c) => /yes/i.test(c[1]) && !/\bno\b/i.test(c[1]));
  const lv = parseVer(latest);
  for (const r of yes) {
    if (/^1\.x/.test(r[0]) && lv[0] === 0) errs.push("table claims 1.x supported but latest major is 0");
  }
  const supported = yes.map((r) => r[0].match(/^(\d+)\.(\d+)\.x/)).filter(Boolean).map((m) => [Number(m[1]), Number(m[2])]);
  if (!supported.length) errs.push("no supported <major>.<minor>.x row");
  // The supported row must be the newest tag's minor, or ahead of it while a release is being cut.
  else if (!supported.some(([a, b]) => a > lv[0] || (a === lv[0] && b >= lv[1]))) {
    errs.push(`no supported row covers latest version ${latest}`);
  }
  return errs;
}

function latestVersion() {
  try {
    const out = execFileSync("git", ["tag", "--list", "v[0-9]*", "--sort=-v:refname"], { cwd: root, encoding: "utf8" });
    const first = out.split("\n").find(Boolean);
    if (first) return first.replace(/^v/, "");
  } catch { /* fall through to CHANGELOG */ }
  const cl = readFileSync(resolve(root, "CHANGELOG.md"), "utf8");
  for (const m of cl.matchAll(/^## \[([^\]]+)\]/gm)) if (!/unreleased/i.test(m[1])) return m[1];
  throw new Error("cannot determine latest version");
}

function selfTest() {
  const now = new Date("2026-10-16T00:00:00Z");
  const good = `Contact: mailto:a@b.io\nExpires: 2027-04-16T00:00:00.000Z\nCanonical: https://x.io/.well-known/security.txt\nPolicy: https://x.io/p\n`;
  const cases = [
    ["valid passes", good, true],
    ["missing Expires", good.replace(/Expires.*\n/, ""), false],
    ["expired", good.replace("2027-04-16", "2026-01-01"), false],
    ["over 366 days", good.replace("2027-04-16", "2028-04-16"), false],
    ["http Canonical", good.replace("https://x.io/.well", "http://x.io/.well"), false],
    ["missing Policy", good.replace(/Policy.*\n/, ""), false],
    ["bad Contact scheme", good.replace("mailto:a@b.io", "tel:1"), false],
  ];
  let bad = 0;
  for (const [name, txt, ok] of cases) {
    const pass = checkSecurityTxt(txt, now).length === 0;
    if (pass !== ok) { console.error(`SELF-TEST FAIL: ${name}`); bad++; }
  }
  const tbl = (rows) => `## Supported Versions\n\n| Version | Supported |\n|---|---|\n${rows}\n\n## Next\n`;
  const tcases = [
    ["table ok", tbl("| 0.15.x | ✅ Yes |\n| < 0.15 | ❌ No |"), "0.15.0", true],
    ["table ahead of tag ok", tbl("| 0.21.x | ✅ Yes |"), "0.15.0", true],
    ["table behind tag", tbl("| 0.9.x | ✅ Yes |"), "0.15.0", false],
    ["1.x claimed on 0.x", tbl("| 1.x | ✅ Yes |"), "0.15.0", false],
    ["no section", "# nothing", "0.15.0", false],
  ];
  for (const [name, md, latest, ok] of tcases) {
    const pass = checkSupportedTable(md, latest).length === 0;
    if (pass !== ok) { console.error(`SELF-TEST FAIL: ${name}`); bad++; }
  }
  if (bad) process.exit(1);
  console.log(`OK self-test (${cases.length + tcases.length} cases)`);
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes("--self-test")) return selfTest();
  const paths = args.filter((a) => !a.startsWith("--"));
  const files = paths.length ? paths : DEFAULT_PATHS;
  let failed = false;
  const fail = (file, why) => { console.log(`FAIL ${file}: ${why}`); failed = true; };
  const bufs = files.map((p) => readFileSync(resolve(root, p)));
  files.forEach((p, i) => {
    const errs = checkSecurityTxt(bufs[i].toString("utf8"));
    errs.forEach((e) => fail(p, e));
    if (!errs.length) console.log(`OK ${p}`);
  });
  if (!paths.length) {
    if (bufs[0].equals(bufs[1])) console.log("OK copies are byte-identical");
    else fail(files.join(" vs "), "copies differ");
  }
  const latest = latestVersion();
  const errs = checkSupportedTable(readFileSync(resolve(root, "SECURITY.md"), "utf8"), latest);
  errs.forEach((e) => fail("SECURITY.md", e));
  if (!errs.length) console.log(`OK SECURITY.md supported-versions (latest ${latest})`);
  process.exit(failed ? 1 : 0);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
