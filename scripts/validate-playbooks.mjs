#!/usr/bin/env node
// Lints docs/guides/migrate-from-*.md: each playbook needs the four required level-2
// headings, each with at least 3 non-blank lines of content.
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REQUIRED = ["Prerequisites", "Field mapping", "Rollback", "Verification query"];

export function lintPlaybook(text) {
  const lines = text.split(/\r?\n/);
  const errs = [];
  for (const h of REQUIRED) {
    const idx = lines.findIndex((l) => new RegExp(`^## ${h}\\s*$`).test(l));
    if (idx < 0) { errs.push(`missing heading "## ${h}"`); continue; }
    let n = 0;
    for (let i = idx + 1; i < lines.length && !/^## /.test(lines[i]); i++) if (lines[i].trim()) n++;
    if (n < 3) errs.push(`"## ${h}" has ${n} non-blank lines, need at least 3`);
  }
  return errs;
}

function main() {
  const dir = join(resolve(dirname(fileURLToPath(import.meta.url)), ".."), "docs", "guides");
  const files = readdirSync(dir).filter((f) => /^migrate-from-.*\.md$/.test(f)).sort();
  if (!files.length) { console.log("FAIL no docs/guides/migrate-from-*.md playbooks found"); process.exit(1); }
  let bad = false;
  for (const f of files) {
    const errs = lintPlaybook(readFileSync(join(dir, f), "utf8"));
    errs.forEach((e) => { console.log(`FAIL ${f}: ${e}`); bad = true; });
    if (!errs.length) console.log(`OK ${f}`);
  }
  process.exit(bad ? 1 : 0);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
