#!/usr/bin/env node
// Builds the per-story table for CAPTURE_REPORT.md from docs/guide/specs/*.json, the screenshots on disk and STORIES.md.
//   node docs/guide/tools/report.mjs > /tmp/table.md
import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const guide = path.join(root, "docs/guide");
const stories = new Map();
for (const line of fs.readFileSync(path.join(guide, "STORIES.md"), "utf8").split("\n")) {
  const m = line.match(/^\| (U-\d+) \| (.+?) \| (.+?) \| (.+?) \|$/);
  if (m) stories.set(m[1], { id: m[1], title: m[2], persona: m[3], flags: m[4] });
}
const specs = fs.readdirSync(path.join(guide, "specs")).filter((f) => f.endsWith(".json")).sort();
const byStory = new Map();
for (const f of specs) {
  const spec = JSON.parse(fs.readFileSync(path.join(guide, "specs", f), "utf8"));
  const mm = spec.task.match(/^U-\d+/); if (!mm) continue; const base = mm[0];
  if (!byStory.has(base)) byStory.set(base, []);
  byStory.get(base).push(spec);
}
const png = (dir) => (fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith(".png")) : []);
const rows = [];
const totals = { stories: 0, captured: 0, partial: 0, blocked: 0, skipped: 0, shots: 0, annotated: 0, finals: 0, steps: 0 };
for (const [id, st] of [...stories].sort((a, b) => a[0].localeCompare(b[0]))) {
  const ss = byStory.get(id) || [];
  let steps = 0, shots = 0, annotated = 0, finals = 0, blocked = 0;
  const notes = [];
  for (const s of ss) {
    const files = png(path.join(guide, "screenshots", s.task));
    const clean = files.filter((f) => /^\d\d-/.test(f) && !f.endsWith("-annotated.png")).length;
    const anno = files.filter((f) => f.endsWith("-annotated.png")).length;
    const fin = files.filter((f) => f.startsWith("final-")).length;
    shots += clean; annotated += anno; finals += fin; steps += s.steps.length;
    for (const x of s.steps) {
      const c = typeof x.capture === "object" && x.capture ? x.capture : null;
      if (c && c.status === "BLOCKED") { blocked++; notes.push(`${s.task} step ${x.n}: ${(c.error || (c.gates?.evidence || []).join("; ") || "gate").slice(0, 160)}`); }
    }
    for (const x of s.steps) if (x.capture?.dialogOverflow) notes.push(`${s.task} step ${x.n}: dialog overflows viewport ${JSON.stringify(x.capture.dialogOverflow)}`);
  }
  const flags = st.flags;
  let status;
  if (!ss.length) status = /LAB|EXTERNAL/.test(flags) ? "skipped" : "blocked (no spec)";
  else if (blocked > 0 && shots === 0) status = "blocked";
  else if (blocked > 0) status = "captured with blocked steps";
  else status = "captured";
  const remainder = /LAB|EXTERNAL/.test(flags) && ss.length ? " (UI portion; lab/external remainder skipped)" : "";
  totals.stories++;
  if (status === "captured") totals[/LAB|EXTERNAL/.test(flags) ? "partial" : "captured"]++;
  else if (status.startsWith("blocked")) totals.blocked++;
  else if (status === "skipped") totals.skipped++;
  else totals.partial++;
  totals.shots += shots; totals.annotated += annotated; totals.finals += finals; totals.steps += steps;
  rows.push(`| ${id} | ${st.title} | ${ss.map((s) => s.task).join(", ") || "-"} | ${status}${remainder} | ${steps} | ${shots} | ${annotated} | ${finals} | ${flags} |` + (notes.length ? `\n|  | blocked/notes: ${notes.join(" // ").replace(/\|/g, "/")} | | | | | | | |` : ""));
}
console.log("| Story | Title | Specs | Status | Steps | Screenshots | Annotated | Finals (dark 1440 + light 375) | Flags |\n|---|---|---|---|---|---|---|---|---|");
console.log(rows.join("\n"));
console.log("\n<!-- totals " + JSON.stringify(totals) + " -->");
