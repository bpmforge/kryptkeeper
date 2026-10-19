import test from "node:test";
import assert from "node:assert/strict";
import { lintPlaybook, REQUIRED } from "./validate-playbooks.mjs";

const body = "a\nb\nc\n";
const good = REQUIRED.map((h) => `## ${h}\n${body}`).join("\n");

test("good playbook passes", () => {
  assert.deepEqual(lintPlaybook(good), []);
});

test("missing heading and thin section fail", () => {
  const bad = good.replace("## Rollback", "## Back out").replace(/## Prerequisites\na\nb\nc\n/, "## Prerequisites\na\n");
  const errs = lintPlaybook(bad);
  assert.ok(errs.some((e) => e.includes("Rollback")));
  assert.ok(errs.some((e) => e.includes("Prerequisites")));
});
