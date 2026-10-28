import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { payloadFiles, stagePayload, scanPayload, loadPrivateRef, privateRef } from "./payload.mjs";

const LAB = String.raw`labhost-\d+|secretlab\.example`;

function site(extra = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kk-payload-"));
  const files = {
    "index.html": "<h1>ok</h1>",
    "_headers": "/*\n  X-Frame-Options: DENY\n",
    "_redirects": "/old /new 301\n",
    ".well-known/security.txt": "Contact: mailto:security@kryptkeeper.io\n",
    "proof/index.html": "<p>proof</p>",
    "shots/a.png": "PNG",
    "shots/_sheet.html": "<p>scratch</p>",
    "tools/build.mjs": "// pattern labhost-1",
    "tools/private-ref.txt": LAB,
    "content/proof.json": "{}",
    ".DS_Store": "x",
    "style.css.bak": "x",
    ...extra,
  };
  for (const [f, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
    fs.writeFileSync(path.join(dir, f), body);
  }
  return dir;
}

test("payload keeps pages and Pages config, drops tooling, inputs and scratch files", () => {
  assert.deepEqual(payloadFiles(site()), [
    ".well-known/security.txt", "_headers", "_redirects", "index.html", "proof/index.html", "shots/a.png",
  ]);
});

test("a planted file under tools/ is never staged, even one that leaks", () => {
  const dir = site({ "tools/notes.html": "<p>labhost-7 /Users/someone</p>" });
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "kk-stage-"));
  const files = stagePayload(dir, out);
  assert.ok(!files.some((f) => f.startsWith("tools/")));
  assert.ok(!fs.existsSync(path.join(out, "tools")));
  assert.deepEqual(scanPayload(out, files, loadPrivateRef(dir)), []);
});

test("a leak in an uploaded page is rejected", () => {
  const dir = site({ "proof/index.html": "<p>ran on labhost-12</p>" });
  const problems = scanPayload(dir, payloadFiles(dir), loadPrivateRef(dir));
  assert.equal(problems.length, 1);
  assert.match(problems[0], /^proof\/index\.html: private lab or local reference \("labhost-12"\)/);
});

test("binary files are scanned too", () => {
  const dir = site({ "shots/b.png": Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0]), Buffer.from("/Users/someone/x.png")]) });
  fs.rmSync(path.join(dir, "tools/private-ref.txt"));
  const problems = scanPayload(dir, payloadFiles(dir), privateRef(dir));
  assert.deepEqual(problems, ['shots/b.png: private lab or local reference ("/Users/")']);
});

test("secrets and deploy literals are rejected", () => {
  const dir = site({
    // Split so secret scanners do not flag the fixture itself.
    "a.html": "-----BEGIN EC " + "PRIVATE KEY-----\nAAAA\n",
    "b.html": "id AKIA" + "ABCDEFGHIJKLMNOP",
    "c.html": "token value-123-abc",
  });
  const problems = scanPayload(dir, payloadFiles(dir), privateRef(dir), ["value-123-abc"]);
  assert.deepEqual(problems, [
    "a.html: private key block",
    "b.html: AWS access key id",
    "c.html: contains a deploy secret",
  ]);
});

test("without private-ref.txt the generic pattern still catches local paths and addresses", () => {
  const dir = site();
  fs.rmSync(path.join(dir, "tools/private-ref.txt"));
  assert.equal(loadPrivateRef(dir), null);
  const ref = privateRef(dir);
  assert.ok(ref.test("/Users/x") && ref.test("192.168.1.5") && ref.test("10.0.0.1"));
  assert.ok(!ref.test("labhost-1"));
});
