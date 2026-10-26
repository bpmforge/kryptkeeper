import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { build, buildEntry, capabilitySummary } from "./build-catalogue.mjs";

const wasm = Buffer.from("fake-module");
const sha = crypto.createHash("sha256").update(wasm).digest("hex");
const manifest = (over = {}) =>
  Buffer.from(JSON.stringify({ id: "kryptkeeper.t", name: "T", publisher: "P", version: "1.0.0", artifact: { file: "plugin.wasm", sha256: sha }, capabilities: { receive_private_key: true, network: { hosts: [] }, file_write: [] }, ...over }));

test("entry pins the module and summarises capabilities", () => {
  const e = buildEntry({ manifestBytes: manifest(), wasmBytes: wasm, bundleBytes: Buffer.from("b"), baseUrl: "https://x.example/plugins/" });
  assert.equal(e.sha256, sha);
  assert.equal(e.wasm_url, "https://x.example/plugins/kryptkeeper.t/1.0.0/plugin.wasm");
  assert.deepEqual(e.capabilities, ["receive_private_key", "network"]);
  assert.equal(e.min_hub_version, undefined);
  assert.equal(buildEntry({ manifestBytes: manifest({ kind: "notify" }), wasmBytes: wasm, bundleBytes: Buffer.from("b"), baseUrl: "https://x" }).min_hub_version, "1.1.0");
  assert.deepEqual(capabilitySummary({}), []);
});

test("an unpinned module or a missing bundle is refused", () => {
  assert.throws(() => buildEntry({ manifestBytes: manifest(), wasmBytes: Buffer.from("other"), bundleBytes: Buffer.from("b"), baseUrl: "https://x" }), /pins/);
  assert.throws(() => buildEntry({ manifestBytes: manifest(), wasmBytes: wasm, bundleBytes: Buffer.alloc(0), baseUrl: "https://x" }), /bundle/);
});

test("build writes the tree with manifest bytes untouched", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cat-"));
  const dist = path.join(dir, "dist", "t");
  fs.mkdirSync(dist, { recursive: true });
  const m = manifest();
  fs.writeFileSync(path.join(dist, "manifest.json"), m);
  fs.writeFileSync(path.join(dist, "plugin.wasm"), wasm);
  fs.writeFileSync(path.join(dist, "manifest.json.bundle"), "bundle");
  const out = path.join(dir, "out");
  const cat = build({ dist: path.join(dir, "dist"), out, baseUrl: "https://x.example/plugins", now: new Date("2026-10-25T01:02:03.456Z") });
  assert.equal(cat.generated_at, "2026-10-25T01:02:03Z");
  assert.ok(fs.readFileSync(path.join(out, "kryptkeeper.t", "1.0.0", "manifest.json")).equals(m));
  assert.equal(JSON.parse(fs.readFileSync(path.join(out, "catalogue.json"), "utf8")).entries.length, 1);
});
