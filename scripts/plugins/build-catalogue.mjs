#!/usr/bin/env node
// Build the signed-plugin catalogue tree (W38-11, D-328) from the output of
// `make plugins` (dist/plugins/<name>/{plugin.wasm,manifest.json}) once
// scripts/sign-plugins.sh has added manifest.json.bundle beside each manifest.
//
//   node scripts/plugins/build-catalogue.mjs --dist dist/plugins \
//     --out dist/plugin-catalogue --base-url https://kryptkeeper.io/plugins
//
// Writes <out>/catalogue.json and, per plugin, <out>/<id>/<version>/
// {manifest.json,manifest.json.bundle,plugin.wasm}. The catalogue itself is
// signed afterwards (cosign sign-blob over the exact catalogue.json bytes ->
// catalogue.json.bundle); this script never signs, so it holds no key.
// The same tree is published at <base-url> (the site) and as one release
// asset, which is what an air-gapped hub imports.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

// Kinds other than delivery arrived with hub 1.1 (D-321); an older hub would
// refuse the manifest's unknown "kind" field, so the catalogue says so up
// front instead of letting the install fail.
export const NEW_KIND_MIN_HUB = "1.1.0";

const CAPS = ["receive_private_key", "trust_store", "elevated_exec", "remote_exec", "network", "file_write", "tls_verify", "provide_credentials"];

export function capabilitySummary(caps = {}) {
  return CAPS.filter((c) => (Array.isArray(caps[c]) ? caps[c].length > 0 : Boolean(caps[c])));
}

/** Pure: one catalogue entry from a pinned, signed plugin directory. */
export function buildEntry({ manifestBytes, wasmBytes, bundleBytes, baseUrl, description }) {
  const m = JSON.parse(manifestBytes.toString("utf8"));
  const sha = crypto.createHash("sha256").update(wasmBytes).digest("hex");
  if (m.artifact?.sha256 !== sha) {
    throw new Error(`${m.id}: manifest pins ${m.artifact?.sha256}, module is ${sha} (run make plugins first)`);
  }
  if (!bundleBytes?.length) throw new Error(`${m.id}: no manifest.json.bundle (run scripts/sign-plugins.sh first)`);
  const kind = m.kind || "delivery";
  const dir = `${baseUrl.replace(/\/+$/, "")}/${m.id}/${m.version}`;
  const entry = {
    id: m.id,
    kind,
    name: m.name,
    publisher: m.publisher,
    version: m.version,
    description: description || `${m.name} (${kind} plugin)`,
    manifest_url: `${dir}/manifest.json`,
    wasm_url: `${dir}/plugin.wasm`,
    bundle_url: `${dir}/manifest.json.bundle`,
    sha256: sha,
    capabilities: capabilitySummary(m.capabilities),
  };
  if (kind !== "delivery") entry.min_hub_version = NEW_KIND_MIN_HUB;
  return entry;
}

function firstLine(file) {
  if (!fs.existsSync(file)) return "";
  const line = fs.readFileSync(file, "utf8").split("\n").find((l) => l.trim() && !l.startsWith("#"));
  return line ? line.trim().slice(0, 240) : "";
}

export function build({ dist, plugins, out, baseUrl, now = new Date() }) {
  const entries = [];
  fs.mkdirSync(out, { recursive: true });
  for (const name of fs.readdirSync(dist).sort()) {
    const dir = path.join(dist, name);
    const manifestFile = path.join(dir, "manifest.json");
    if (!fs.existsSync(manifestFile)) continue;
    const manifestBytes = fs.readFileSync(manifestFile);
    const wasmBytes = fs.readFileSync(path.join(dir, "plugin.wasm"));
    const bundleFile = path.join(dir, "manifest.json.bundle");
    const bundleBytes = fs.existsSync(bundleFile) ? fs.readFileSync(bundleFile) : Buffer.alloc(0);
    const entry = buildEntry({ manifestBytes, wasmBytes, bundleBytes, baseUrl, description: plugins ? firstLine(path.join(plugins, name, "README.md")) : "" });
    const dest = path.join(out, entry.id, entry.version);
    fs.mkdirSync(dest, { recursive: true });
    // Copied byte for byte: the signature covers these exact bytes.
    fs.writeFileSync(path.join(dest, "manifest.json"), manifestBytes);
    fs.writeFileSync(path.join(dest, "manifest.json.bundle"), bundleBytes);
    fs.writeFileSync(path.join(dest, "plugin.wasm"), wasmBytes);
    entries.push(entry);
  }
  if (!entries.length) throw new Error(`no plugins found under ${dist}`);
  entries.sort((a, b) => a.id.localeCompare(b.id) || a.version.localeCompare(b.version));
  const catalogue = { version: 1, generated_at: now.toISOString().replace(/\.\d+Z$/, "Z"), entries };
  fs.writeFileSync(path.join(out, "catalogue.json"), JSON.stringify(catalogue, null, 2) + "\n");
  return catalogue;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const arg = (n, d) => {
    const i = process.argv.indexOf(`--${n}`);
    return i > 0 ? process.argv[i + 1] : d;
  };
  const cat = build({
    dist: arg("dist", "dist/plugins"),
    plugins: arg("plugins", "plugins"),
    out: arg("out", "dist/plugin-catalogue"),
    baseUrl: arg("base-url", "https://kryptkeeper.io/plugins"),
  });
  console.log(`catalogue.json: ${cat.entries.length} plugins`);
}
