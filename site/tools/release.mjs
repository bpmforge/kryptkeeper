// The site's release version comes from site/content/release.json only.
// stampRelease rewrites every version-bearing spot in a hand-written page; findStaleVersions
// reports any other version string so a forgotten "v0.9.4" fails --check instead of shipping.
import fs from "node:fs";
import path from "node:path";

export function loadRelease(root) {
  const r = JSON.parse(fs.readFileSync(path.join(root, "site/content/release.json"), "utf8"));
  if (!/^\d+\.\d+\.\d+$/.test(r.version || "")) throw new Error(`release.json: bad version ${JSON.stringify(r.version)}`);
  return r;
}

// Spots that carry the release: release/tag URLs, workflow refs, image tags, and visible "vX.Y.Z" text.
const STAMP = /(releases\/tag\/v|refs\/tags\/v|ghcr\.io\/bpmforge\/kryptkeeper(?:-[a-z]+)?:|\bv)(\d+\.\d+\.\d+(?:-rc\.\d+)?)\b/g;

export function stampRelease(html, version) {
  return html.replace(STAMP, (_, prefix) => `${prefix}${version}`);
}

// Any semver-looking version that isn't the release, outside IP addresses (which never carry a "v").
const ANY = /(?:\bv|kryptkeeper(?:-[a-z]+)?:|Kryptkeeper )(\d+\.\d+\.\d+(?:-rc\.\d+)?)\b/g;

export function findStaleVersions(html, version) {
  const found = [];
  for (const m of html.matchAll(ANY)) if (m[1] !== version) found.push(m[0]);
  return found;
}

export async function releaseExists({ version, repo }) {
  const url = `https://github.com/${repo}/releases/tag/v${version}`;
  const res = await fetch(url, { method: "HEAD", redirect: "follow" });
  return { url, ok: res.status === 200, status: res.status };
}
