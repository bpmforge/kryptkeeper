import { test } from "node:test";
import assert from "node:assert/strict";
import { stampRelease, findStaleVersions } from "./release.mjs";

test("stampRelease rewrites every release spot", () => {
  const html = `<a href="https://github.com/bpmforge/kryptkeeper/releases/tag/v0.9.4">Download v0.9.4</a>
cosign verify ghcr.io/bpmforge/kryptkeeper:0.9.4 "release.yml@refs/tags/v0.9.4" <span>v0.9.4-rc.2 status</span>`;
  const out = stampRelease(html, "1.0.0");
  assert.equal(findStaleVersions(out, "1.0.0").length, 0);
  assert.match(out, /releases\/tag\/v1\.0\.0/);
  assert.match(out, /kryptkeeper:1\.0\.0/);
});

test("findStaleVersions ignores IP addresses and catches stray versions", () => {
  assert.deepEqual(findStaleVersions("scan 10.0.0.0/24 and 127.0.0.1", "1.0.0"), []);
  assert.deepEqual(findStaleVersions("a Kryptkeeper 0.21.0 hub, see v0.9.3", "1.0.0"), ["Kryptkeeper 0.21.0", "v0.9.3"]);
  assert.deepEqual(findStaleVersions("Download v1.0.0", "1.0.0"), []);
});
