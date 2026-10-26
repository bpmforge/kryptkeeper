// Converts the gated guide screenshots that the site uses into WebP under site/shots/<spec>/.
// Hub covers and walkthrough thumbnails are cropped dark finals (cover-dark*.webp) and are always rebuilt;
// step images are converted once and skipped when present (use --force to redo them).
// Uses the Chromium that run-spec.mjs already drives, so the site needs no image library.
// Usage: node site/tools/images.mjs --shots <dir containing U-xx/ folders> [--quality 0.8]
import { chromium } from "../../ui/node_modules/playwright-core/index.mjs";
import fs from "node:fs";
import path from "node:path";
import { loadContent, walkthroughImages } from "./content.mjs";

const args = process.argv.slice(2);
const opt = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
const shots = opt("--shots");
const quality = Number(opt("--quality", "0.8"));
if (!shots) { console.error("usage: images.mjs --shots <dir>"); process.exit(2); }

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const content = loadContent(ROOT);
const all = walkthroughImages(content);
const jobs = all.filter(({ out, crop }) => crop || args.includes("--force") || !fs.existsSync(path.join(ROOT, "site", out)));

// Drop cover/thumbnail files nothing references any more.
const keep = new Set(all.map((j) => j.out));
const shotsRoot = path.join(ROOT, "site/shots");
let pruned = 0;
for (const dir of fs.existsSync(shotsRoot) ? fs.readdirSync(shotsRoot, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name) : []) {
  for (const f of fs.readdirSync(path.join(shotsRoot, dir))) {
    if (/^cover-dark.*\.webp$/.test(f) && !keep.has(`shots/${dir}/${f}`)) { fs.rmSync(path.join(shotsRoot, dir, f)); pruned++; }
  }
}

const browser = await chromium.launch();
const page = await browser.newPage();
let bytes = 0, missing = 0;
for (const { src, out, crop, width, height } of jobs) {
  const file = path.join(shots, src);
  if (!fs.existsSync(file)) { console.error(`missing screenshot: ${src}`); missing++; continue; }
  const b64 = fs.readFileSync(file).toString("base64");
  const data = await page.evaluate(async ({ b64, quality, crop, width, height }) => {
    const img = new Image();
    img.src = `data:image/png;base64,${b64}`;
    await img.decode();
    const c = document.createElement("canvas");
    const ctx = c.getContext("2d");
    ctx.imageSmoothingQuality = "high";
    if (crop) {
      c.width = width; c.height = height;
      ctx.drawImage(img, crop.x, crop.y, crop.w, crop.h, 0, 0, width, height);
    } else {
      c.width = img.naturalWidth; c.height = img.naturalHeight;
      ctx.drawImage(img, 0, 0);
    }
    return c.toDataURL("image/webp", quality).split(",")[1];
  }, { b64, quality, crop, width, height });
  const dst = path.join(ROOT, "site", out);
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  const buf = Buffer.from(data, "base64");
  fs.writeFileSync(dst, buf);
  bytes += buf.length;
}
await browser.close();
console.log(`converted ${jobs.length - missing} images, ${(bytes / 1048576).toFixed(1)} MB${missing ? `, ${missing} missing` : ""}${pruned ? `, pruned ${pruned} unreferenced` : ""}`);
process.exit(missing ? 1 : 0);
