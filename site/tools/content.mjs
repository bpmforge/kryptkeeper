// Loads site/content/hubs.json plus the capture specs it references, and validates the two against each other.
// Shared by build.mjs (pages) and images.mjs (screenshot conversion); node: builtins only.
import fs from "node:fs";
import path from "node:path";
import { loadPrivateRef } from "./payload.mjs";

const SPECS_DIR = "docs/guide/specs";

export function loadContent(root) {
  const hubsFile = JSON.parse(fs.readFileSync(path.join(root, "site/content/hubs.json"), "utf8"));
  const specs = new Map();
  const wanted = new Set();
  for (const hub of hubsFile.hubs ?? []) {
    for (const w of hub.walkthroughs ?? []) for (const id of w.specs ?? []) wanted.add(id);
  }
  for (const id of wanted) {
    const file = path.join(root, SPECS_DIR, `${id}.json`);
    if (fs.existsSync(file)) specs.set(id, JSON.parse(fs.readFileSync(file, "utf8")));
  }
  const captionsFile = path.join(root, "site/content/captions.json");
  const captions = fs.existsSync(captionsFile) ? JSON.parse(fs.readFileSync(captionsFile, "utf8")) : {};
  const proofFile = path.join(root, "site/content/proof.json");
  const proof = fs.existsSync(proofFile) ? JSON.parse(fs.readFileSync(proofFile, "utf8")) : null;
  return {
    proof,
    hubs: hubsFile.hubs ?? [],
    captions,
    bands: hubsFile.bands ?? [],
    flagship: hubsFile.flagship ?? [],
    paths: hubsFile.paths ?? [],
    unlisted: hubsFile.unlisted ?? {},
    pages: hubsFile.pages ?? [],
    repo: hubsFile.repo ?? "",
    specs,
  };
}

const pad2 = (n) => String(n).padStart(2, "0");

/** Image descriptor for one step, or null when the step has no capture. */
export function stepImage(spec, step) {
  const cap = step.capture;
  if (!cap) return null;
  const file = cap.annotated || cap.file;
  const id = spec.task;
  return {
    spec: id,
    n: step.n,
    src: `${id}/${path.posix.basename(file)}`,
    out: `shots/${id}/${pad2(step.n)}-${step.slug}.webp`,
    width: cap.viewport?.width,
    height: cap.viewport?.height,
  };
}

export function specImages(spec) {
  return (spec.steps ?? []).map((s) => stepImage(spec, s)).filter(Boolean);
}

/** Default thumbnail crop: drops the 220px app sidebar from a 1440x900 capture, leaving a 16:10 frame. */
export const DEFAULT_CROP = { x: 220, y: 0, w: 1220, h: 762 };
const SHOT_W = 1440, SHOT_H = 900;
const MIN_OUT_W = 960;

const cropOf = (c) => (c ? { x: c.x, y: c.y, w: c.w, h: c.h } : DEFAULT_CROP);
const isDefaultCrop = (c) => c.x === DEFAULT_CROP.x && c.y === DEFAULT_CROP.y && c.w === DEFAULT_CROP.w && c.h === DEFAULT_CROP.h;
const validCrop = (c) => [c?.x, c?.y, c?.w, c?.h].every(Number.isInteger) && c.x >= 0 && c.y >= 0 && c.w > 0 && c.h > 0 && c.x + c.w <= SHOT_W && c.y + c.h <= SHOT_H;

/** Dark cover/thumbnail for a spec's final-dark capture, cropped to `crop` (default: sidebar removed). */
export function darkCrop(spec, crop) {
  const c = cropOf(crop);
  const scale = Math.max(1, MIN_OUT_W / c.w);
  const name = isDefaultCrop(c) ? "cover-dark.webp" : `cover-dark-${c.x}-${c.y}-${c.w}-${c.h}.webp`;
  return { spec, src: `${spec}/final-dark-1440.png`, href: `/shots/${spec}/${name}`, width: Math.round(c.w * scale), height: Math.round(c.h * scale), crop: c };
}

/** Hero image for a hub: a spec's cropped dark capture, or an existing site file. */
export function coverImage(hub) {
  const c = hub.cover;
  if (!c) return null;
  if (c.spec) return darkCrop(c.spec, c.crop);
  return { spec: null, src: null, href: c.file, width: c.width, height: c.height, crop: null };
}

export const HOST = "kryptkeeper.example.com";

/** Route shown in a .frame bar for a hub cover: the first goTo step of a spec cover, a file cover's route, else the bare host. */
export function frameRoute(hub, specs) {
  const c = hub.cover;
  let route = c?.route;
  if (c?.spec) {
    const step = specs?.get(c.spec)?.steps?.find((s) => s.action === "goTo" && s.target?.url);
    route = step?.target.url;
  }
  return `${HOST}${route ?? ""}`;
}

/** The steps of `spec` that walkthrough `w` shows, in order: [{ step, n }] where n is the step's number in the spec. */
export function selectedSteps(w, spec) {
  const all = (spec.steps ?? []).map((step, i) => ({ step, n: i + 1 }));
  const pick = w.steps?.[spec.task];
  if (!Array.isArray(pick)) return all;
  return pick.map((n) => all[n - 1]).filter(Boolean);
}

/** Number of steps a walkthrough shows, after step selection. */
export function stepCount(w, specs) {
  return (w.specs ?? []).map((id) => specs.get(id)).filter(Boolean).reduce((n, s) => n + selectedSteps(w, s).length, 0);
}

/** Caption to render for step `n` of `spec`: the captions.json override when there is one, else the spec's own. */
export function captionOf(captions, spec, n, step) {
  return captions?.[spec.task]?.[String(n)] ?? step.caption;
}

/** Thumbnail for a walkthrough card on a hub page: the step image named by its optional thumb {spec, n}, else the last selected captured image. */
export function thumbImage(w, specs) {
  if (w.thumb) {
    const spec = specs.get(w.thumb.spec);
    const step = spec?.steps?.[w.thumb.n - 1];
    return (spec && step && stepImage(spec, step)) || null;
  }
  const list = (w.specs ?? []).map((id) => specs.get(id)).filter(Boolean);
  return list.flatMap((s) => selectedSteps(w, s).map((x) => stepImage(s, x.step)).filter(Boolean)).at(-1) ?? null;
}

/** Cropped dark thumbnail for a path-page step: the dark final of its optional thumbSpec, else of its last spec, cropped by thumbCrop. */
export function pathThumb(w) {
  const spec = w.thumbSpec ?? (w.specs ?? []).at(-1);
  return spec ? darkCrop(spec, w.thumbCrop) : null;
}

/** Hubs in display order: band order, then hubs.json order within a band. */
export function orderedHubs(content) {
  const rank = new Map(content.bands.map((b, i) => [b.id, i]));
  return content.hubs.map((h, i) => ({ h, i })).sort((a, b) => (rank.get(a.h.band) ?? 99) - (rank.get(b.h.band) ?? 99) || a.i - b.i).map((x) => x.h);
}

/** Every distinct image any hub cover, walkthrough thumbnail or shown step uses, each emitted once. Crops carry a `crop` rect. */
export function walkthroughImages(content) {
  const out = [];
  const outs = new Set();
  const add = (img) => { if (img && !outs.has(img.out)) { outs.add(img.out); out.push(img); } };
  const dark = (d) => ({ spec: d.spec, n: 0, src: d.src, out: d.href.slice(1), width: d.width, height: d.height, crop: d.crop });
  for (const hub of content.hubs) {
    const cv = coverImage(hub);
    if (cv?.src) add(dark(cv));
  }
  for (const hub of content.hubs) {
    for (const w of hub.walkthroughs ?? []) {
      const t = pathThumb(w);
      if (t) add(dark(t));
      add(thumbImage(w, content.specs));
      for (const id of w.specs ?? []) {
        const spec = content.specs.get(id);
        if (spec) for (const { step } of selectedSteps(w, spec)) add(stepImage(spec, step));
      }
    }
  }
  return out;
}

export const escapeHtml = (s) =>
  String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** Mini-markdown from the capture specs: escape first, then **bold** and `code`. */
export function renderCaption(text) {
  return escapeHtml(text)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
}

/** Caption with the markup removed, for alt text. Not escaped. */
export function plainCaption(text) {
  return String(text).replace(/\*\*([^*]+)\*\*/g, "$1").replace(/`([^`]+)`/g, "$1");
}

const SELECTOR_SYNTAX = /xpath=|css=|>>|(?<!:)\/\/|\[@|normalize-space|nth=/;
const PRIVATE_IPV4 = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/;

/** Why a caption must not be published as is (selector syntax, key material, a private address), or null when it is fine. */
export function captionProblem(text) {
  if (SELECTOR_SYNTAX.test(text)) return "contains selector syntax";
  if (/BEGIN CERTIFICATE/.test(text) || /\S{60,}/.test(text)) return "contains a PEM or base64 blob";
  if (PRIVATE_IPV4.test(text)) return "contains a private IPv4 address";
  return null;
}

// Lab hostnames, secrets and tokens must never reach the public proof page (evidence text, labels, captions).
// The lab names come from site/tools/private-ref.txt, which the public snapshot leaves
// out; there the check is off (the site is deployed from the development repo only).
let LAB_HOST = loadPrivateRef(path.resolve(path.dirname(new URL(import.meta.url).pathname), ".."));
/** Replaces the lab-host pattern; tests use a synthetic one so they never name the real lab. */
export function setLabHostPattern(re) {
  LAB_HOST = re;
}
const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\b(?:ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{20,}/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/,
  /\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}/,
  /\bBearer\s+[A-Za-z0-9._~+\/=-]{20,}/i,
  /\b[\w-]*(?:api[_-]?key|token|secret|passw(?:or)?d|passphrase)["']?\s*[:=]\s*["']?[A-Za-z0-9+\/_.-]{8,}/i,
];
/** Why proof evidence (text, label or caption) must not be published, or null when it is fine. */
export function scrubProblem(text) {
  if (typeof text !== "string") return null;
  if (PRIVATE_IPV4.test(text)) return "contains a private IPv4 address";
  if (LAB_HOST?.test(text)) return "contains a lab hostname";
  if (SECRET_PATTERNS.some((p) => p.test(text))) return "contains a token or secret pattern";
  return null;
}
export const PROOF_EVIDENCE_MAX_LINES = 25;
const normEol = (t) => t.replace(/\r\n?/g, "\n");

export const PROOF_RESULTS = ["pass", "partial", "fail"];
export const PROOF_AGAINST = ["real", "mixed", "stand-in"];
export const GAP_NEEDS = ["account", "hardware", "later"];

/** Problems in site/content/proof.json: missing fields, bad enums, a record that is not on disk, a private address in the copy. */
export function validateProof(proof, root) {
  const errors = [];
  const str = (v) => typeof v === "string" && v.trim() !== "";
  const leak = (where, v) => { if (typeof v === "string" && PRIVATE_IPV4.test(v)) errors.push(`proof ${where}: contains a private IPv4 address`); };
  if (!Array.isArray(proof?.records) || !proof.records.length) return ["proof.json: records must be a non-empty list"];
  for (const [v, sha] of Object.entries(proof.public_releases ?? {})) if (!/^\d+\.\d+\.\d+$/.test(v) || !/^[0-9a-f]{7,40}$/.test(sha)) errors.push(`proof public_releases: "${v}" must map a version like 1.1.0 to a commit hash`);
  const ids = new Set();
  for (const r of proof.records) {
    const who = `proof ${r?.id ?? "?"}`;
    for (const f of ["id", "area", "title", "environment", "what_ran", "version", "record"]) if (!str(r[f])) errors.push(`${who}: missing ${f}`);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(r.date ?? "")) errors.push(`${who}: date must be YYYY-MM-DD`);
    if (!PROOF_RESULTS.includes(r.result)) errors.push(`${who}: result must be one of ${PROOF_RESULTS.join(", ")}`);
    if (!PROOF_AGAINST.includes(r.against)) errors.push(`${who}: against must be one of ${PROOF_AGAINST.join(", ")}`);
    if (!Array.isArray(r.not_proven) || !r.not_proven.every(str)) errors.push(`${who}: not_proven must be a list of strings`);
    for (const f of ["counts", "note"]) if (r[f] !== undefined && typeof r[f] !== "string") errors.push(`${who}: ${f} must be a string`);
    if (r.headline !== undefined && typeof r.headline !== "boolean") errors.push(`${who}: headline must be true or false`);
    if (ids.has(r.id)) errors.push(`${who}: duplicate id`);
    ids.add(r.id);
    if (str(r.record) && !fs.existsSync(path.join(root, r.record))) errors.push(`${who}: record ${r.record} does not exist in the repo`);
    for (const [i, row] of (r.rows ?? []).entries()) {
      if (!str(row.name)) errors.push(`${who}: row ${i + 1} is missing name`);
      if (!PROOF_RESULTS.includes(row.result)) errors.push(`${who}: row ${i + 1} result must be one of ${PROOF_RESULTS.join(", ")}`);
      leak(`${r.id} row ${i + 1}`, row.name); leak(`${r.id} row ${i + 1}`, row.note);
    }
    if (!Array.isArray(r.evidence) || !r.evidence.length) errors.push(`${who}: evidence must be a non-empty list`);
    for (const [i, e] of (Array.isArray(r.evidence) ? r.evidence : []).entries()) {
      const ew = `${who}: evidence ${i + 1}`;
      if (!str(e?.label) || !str(e?.source) || !str(e?.text)) { errors.push(`${ew} needs label, source and text`); continue; }
      const file = path.join(root, e.source);
      if (!e.source.startsWith("docs/") || e.source.includes("..") || !fs.existsSync(file)) { errors.push(`${ew}: source ${e.source} must be an existing file under docs/`); continue; }
      const text = normEol(e.text);
      if (text.split("\n").length > PROOF_EVIDENCE_MAX_LINES) errors.push(`${ew}: more than ${PROOF_EVIDENCE_MAX_LINES} lines`);
      if (!normEol(fs.readFileSync(file, "utf8")).includes(text)) errors.push(`${ew}: text is not verbatim in ${e.source}`);
      for (const [k, v] of [["text", e.text], ["label", e.label]]) { const p = scrubProblem(v); if (p) errors.push(`${ew} ${k}: ${p}`); }
    }
    for (const [i, sh] of (r.shots ?? []).entries()) {
      const sw = `${who}: shot ${i + 1}`;
      if (!str(sh?.src) || !str(sh?.caption) || !/^\d{4}-\d{2}-\d{2}$/.test(sh?.date ?? "") || !(sh?.width > 0) || !(sh?.height > 0)) { errors.push(`${sw} needs src, caption, date (YYYY-MM-DD), width and height`); continue; }
      if (sh.src.includes("..") || !fs.existsSync(path.join(root, "site", sh.src))) errors.push(`${sw}: image site/${sh.src} does not exist`);
      const p = scrubProblem(sh.caption); if (p) errors.push(`${sw} caption: ${p}`);
    }
    for (const f of ["environment", "what_ran", "counts", "note", "title"]) leak(`${r.id} ${f}`, r[f]);
    for (const v of r.not_proven ?? []) leak(`${r.id} not_proven`, v);
  }
  const g = proof.gaps;
  if (!g || !str(g.source) || !fs.existsSync(path.join(root, g.source))) errors.push(`proof gaps: source ${g?.source ?? "?"} does not exist in the repo`);
  if (!Array.isArray(g?.items) || !g.items.length) errors.push("proof gaps: items must be a non-empty list");
  for (const it of g?.items ?? []) {
    if (!str(it.item) || !str(it.why)) errors.push(`proof gaps: "${it.item ?? "?"}" needs item and why`);
    if (!GAP_NEEDS.includes(it.needs)) errors.push(`proof gaps: "${it.item ?? "?"}" needs must be one of ${GAP_NEEDS.join(", ")}`);
  }
  return errors;
}

export function validate(content, root, { shotsDir, publicRoot } = {}) {
  const errors = [];
  if (content.proof) errors.push(...validateProof(content.proof, root));
  const referenced = new Set();
  const hubIds = new Set();
  const walkthroughKeys = new Set();
  const bandIds = new Set(content.bands.map((b) => b.id));
  const checkedCaptions = new Set();

  for (const pg of content.pages ?? []) {
    if (!pg.url?.startsWith("/") || !pg.file || !fs.existsSync(path.join(root, "site", pg.file))) {
      errors.push(`page ${pg.url ?? "?"}: site/${pg.file ?? "?"} does not exist (hubs.json "pages")`);
    }
  }

  for (const hub of content.hubs) {
    if (hubIds.has(hub.id)) errors.push(`duplicate hub id: ${hub.id}`);
    hubIds.add(hub.id);
    if (!bandIds.has(hub.band)) errors.push(`hub ${hub.id}: band "${hub.band ?? ""}" is not one of the bands in hubs.json`);
    const cv = hub.cover;
    if (cv?.crop && !validCrop(cv.crop)) errors.push(`hub ${hub.id}: cover crop must be integer x, y, w, h inside ${SHOT_W}x${SHOT_H}`);
    if (!cv || (!cv.spec && !cv.file)) errors.push(`hub ${hub.id}: missing cover (a spec id or a file)`);
    else if (cv.spec) {
      if (!fs.existsSync(path.join(root, SPECS_DIR, `${cv.spec}.json`))) errors.push(`hub ${hub.id}: cover spec ${cv.spec} not found at ${SPECS_DIR}/${cv.spec}.json`);
    } else if (!fs.existsSync(path.join(root, "site", cv.file.replace(/^\//, "")))) errors.push(`hub ${hub.id}: cover file ${cv.file} does not exist under site/`);
    const slugs = new Set();
    for (const w of hub.walkthroughs ?? []) {
      if (slugs.has(w.slug)) errors.push(`duplicate walkthrough slug in hub ${hub.id}: ${w.slug}`);
      slugs.add(w.slug);
      walkthroughKeys.add(`${hub.id}/${w.slug}`);
      for (const id of w.specs ?? []) {
        referenced.add(id);
        if (!content.specs.has(id)) errors.push(`${hub.id}/${w.slug}: spec ${id} not found at ${SPECS_DIR}/${id}.json`);
      }
      if (w.thumb) {
        if (!(w.specs ?? []).includes(w.thumb.spec)) errors.push(`${hub.id}/${w.slug}: thumb spec ${w.thumb.spec} is not one of the walkthrough's specs`);
        else if (!thumbImage(w, content.specs)) errors.push(`${hub.id}/${w.slug}: thumb ${w.thumb.spec} step ${w.thumb.n} has no capture`);
      }
      if (w.thumbSpec && !fs.existsSync(path.join(root, SPECS_DIR, `${w.thumbSpec}.json`))) errors.push(`${hub.id}/${w.slug}: thumbSpec ${w.thumbSpec} not found at ${SPECS_DIR}/${w.thumbSpec}.json`);
      if (w.thumbCrop && !validCrop(w.thumbCrop)) errors.push(`${hub.id}/${w.slug}: thumbCrop must be integer x, y, w, h inside ${SHOT_W}x${SHOT_H}`);
      for (const [id, pick] of Object.entries(w.steps ?? {})) {
        const spec = content.specs.get(id);
        const where = `${hub.id}/${w.slug}: steps ${id}`;
        if (!(w.specs ?? []).includes(id)) errors.push(`${where} is not one of the walkthrough's specs`);
        else if (!Array.isArray(pick) || !pick.length) errors.push(`${where} must be a non-empty list of step numbers`);
        else if (spec) {
          for (const n of pick) if (!Number.isInteger(n) || n < 1 || n > spec.steps.length) errors.push(`${where}: step ${n} does not exist (${id} has ${spec.steps.length} steps)`);
          if (new Set(pick).size !== pick.length) errors.push(`${where} lists a step more than once`);
        }
      }
      for (const id of w.specs ?? []) {
        const spec = content.specs.get(id);
        if (!spec) continue;
        for (const { step, n } of selectedSteps(w, spec)) {
          const key = `${id}:${n}`;
          if (checkedCaptions.has(key)) continue;
          checkedCaptions.add(key);
          const text = captionOf(content.captions, spec, n, step);
          const problem = captionProblem(text);
          if (problem) errors.push(`${hub.id}/${w.slug}: ${id} step ${n}: caption "${text.replace(/\s+/g, " ").slice(0, 50)}..." ${problem}; add an override for ${id} ${n} in site/content/captions.json`);
        }
      }
    }
    for (const d of hub.docs ?? []) {
      if (!fs.existsSync(path.join(root, d.path))) errors.push(`hub ${hub.id}: doc ${d.path} is missing from the repo`);
      else if (publicRoot && !fs.existsSync(path.join(publicRoot, d.path))) {
        errors.push(`hub ${hub.id}: doc ${d.path} is missing from the public checkout ${publicRoot}`);
      }
    }
  }

  const specDir = path.join(root, SPECS_DIR);
  const onDisk = fs.existsSync(specDir) ? fs.readdirSync(specDir).filter((f) => f.endsWith(".json")).map((f) => f.slice(0, -5)).sort() : [];
  for (const id of onDisk) {
    if (!referenced.has(id) && !(id in content.unlisted)) {
      errors.push(`spec ${id} is not on any walkthrough: add it to a hub in site/content/hubs.json or list it under "unlisted" with a reason`);
    }
  }

  for (const [id, byStep] of Object.entries(content.captions ?? {})) {
    const spec = content.specs.get(id);
    if (!spec) { errors.push(`captions.json: spec ${id} is not on any walkthrough`); continue; }
    for (const [n, text] of Object.entries(byStep)) {
      if (!Number.isInteger(Number(n)) || Number(n) < 1 || Number(n) > spec.steps.length) errors.push(`captions.json: ${id} has no step ${n}`);
      else if (typeof text !== "string" || !text.trim()) errors.push(`captions.json: ${id} step ${n} must be a non-empty string`);
    }
  }

  for (const id of content.flagship) if (!hubIds.has(id)) errors.push(`flagship hub "${id}" does not exist`);

  const pathIds = new Set();
  for (const p of content.paths) {
    if (pathIds.has(p.id)) errors.push(`duplicate path id: ${p.id}`);
    pathIds.add(p.id);
    for (const step of p.steps ?? []) {
      if (!walkthroughKeys.has(step)) errors.push(`path ${p.id}: step "${step}" does not match any hub/walkthrough`);
    }
  }

  if (shotsDir) {
    for (const img of walkthroughImages(content)) {
      if (!fs.existsSync(path.join(shotsDir, img.src))) errors.push(`missing screenshot: ${img.src}`);
    }
  }
  return errors;
}
