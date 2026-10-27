// Generates the feature hub, walkthrough and path pages from site/content/hubs.json and the capture specs.
// Usage: node site/tools/build.mjs [--check] [--public <dir>] [--shots <dir>]
// --check renders in memory, validates, and exits 1 if validation fails or any generated file is stale or missing.
import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { PROOF_RESULTS, loadContent, coverImage, frameRoute, thumbImage, pathThumb, orderedHubs, selectedSteps, stepCount as countSteps, captionOf, stepImage, validate, renderCaption, plainCaption, escapeHtml as esc } from "./content.mjs";
import { loadRelease, stampRelease, findStaleVersions, releaseExists } from "./release.mjs";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const SITE = path.join(ROOT, "site");
const BASE = "https://kryptkeeper.io";
const GENERATED_DIRS = ["features", "paths", "proof"];

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const check = args.includes("--check");

// Cache busting: asset URLs carry the first 10 hex chars of the file's sha256, so output stays deterministic.
const assetHash = (file) => crypto.createHash("sha256").update(fs.readFileSync(path.join(SITE, file))).digest("hex").slice(0, 10);
const ASSET_TAGS = `<link rel="stylesheet" href="/style.css?v=${assetHash("style.css")}">\n<script src="/lightbox.js?v=${assetHash("lightbox.js")}" defer></script>`;

const content = loadContent(ROOT);
if (!content.proof) throw new Error("site/content/proof.json is missing");
const release = loadRelease(ROOT);
const { hubs, paths, repo, specs, bands, flagship, pages } = content;
const hubById = new Map(hubs.map((h) => [h.id, h]));
const wKey = (hub, w) => `${hub.id}/${w.slug}`;
const wUrl = (hub, w) => `/features/${hub.id}/${w.slug}/`;
const hubUrl = (hub) => `/features/${hub.id}/`;
const imgUrl = (img) => img.href ?? `/${img.out}`;

function walkthroughByKey(key) {
  const [hubId, slug] = key.split("/");
  const hub = hubById.get(hubId);
  const w = hub?.walkthroughs.find((x) => x.slug === slug);
  return w ? { hub, w } : null;
}

const wSpecs = (w) => w.specs.map((id) => specs.get(id)).filter(Boolean);
const stepCount = (w) => countSteps(w, specs);
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

const roleOf = (spec) => spec.persona.match(/\(([^)]*)\)\s*$/)?.[1] ?? spec.persona;
const partTitle = (spec) => { const i = spec.title.indexOf(": "); const t = i >= 0 ? spec.title.slice(i + 2) : spec.title; return t.charAt(0).toUpperCase() + t.slice(1); };
const docUrl = (d) => (d.tree ? repo.replace(/\/blob\/main\/$/, "/tree/main/") : repo) + d.path;

/** First hub (in hubs.json order) whose walkthrough shows exactly the same specs and steps. */
const showSig = (w) => `${w.specs.join(",")}${w.steps ? JSON.stringify(w.steps) : ""}`;
function canonicalOwner(w) {
  const sig = showSig(w);
  for (const h of hubs) for (const x of h.walkthroughs) if (showSig(x) === sig) return { hub: h, w: x };
  return null;
}
const sharedSig = new Map();
for (const h of hubs) for (const w of h.walkthroughs) sharedSig.set(showSig(w), (sharedSig.get(showSig(w)) ?? 0) + 1);

const pathsUsing = (key) => paths.map((p) => ({ p, i: p.steps.indexOf(key) })).filter((x) => x.i >= 0);

// ---------- shared chrome ----------
const LOGO = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg>`;
const HEADER = `<header class="site">
  <a class="brand" href="/" aria-label="Kryptkeeper home">
    <span class="tile" aria-hidden="true">${LOGO}</span>
    <span class="word">Kryptkeeper</span>
  </a>
  <nav class="top" aria-label="Site">
    <a href="/features/">Features</a>
    <a href="/paths/">Paths</a>
    <a href="/features/build-your-own/">Build your own</a>
    <a href="/proof/">Proof</a>
    <a href="/#install">Install</a>
    <a href="https://github.com/bpmforge/kryptkeeper">GitHub</a>
  </nav>
</header>`;
const FOOTER = `<footer class="site">
  <div>
    <p>Kryptkeeper · Apache License 2.0</p>
    <p><a href="https://github.com/bpmforge/kryptkeeper">github.com/bpmforge/kryptkeeper</a></p>
  </div>
  <div class="contacts">
    <span>Security reports: <span class="addr">security@kryptkeeper.io</span> or <a href="https://github.com/bpmforge/kryptkeeper/security/advisories/new">a private advisory</a></span>
    <span>Everything else: <span class="addr">contact@kryptkeeper.io</span></span>
  </div>
</footer>`;

function page({ title, description, url, body, canonical }) {
  const full = `${title} · Kryptkeeper`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${esc(full)}</title>
<meta name="description" content="${esc(description)}">
<meta property="og:title" content="${esc(full)}">
<meta property="og:description" content="${esc(description)}">
<meta property="og:url" content="${BASE}${url}">
<meta property="og:type" content="website">
${canonical ? `<link rel="canonical" href="${BASE}${canonical}">\n` : ""}<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;500&display=swap">
${ASSET_TAGS}
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<div class="wrap">

${HEADER}

<main id="main" class="page">
${body}
</main>

${FOOTER}

</div>
</body>
</html>
`;
}

function breadcrumb(items, extra = "") {
  const lis = items.map(([label, href], i) =>
    i === items.length - 1
      ? `<li aria-current="page">${esc(label)}</li>`
      : `<li><a href="${href}">${esc(label)}</a></li>`);
  return `<div class="crumb-row"><nav class="crumbs" aria-label="Breadcrumb"><ol>${lis.join("")}</ol></nav>${extra}</div>`;
}

const imgTag = (img, alt, extra = "") =>
  `<img src="${imgUrl(img)}" width="${img.width}" height="${img.height}" alt="${esc(alt)}"${extra}>`;

// ---------- cards and rows ----------
/** Compact role list for the home page: label, title, one-line intro, step count pinned to the bottom. */
function pathItem(p) {
  return `<li><span class="label">${esc(p.role)}</span><h3><a class="stretch" href="/paths/${p.id}/">${esc(p.title)}</a></h3><p>${esc(p.intro)}</p><span class="steps-n">${plural(p.steps.length, "step", "steps")} &rarr;</span></li>`;
}
const pathList = (list) => `<ul class="path-list">\n${list.map(pathItem).join("\n")}\n</ul>`;

/** Browser-style frame around a linked screenshot; the bar shows the route the screen lives at. */
function frame(route, href, img) {
  return `<div class="frame">
    <div class="bar"><i></i><i></i><i></i><span>${esc(route)}</span></div>
    <a href="${href}" tabindex="-1" aria-hidden="true">${img}</a>
  </div>`;
}

/** One tour-style row: caption beside a framed screenshot. */
function hubRow(h, flip = false) {
  const cv = coverImage(h);
  return `<figure class="shot${flip ? " flip" : ""}">
  <figcaption>
    <h3><a href="${hubUrl(h)}">${esc(h.title)}</a></h3>
    <p>${esc(h.tagline)}</p>
    <p>${esc(h.intro)}</p>
    <a class="how-link" href="${hubUrl(h)}">How it works &rarr;</a>
  </figcaption>
  ${frame(frameRoute(h, specs), hubUrl(h), `<img src="${cv.href}" width="${cv.width}" height="${cv.height}" loading="lazy" decoding="async" alt="${esc(h.title)} screen in Kryptkeeper">`)}
</figure>`;
}

/** Home feature block: flagship rows, then every other hub as plain links grouped by band. */
function homeHubs() {
  const rows = flagship.map((id, i) => hubRow(hubById.get(id), i % 2 === 1)).join("\n");
  const rest = new Set(flagship);
  const cols = bands.map((band) => {
    const items = orderedHubs(content).filter((h) => h.band === band.id && !rest.has(h.id));
    return items.length
      ? `<div><span class="label">${esc(band.label)}</span><ul>${items.map((h) => `<li><a href="${hubUrl(h)}">${esc(h.title)}</a></li>`).join("")}</ul></div>`
      : "";
  }).join("\n");
  return `<div class="showcase">
${rows}
</div>
<div class="more-hubs">
  <h3>Everything else</h3>
  <div class="more-cols">
${cols}
  </div>
  <p class="all-link"><a href="/features/">All features &rarr;</a></p>
</div>`;
}

function thumb(w) {
  const img = thumbImage(w, specs);
  return img ? `<div class="thumb">${imgTag(img, "", ' loading="lazy" decoding="async"')}</div>` : "";
}

// ---------- pages ----------
const out = new Map(); // path relative to site/ -> content

function featuresIndex() {
  const ordered = orderedHubs(content);
  const jump = `<nav class="band-jump" aria-label="Jump to a group">${bands.map((b) => `<a href="#${b.id}">${esc(b.label)}</a>`).join("")}</nav>`;
  const sections = bands.map((b) => {
    const rows = ordered.filter((h) => h.band === b.id).map((h, i) => hubRow(h, i % 2 === 1)).join("\n");
    return `<section class="chapter" id="${b.id}">
  <header>
    <span class="label">${esc(b.label)}</span>
    <h2>${esc(b.title)}</h2>
    <p class="muted">${esc(b.intro)}</p>
  </header>
${rows}
</section>`;
  }).join("\n");
  const body = `${breadcrumb([["Features", "/features/"]])}
<header class="page-head">
  <h1>Features</h1>
  <p class="lede">${hubs.length} areas of the product, each shown on real screens from a running hub. Open one to follow it step by step, in the order you would do the work.</p>
  ${jump}
</header>
${sections}`;
  return page({ title: "Features", description: "Every area of Kryptkeeper with step-by-step walkthroughs and screenshots from a running hub.", url: "/features/", body });
}

function hubPage(hub) {
  const cv = coverImage(hub);
  const hero = `<figure class="hub-hero">${frame(frameRoute(hub, specs), hubUrl(hub), `<img src="${cv.href}" width="${cv.width}" height="${cv.height}" alt="${esc(hub.title)} screen in Kryptkeeper">`)}</figure>\n`;
  const points = hub.points?.length
    ? `<section aria-labelledby="points"><h2 id="points">What you get</h2><ul class="card-grid points">${hub.points.map((pt) => `<li class="card"><h3>${esc(pt.title)}</h3><p>${esc(pt.text)}</p></li>`).join("")}</ul></section>\n`
    : "";
  const pending = hub.pending ? `<p class="callout" role="note"><strong>Coming:</strong> ${esc(hub.pending)}</p>\n` : "";
  const cards = hub.walkthroughs.map((w) =>
    `<li class="card wt-card">${thumb(w)}<h3><a class="stretch" href="${wUrl(hub, w)}">${esc(w.title)}</a></h3><p>${esc(w.summary)}</p><span class="meta">${plural(stepCount(w), "step", "steps")}</span></li>`);
  const docs = hub.docs?.length
    ? `<section aria-labelledby="docs"><h2 id="docs">Docs</h2><ul class="link-list">${hub.docs.map((d) => `<li><a href="${esc(docUrl(d))}">${esc(d.title)}</a></li>`).join("")}</ul></section>\n`
    : "";
  const using = paths.filter((p) => p.steps.some((s) => s.startsWith(`${hub.id}/`)));
  const usedBy = using.length
    ? `<section aria-labelledby="used-by"><h2 id="used-by">Paths that use this</h2><ul class="link-list">${using.map((p) => `<li><a href="/paths/${p.id}/">${esc(p.title)}</a> <span class="muted">for ${esc(p.role)}</span></li>`).join("")}</ul></section>\n`
    : "";
  const body = `${breadcrumb([["Features", "/features/"], [hub.title, hubUrl(hub)]])}
<header class="page-head">
  <span class="label">Feature</span>
  <h1>${esc(hub.title)}</h1>
  <p class="lede">${esc(hub.tagline)}</p>
  <p class="intro">${esc(hub.intro)}</p>
</header>
${hero}${points}${pending}<section aria-labelledby="how"><h2 id="how">How it works</h2><ol class="card-grid wt-grid">
${cards.join("\n")}
</ol></section>
${docs}${usedBy}`;
  return page({ title: hub.title, description: `${hub.tagline} ${hub.intro}`.slice(0, 300), url: hubUrl(hub), body });
}

/** One card per shown step: "Step N" label and caption on top, the screenshot in a rounded frame below. */
function stepList(w, spec) {
  const items = selectedSteps(w, spec).map(({ step, n }, i) => {
    const caption = captionOf(content.captions, spec, n, step);
    const img = stepImage(spec, step);
    const narrow = img && img.width < 600 ? " narrow" : "";
    const fig = img
      ? `\n    <figure class="shot-fig${narrow}"><a class="shot-link" href="${imgUrl(img)}">${imgTag(img, plainCaption(caption), ' loading="lazy" decoding="async"')}</a></figure>`
      : "";
    return `  <li class="step"><div class="step-head"><span class="label">Step <b>${i + 1}</b></span><p>${renderCaption(caption)}</p></div>${fig}</li>`;
  });
  return `<ol class="steps">\n${items.join("\n")}\n</ol>`;
}

const rolePill = (spec) => `<span class="pill role">${esc(roleOf(spec))}</span>`;

function walkthroughPage(hub, w, idx) {
  const ws = wSpecs(w);
  const multi = ws.length > 1;
  const parts = multi
    ? ws.map((s) => `<section class="part"><h2>${esc(partTitle(s))}</h2><p class="as">As ${rolePill(s)}</p>\n${stepList(w, s)}</section>`).join("\n")
    : ws.map((s) => stepList(w, s)).join("\n");
  const as = !multi && ws[0] ? `<p class="as">As ${rolePill(ws[0])}</p>` : "";
  const prev = hub.walkthroughs[idx - 1];
  const next = hub.walkthroughs[idx + 1];
  const key = wKey(hub, w);
  const pathNext = pathsUsing(key).map(({ p, i }) => p.steps[i + 1]);
  const showNext = next && !pathNext.includes(wKey(hub, next));
  const pager = `<nav class="pager" aria-label="More in ${esc(hub.title)}">${prev ? `<a class="prev" href="${wUrl(hub, prev)}"><span class="label">Previous</span>${esc(prev.title)}</a>` : "<span></span>"}${showNext ? `<a class="next" href="${wUrl(hub, next)}"><span class="label">Next</span>${esc(next.title)}</a>` : "<span></span>"}</nav>`;
  const used = pathsUsing(key).map(({ p, i }) => {
    const nextStep = p.steps[i + 1] && walkthroughByKey(p.steps[i + 1]);
    const link = nextStep ? ` <a href="${wUrl(nextStep.hub, nextStep.w)}">Next: ${esc(nextStep.w.title)} →</a>` : ` <span class="muted">Last step.</span>`;
    return `<li>Step ${i + 1} of ${p.steps.length} in <a href="/paths/${p.id}/">${esc(p.title)}</a>.${link}</li>`;
  });
  const usedBox = used.length ? `<aside class="path-box" aria-labelledby="in-paths"><h2 id="in-paths">Part of these paths</h2><ul>${used.join("")}</ul></aside>\n` : "";
  const docs = hub.docs?.length
    ? `<aside class="path-box" aria-labelledby="hub-docs"><h2 id="hub-docs">Docs for ${esc(hub.title)}</h2><ul class="link-list">${hub.docs.map((d) => `<li><a href="${esc(docUrl(d))}">${esc(d.title)}</a></li>`).join("")}</ul></aside>\n`
    : "";
  const owner = sharedSig.get(showSig(w)) > 1 ? canonicalOwner(w) : null;
  const body = `${breadcrumb([["Features", "/features/"], [hub.title, hubUrl(hub)], [w.title, wUrl(hub, w)]])}
<header class="page-head">
  <span class="label">Walkthrough · ${plural(stepCount(w), "step", "steps")}</span>
  <h1>${esc(w.title)}</h1>
  <p class="lede">${esc(w.summary)}</p>
  ${as}
</header>
${parts}
${usedBox}${pager}
${docs}`;
  return page({ title: `${w.title} · ${hub.title}`, description: w.summary, url: wUrl(hub, w), body, canonical: owner ? wUrl(owner.hub, owner.w) : undefined });
}

function pathsIndex() {
  const body = `${breadcrumb([["Paths", "/paths/"]])}
<header class="page-head">
  <h1>Pick your path</h1>
  <p class="lede">Walkthroughs in the order a particular role needs them, from the first screen to a working setup.</p>
</header>
${pathList(paths)}`;
  return page({ title: "Paths", description: "Role-based routes through the Kryptkeeper walkthroughs.", url: "/paths/", body });
}

const lazy = ' loading="lazy" decoding="async"';
const arrow = `<span class="arr" aria-hidden="true">&rarr;</span>`;

/** Path steps are cards on a vertical connector line: cropped dark thumbnail beside "Step N · Hub", title, summary and step count. */
function pathPage(p) {
  const items = p.steps.map((key, i) => {
    const hit = walkthroughByKey(key);
    if (!hit) return "";
    const { hub, w } = hit;
    return `<li class="pstep">
  <span class="card-img">${imgTag(pathThumb(w), `${w.title} screen in Kryptkeeper`, lazy)}</span>
  <div class="pstep-text">
    <span class="label">Step <b>${i + 1}</b> &middot; ${esc(hub.title)}</span>
    <h3><a class="stretch" href="${wUrl(hub, w)}">${esc(w.title)}</a></h3>
    <p>${esc(w.summary)}</p>
    <span class="card-foot"><span>${plural(stepCount(w), "step", "steps")}</span>${arrow}</span>
  </div>
</li>`;
  });
  const body = `${breadcrumb([["Paths", "/paths/"], [p.title, `/paths/${p.id}/`]], `<span class="pill role">${esc(p.role)}</span>`)}
<header class="page-head">
  <h1>${esc(p.title)}</h1>
  <p class="lede">${esc(p.intro)}</p>
</header>
<ol class="path-steps">
${items.join("\n")}
</ol>`;
  return page({ title: p.title, description: p.intro, url: `/paths/${p.id}/`, body });
}

// ---------- proof ----------
const { proof } = content;
const RESULT_LABEL = { pass: "Pass", partial: "Partial", fail: "Fail" };
const AGAINST_LABEL = { real: "Real systems", mixed: "Real systems and stand-ins", "stand-in": "Stand-ins only" };
const NEEDS_LABEL = { account: "Needs an account", hardware: "Needs partner or hardware", later: "Later" };
// A record written after the release tag is published on the site itself until
// the next tag carries it, so its link never 404s (`"hosted": true` in proof.json).
const HOSTED = new Set(proof.records.filter((r) => r.hosted).map((r) => r.record));
const hostedPath = (p) => `proof/records/${path.basename(p)}`;
const recordUrl = (p) => (HOSTED.has(p) ? `/${hostedPath(p)}` : `https://github.com/${release.repo}/blob/v${release.version}/${p}`);
const resultPill = (r) => `<span class="pill ${r}">${RESULT_LABEL[r]}</span>`;
// A pass against local stand-ins is a "Mock pass": its own neutral pill, never counted as a real pass.
const recordPill = (r) => (r.against === "stand-in" && r.result === "pass" ? '<span class="pill mock">Mock pass</span>' : resultPill(r.result));
// Public tag and commit for each version that has a public release (proof.json "public_releases").
const publicBuild = (version) => {
  const m = /^(\d+\.\d+\.\d+)\b/.exec(version);
  const sha = m && proof.public_releases?.[m[1]];
  return sha ? `public v${m[1]} ${sha}` : "";
};
const tally = (list) => Object.fromEntries(PROOF_RESULTS.map((r) => [r, list.filter((x) => x.result === r).length]));
const tallyText = (t) => PROOF_RESULTS.filter((r) => t[r]).map((r) => `${t[r]} ${r}`).join(", ");
const realCounts = tally(proof.records.filter((r) => r.against !== "stand-in"));
const mockPasses = proof.records.filter((r) => r.against === "stand-in" && r.result === "pass").length;
const withFailedChecks = proof.records.filter((r) => r.result === "fail" || r.rows?.some((x) => x.result === "fail")).length;
const realSummary = [`${realCounts.pass} pass`, `${realCounts.partial} partial`, ...(realCounts.fail ? [`${realCounts.fail} fail`] : [])].join(", ");
const statsText = `Real systems: ${realSummary}. Mocks only: ${mockPasses}.`;
const failedChecksText = withFailedChecks ? `${plural(withFailedChecks, "record includes", "records include")} failed checks.` : "";
const statsList = (label) => `<ul class="proof-stats" aria-label="${label}">
  <li>${resultPill("pass")} <b>${realCounts.pass}</b> real</li>
  <li>${resultPill("partial")} <b>${realCounts.partial}</b> real</li>${realCounts.fail ? `
  <li>${resultPill("fail")} <b>${realCounts.fail}</b> real</li>` : ""}
  <li><span class="pill mock">Mock pass</span> <b>${mockPasses}</b> mocks only</li>
</ul>
<p class="proof-stats-text"><b>${esc(statsText)}</b>${failedChecksText ? ` ${esc(failedChecksText)}` : ""}</p>`;
const gapsBy = (needs) => proof.gaps.items.filter((g) => g.needs === needs);

const TERM_INLINE_LINES = 10;
function evidencePanel(e) {
  const n = e.text.split("\n").length;
  const head = `<span class="term-label">${esc(e.label)}</span> <span class="muted">from <a href="${esc(recordUrl(e.source))}"><code>${esc(e.source)}</code></a></span>`;
  const pre = `<pre tabindex="0"><code>${esc(e.text)}</code></pre>`;
  return n > TERM_INLINE_LINES
    ? `<details class="term"><summary>${head} <span class="muted">${n} lines</span></summary>${pre}</details>`
    : `<div class="term"><p class="term-head">${head}</p>${pre}</div>`;
}
function shotFigure(sh) {
  return `<figure class="proof-shot"><a class="shot-link" href="/${esc(sh.src)}"><img src="/${esc(sh.src)}" width="${sh.width}" height="${sh.height}" loading="lazy" decoding="async" alt="${esc(sh.caption)}"></a><figcaption>${esc(sh.caption)} <span class="muted">Captured ${esc(sh.date)}.</span></figcaption></figure>`;
}

function proofRecord(r) {
  const meta = [r.area, r.date, r.version, publicBuild(r.version), r.counts].filter(Boolean).map(esc).join(" · ");
  const rows = r.rows?.length
    ? `<details class="proof-rows"><summary>${r.rows.length} areas in this record: ${esc(tallyText(tally(r.rows)))}</summary><ul>${r.rows.map((x) => `<li>${resultPill(x.result)} <span>${esc(x.name)}${x.note ? ` <span class="muted">${esc(x.note)}</span>` : ""}</span></li>`).join("")}</ul></details>`
    : "";
  const np = r.not_proven.length ? `<div class="proof-np"><h4>Not proven</h4><ul>${r.not_proven.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>` : "";
  return `<li class="proof" id="${esc(r.id)}">
  <div class="proof-head"><h3>${esc(r.title)}</h3><span class="pills">${recordPill(r)}<span class="pill against">${AGAINST_LABEL[r.against]}</span></span></div>
  <p class="proof-meta">${meta}</p>
  <dl class="proof-dl"><dt>Environment</dt><dd>${esc(r.environment)}</dd><dt>What ran</dt><dd>${esc(r.what_ran)}</dd>${r.note ? `<dt>Note</dt><dd>${esc(r.note)}</dd>` : ""}</dl>
  <div class="proof-evidence"><h4>Output from the record, verbatim</h4>${r.evidence.map(evidencePanel).join("")}</div>
  ${r.shots?.length ? `<div class="proof-shots"><h4>Screenshots</h4>${r.shots.map(shotFigure).join("")}</div>` : ""}
  ${rows}
  ${np}
  <p class="proof-link"><a href="${esc(recordUrl(r.record))}">Record: <code>${esc(r.record)}</code></a></p>
</li>`;
}

function proofPage() {
  const gaps = Object.keys(NEEDS_LABEL).map((k) => {
    const list = gapsBy(k);
    return list.length ? `<div class="gap-group"><h3>${NEEDS_LABEL[k]} <span class="muted">(${list.length})</span></h3><ul class="gap-list">${list.map((g) => `<li><strong>${esc(g.item)}</strong><span class="muted">${esc(g.why)}</span></li>`).join("")}</ul></div>` : "";
  }).join("\n");
  const body = `${breadcrumb([["Proof", "/proof/"]])}
<header class="page-head">
  <span class="label">Lab records</span>
  <h1>Tested environments and proof</h1>
  <p class="lede">For each area: where it ran, what ran, how it ended, and a link to the record. The gaps are listed too.</p>
  <p class="intro">Commit hashes on this page are from the development repository. Where a version has a public release, the public tag and commit are shown beside it. Every entry comes from a record kept in the repository. A pass means the test exited cleanly on the named build. "Stand-ins" means the other side was a local copy or emulator, not the real service. Each record names the build it ran on. Some are from earlier releases and say so.</p>
  ${statsList("Results at a glance")}
  <nav class="band-jump" aria-label="Jump to a section"><a href="#records">Lab records</a><a href="#gaps">Not proven yet</a></nav>
</header>
<section id="records" aria-labelledby="records-h">
  <h2 id="records-h">Lab records</h2>
  <ol class="proof-list">
${proof.records.map(proofRecord).join("\n")}
  </ol>
</section>
<section id="gaps" aria-labelledby="gaps-h" class="gaps">
  <h2 id="gaps-h">Not proven yet</h2>
  <p class="muted">These features work against emulators, mock devices or stand-in services in our lab. Each is marked proven only after a run against the real system. The list comes from the <a href="${esc(recordUrl(proof.gaps.source))}">roadmap</a>.</p>
${gaps}
</section>`;
  return page({ title: "Tested environments and proof", description: "Where Kryptkeeper was tested, what ran, how it ended, and what is not proven yet. Each entry links to its lab record.", url: "/proof/", body });
}

/** Compact home-page summary: counts by result, a few headline records, and the gap totals. */
function homeProof() {
  const head = proof.records.filter((r) => r.headline).map((r) => {
    const rowsTally = r.rows?.length ? ` · ${r.rows.length} areas: ${tallyText(tally(r.rows))}` : "";
    return `<li>${recordPill(r)} <span><a href="/proof/#${esc(r.id)}">${esc(r.title)}</a>${r.against === "stand-in" ? ' <span class="pill against">Stand-ins only</span>' : ""} <span class="muted">${esc([r.date, r.counts].filter(Boolean).join(" · "))}${esc(rowsTally)}</span></span></li>`;
  }).join("\n");
  return `${statsList("Lab records by result")}
<ul class="proof-headlines">
${head}
</ul>
<p class="muted">Not proven yet: ${gapsBy("account").length} items need an account, ${gapsBy("hardware").length} need partner hardware or a vendor service, ${gapsBy("later").length} comes later.</p>
<p><a class="how-link" href="/proof/">All tested environments and proof &rarr;</a></p>`;
}

function sitemap(urls) {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map((u) => `  <url><loc>${BASE}${u}</loc></url>`).join("\n")}\n</urlset>\n`;
}

// ---------- assemble ----------
const urls = ["/", "/features/"];
out.set("features/index.html", featuresIndex());
for (const hub of hubs) {
  out.set(`features/${hub.id}/index.html`, hubPage(hub));
  urls.push(hubUrl(hub));
  hub.walkthroughs.forEach((w, i) => {
    out.set(`features/${hub.id}/${w.slug}/index.html`, walkthroughPage(hub, w, i));
    urls.push(wUrl(hub, w));
  });
}
out.set("paths/index.html", pathsIndex());
urls.push("/paths/");
for (const p of paths) {
  out.set(`paths/${p.id}/index.html`, pathPage(p));
  urls.push(`/paths/${p.id}/`);
}
// Hand-written pages listed under "pages" in hubs.json: only the asset tags are stamped, as on the home page.
for (const pg of pages) {
  const html = fs.readFileSync(path.join(SITE, pg.file), "utf8")
    .replace(/<link rel="stylesheet" href="\/style\.css[^"]*">/, ASSET_TAGS.split("\n")[0]);
  out.set(pg.file, html);
  urls.push(pg.url);
}
out.set("proof/index.html", proofPage());
for (const p of HOSTED) out.set(hostedPath(p), fs.readFileSync(path.join(ROOT, p), "utf8"));
urls.push("/proof/");
out.set("sitemap.xml", sitemap(urls));

function replaceRegion(html, name, inner) {
  const start = `<!-- ${name}:start -->`;
  const end = `<!-- ${name}:end -->`;
  const a = html.indexOf(start);
  const b = html.indexOf(end);
  if (a < 0 || b < a) throw new Error(`site/index.html is missing the ${start} ... ${end} markers`);
  return `${html.slice(0, a + start.length)}\n${inner}\n  ${html.slice(b)}`;
}
let indexHtml = fs.readFileSync(path.join(SITE, "index.html"), "utf8")
  .replace(/<script src="\/lightbox\.js[^"]*" defer><\/script>\n?/, "")
  .replace(/<link rel="stylesheet" href="\/style\.css[^"]*">/, ASSET_TAGS);
indexHtml = replaceRegion(indexHtml, "hubs", homeHubs());
indexHtml = replaceRegion(indexHtml, "paths", pathList(paths));
indexHtml = replaceRegion(indexHtml, "proof", homeProof());
out.set("index.html", stampRelease(indexHtml, release.version));

// ---------- write or check ----------
function listGenerated() {
  const found = [];
  const walk = (dir) => {
    if (!fs.existsSync(dir)) return;
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".html")) found.push(path.relative(SITE, p).split(path.sep).join("/"));
    }
  };
  for (const d of GENERATED_DIRS) walk(path.join(SITE, d));
  return found;
}

const errors = validate(content, ROOT, { shotsDir: opt("--shots"), publicRoot: opt("--public") });
const stale = listGenerated().filter((f) => !out.has(f));
for (const [rel, text] of out) {
  // The proof page quotes dated records about earlier releases on purpose
  // (verbatim excerpts checked by validateProof), so older versions are expected there.
  if (!rel.endsWith(".html") || rel.startsWith("proof/")) continue;
  const bad = [...new Set(findStaleVersions(text, release.version))];
  if (bad.length) errors.push(`site/${rel} mentions ${bad.join(", ")} but site/content/release.json says ${release.version}`);
}
// Everything under site/ is published as is, so it gets the same private-reference
// guard the public-repo snapshot applies (publish-snapshot "Guard"): lab domain,
// hypervisor, hostnames, local paths and private addresses. The pattern lives in
// site/tools/private-ref.txt, which .publicignore keeps out of the public repo;
// without it only the generic local-path and private-address checks run.
// site/tools holds the patterns themselves and their tests, so it is skipped.
const PRIVATE_REF_FILE = path.join(SITE, "tools", "private-ref.txt");
const PRIVATE_REF = new RegExp(fs.existsSync(PRIVATE_REF_FILE)
  ? fs.readFileSync(PRIVATE_REF_FILE, "utf8").trim()
  : String.raw`192\.168\.\d|\b10\.\d+\.\d+\.\d+|\/Users\/|claude-\d+`, "i");
const TEXT_EXT = /\.(html|css|js|json|md|txt|xml|svg)$/;
function scanPublished(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    const rel = path.relative(SITE, p).split(path.sep).join("/");
    if (e.isDirectory()) { if (rel !== "tools") scanPublished(p); continue; }
    if (!TEXT_EXT.test(e.name)) continue;
    const text = out.get(rel) ?? fs.readFileSync(p, "utf8");
    const m = text.match(PRIVATE_REF);
    if (m) errors.push(`site/${rel} contains a private lab or local reference ("${m[0]}")`);
  }
}
scanPublished(SITE);
for (const rel of out.keys()) if (!fs.existsSync(path.join(SITE, rel)) && TEXT_EXT.test(rel)) {
  const m = out.get(rel).match(PRIVATE_REF);
  if (m) errors.push(`site/${rel} contains a private lab or local reference ("${m[0]}")`);
}

if (args.includes("--check-release")) {
  const r = await releaseExists(release);
  if (!r.ok) errors.push(`release page ${r.url} returned ${r.status}: publish the release before deploying, or set release.json back`);
  else console.log(`release page exists: ${r.url}`);
}

if (check) {
  const problems = errors.map((e) => `invalid: ${e}`);
  for (const [rel, text] of out) {
    const file = path.join(SITE, rel);
    if (!fs.existsSync(file)) problems.push(`missing: site/${rel}`);
    else if (fs.readFileSync(file, "utf8") !== text) problems.push(`out of date: site/${rel}`);
  }
  for (const f of stale) problems.push(`stale (no longer generated): site/${f}`);
  if (problems.length) {
    console.error(problems.join("\n"));
    console.error(`\n${problems.length} problem(s). Run: node site/tools/build.mjs`);
    process.exit(1);
  }
  console.log(`site is up to date (${out.size} generated files)`);
} else {
  if (errors.length) { console.error(errors.map((e) => `invalid: ${e}`).join("\n")); process.exit(1); }
  let written = 0;
  for (const [rel, text] of out) {
    const file = path.join(SITE, rel);
    if (fs.existsSync(file) && fs.readFileSync(file, "utf8") === text) continue;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text);
    written++;
  }
  for (const f of stale) fs.rmSync(path.join(SITE, f));
  console.log(`wrote ${written} of ${out.size} files, removed ${stale.length} stale`);
}
