import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadContent, renderCaption, plainCaption, stepImage, walkthroughImages, coverImage, frameRoute, thumbImage, pathThumb, darkCrop, DEFAULT_CROP, selectedSteps, stepCount, captionOf, captionProblem, validate } from "./content.mjs";

function fixture({ unlisted = {}, steps = ["h1/w1"] } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kk-site-"));
  fs.mkdirSync(path.join(root, "site/content"), { recursive: true });
  fs.mkdirSync(path.join(root, "docs/guide/specs"), { recursive: true });
  fs.writeFileSync(path.join(root, "README.md"), "x");
  fs.mkdirSync(path.join(root, "site/screens"), { recursive: true });
  fs.writeFileSync(path.join(root, "site/screens/c.webp"), "x");
  const hubs = {
    repo: "https://example.test/blob/main/",
    bands: [{ id: "b1", label: "B", title: "B", intro: "i" }],
    flagship: ["h1"],
    hubs: [{ id: "h1", band: "b1", cover: { spec: "U-01" }, title: "H1", tagline: "t", intro: "i", docs: [{ title: "R", path: "README.md" }], walkthroughs: [{ slug: "w1", title: "W1", summary: "s", specs: ["U-01"] }] }],
    paths: [{ id: "p1", title: "P1", role: "r", intro: "i", steps }],
    unlisted,
  };
  fs.writeFileSync(path.join(root, "site/content/hubs.json"), JSON.stringify(hubs));
  const spec = (task) => ({ task, title: task, persona: "a (b)", steps: [{ n: 1, caption: "c", slug: "s", capture: { file: `docs/guide/screenshots/${task}/01-s.png`, annotated: null, viewport: { width: 1440, height: 900 } } }] });
  fs.writeFileSync(path.join(root, "docs/guide/specs/U-01.json"), JSON.stringify(spec("U-01")));
  fs.writeFileSync(path.join(root, "docs/guide/specs/U-02.json"), JSON.stringify(spec("U-02")));
  return root;
}

test("renderCaption escapes before converting bold and code", () => {
  assert.equal(renderCaption('Click **Save** in <b>"x"</b> & `a<b`'), "Click <strong>Save</strong> in &lt;b&gt;&quot;x&quot;&lt;/b&gt; &amp; <code>a&lt;b</code>");
  assert.equal(plainCaption("**Bold** and `code`"), "Bold and code");
});

test("stepImage prefers the annotated file and zero-pads the output name", () => {
  const spec = { task: "U-04" };
  const step = { n: 3, slug: "type-root", capture: { file: "docs/guide/screenshots/U-04/03-type-root.png", annotated: "docs/guide/screenshots/U-04/03-type-root-annotated.png", viewport: { width: 1440, height: 900 } } };
  assert.deepEqual(stepImage(spec, step), { spec: "U-04", n: 3, src: "U-04/03-type-root-annotated.png", out: "shots/U-04/03-type-root.webp", width: 1440, height: 900 });
  step.capture.annotated = null;
  assert.equal(stepImage(spec, step).src, "U-04/03-type-root.png");
  assert.equal(stepImage(spec, { n: 1, slug: "x" }), null);
});

test("validate flags a spec that is on disk but on no walkthrough", () => {
  const root = fixture();
  const errors = validate(loadContent(root), root);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /U-02/);
  assert.match(errors[0], /hubs\.json/);
  assert.match(errors[0], /unlisted/);
});

test("validate accepts a spec listed under unlisted", () => {
  const root = fixture({ unlisted: { "U-02": "QA only" } });
  assert.deepEqual(validate(loadContent(root), root), []);
});

test("validate flags a bad path step, a missing doc and a missing screenshot", () => {
  const root = fixture({ unlisted: { "U-02": "x" }, steps: ["h1/nope"] });
  const content = loadContent(root);
  content.hubs[0].docs.push({ title: "Gone", path: "docs/gone.md" });
  const errors = validate(content, root, { shotsDir: path.join(root, "shots") });
  assert.ok(errors.some((e) => /path p1.*h1\/nope/.test(e)));
  assert.ok(errors.some((e) => /docs\/gone\.md/.test(e)));
  assert.ok(errors.some((e) => /missing screenshot: U-01\/01-s\.png/.test(e)));
  assert.equal(walkthroughImages(content).length, 2);
});

test("validate flags duplicates and unknown specs", () => {
  const root = fixture({ unlisted: { "U-02": "x" } });
  const content = loadContent(root);
  content.hubs.push({ ...content.hubs[0] });
  content.hubs[0].walkthroughs.push({ slug: "w1", title: "dup", summary: "", specs: ["U-99"] });
  const errors = validate(content, root);
  assert.ok(errors.some((e) => /duplicate hub id: h1/.test(e)));
  assert.ok(errors.some((e) => /duplicate walkthrough slug/.test(e)));
  assert.ok(errors.some((e) => /U-99/.test(e)));
});

test("validate flags a hub with a missing band or cover, and bad cover or flagship refs", () => {
  const root = fixture({ unlisted: { "U-02": "x" } });
  const content = loadContent(root);
  assert.deepEqual(validate(content, root), []);
  const h = content.hubs[0];
  h.band = "nope";
  delete h.cover;
  let errors = validate(content, root);
  assert.ok(errors.some((e) => /band "nope"/.test(e)));
  assert.ok(errors.some((e) => /missing cover/.test(e)));
  h.band = "b1";
  h.cover = { spec: "U-77" };
  assert.ok(validate(content, root).some((e) => /cover spec U-77/.test(e)));
  h.cover = { file: "/screens/gone.webp", width: 1, height: 1 };
  assert.ok(validate(content, root).some((e) => /cover file \/screens\/gone\.webp/.test(e)));
  h.cover = { file: "/screens/c.webp", width: 1, height: 1 };
  content.flagship = ["ghost"];
  errors = validate(content, root);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /flagship hub "ghost"/);
});

test("validate with shotsDir requires the cover PNG", () => {
  const root = fixture({ unlisted: { "U-02": "x" } });
  const shots = path.join(root, "shots");
  fs.mkdirSync(path.join(shots, "U-01"), { recursive: true });
  fs.writeFileSync(path.join(shots, "U-01/01-s.png"), "x");
  const errors = validate(loadContent(root), root, { shotsDir: shots });
  assert.deepEqual(errors, ["missing screenshot: U-01/final-dark-1440.png"]);
});

test("coverImage maps a spec to its cropped cover and passes a file through", () => {
  assert.deepEqual(coverImage({ cover: { spec: "U-07" } }), { spec: "U-07", src: "U-07/final-dark-1440.png", href: "/shots/U-07/cover-dark.webp", width: 1220, height: 762, crop: DEFAULT_CROP });
  assert.deepEqual(coverImage({ cover: { file: "/screens/01-dashboard.webp", width: 2880, height: 1800 } }), { spec: null, src: null, href: "/screens/01-dashboard.webp", width: 2880, height: 1800, crop: null });
  const root = fixture();
  const jobs = walkthroughImages(loadContent(root));
  const cover = jobs.find((j) => j.src === "U-01/final-dark-1440.png");
  assert.equal(cover.out, "shots/U-01/cover-dark.webp");
  assert.deepEqual(cover.crop, { x: 220, y: 0, w: 1220, h: 762 });
});

test("a custom crop gets its own file, is upscaled to at least 960 wide and keeps its aspect ratio", () => {
  const c = coverImage({ cover: { spec: "U-10", crop: { x: 800, y: 190, w: 640, h: 400 } } });
  assert.equal(c.href, "/shots/U-10/cover-dark-800-190-640-400.webp");
  assert.deepEqual([c.width, c.height], [960, 600]);
  assert.equal(darkCrop("U-10", { ...DEFAULT_CROP }).href, "/shots/U-10/cover-dark.webp");
});

test("pathThumb is the cropped dark final of the last spec, or of thumbSpec, cropped by thumbCrop", () => {
  assert.equal(pathThumb({ specs: ["U-09", "U-09b"] }).src, "U-09b/final-dark-1440.png");
  assert.equal(pathThumb({ specs: ["U-09", "U-09b"], thumbSpec: "U-09" }).href, "/shots/U-09/cover-dark.webp");
  const t = pathThumb({ specs: ["U-10"], thumbSpec: "U-11", thumbCrop: { x: 0, y: 0, w: 1440, h: 900 } });
  assert.equal(t.href, "/shots/U-11/cover-dark-0-0-1440-900.webp");
  assert.deepEqual([t.width, t.height], [1440, 900]);
});

test("validate rejects a missing thumbSpec and malformed crops", () => {
  const root = fixture({ unlisted: { "U-02": "x" } });
  const content = loadContent(root);
  const w = content.hubs[0].walkthroughs[0];
  w.thumbSpec = "U-99";
  assert.ok(validate(content, root).some((e) => /thumbSpec U-99/.test(e)));
  w.thumbSpec = "U-02";
  w.thumbCrop = { x: 1300, y: 0, w: 400, h: 250 };
  assert.ok(validate(content, root).some((e) => /thumbCrop/.test(e)));
  delete w.thumbCrop;
  content.hubs[0].cover = { spec: "U-01", crop: { x: 0, y: 0, w: 0, h: 10 } };
  assert.ok(validate(content, root).some((e) => /cover crop/.test(e)));
  content.hubs[0].cover = { spec: "U-01", crop: { x: 220, y: 0, w: 1220, h: 762 } };
  assert.deepEqual(validate(content, root), []);
});

test("frameRoute uses the first goTo step of a spec cover, the route of a file cover, else the bare host", () => {
  const specs = new Map([["U-10", { steps: [{ action: "click", target: { url: "/x" } }, { action: "goTo", target: { url: "/templates" } }, { action: "goTo", target: { url: "/later" } }] }], ["U-11", { steps: [{ action: "click" }] }]]);
  assert.equal(frameRoute({ cover: { spec: "U-10" } }, specs), "kryptkeeper.example.com/templates");
  assert.equal(frameRoute({ cover: { spec: "U-11" } }, specs), "kryptkeeper.example.com");
  assert.equal(frameRoute({ cover: { file: "/screens/a.webp", width: 1, height: 1, route: "/" } }, specs), "kryptkeeper.example.com/");
  assert.equal(frameRoute({ cover: { file: "/screens/a.webp", width: 1, height: 1 } }, specs), "kryptkeeper.example.com");
});

test("thumbImage defaults to the last image and honours a thumb override", () => {
  const root = fixture({ unlisted: { "U-02": "x" } });
  const content = loadContent(root);
  const w = content.hubs[0].walkthroughs[0];
  assert.equal(thumbImage(w, content.specs).src, "U-01/01-s.png");
  w.thumb = { spec: "U-01", n: 1 };
  assert.equal(thumbImage(w, content.specs).n, 1);
  w.thumb = { spec: "U-01", n: 9 };
  assert.equal(thumbImage(w, content.specs), null);
  assert.ok(validate(content, root).some((e) => /thumb U-01 step 9/.test(e)));
  w.thumb = { spec: "U-02", n: 1 };
  assert.ok(validate(content, root).some((e) => /thumb spec U-02/.test(e)));
});

// ---------- caption overrides, validation and step selection ----------
function manySteps(content, caption = (n) => `Step ${n}`) {
  const spec = content.specs.get("U-01");
  spec.steps = [1, 2, 3, 4, 5].map((n) => ({ n, caption: caption(n), slug: `s${n}`, capture: { file: `docs/guide/screenshots/U-01/0${n}-s.png`, annotated: null, viewport: { width: 1440, height: 900 } } }));
  return spec;
}

test("captionOf prefers the captions.json override, keyed by the step number in the spec", () => {
  const spec = { task: "U-35", steps: [] };
  const captions = { "U-35": { 2: "Fill **SMTP host** with your mail relay" } };
  assert.equal(captionOf(captions, spec, 2, { caption: "Fill SMTP host with 192.168.1.1" }), "Fill **SMTP host** with your mail relay");
  assert.equal(captionOf(captions, spec, 3, { caption: "Original" }), "Original");
  assert.equal(captionOf(undefined, spec, 3, { caption: "Original" }), "Original");
});

test("loadContent reads site/content/captions.json when it exists", () => {
  const root = fixture({ unlisted: { "U-02": "x" } });
  assert.deepEqual(loadContent(root).captions, {});
  fs.writeFileSync(path.join(root, "site/content/captions.json"), JSON.stringify({ "U-01": { 1: "Hello" } }));
  assert.equal(loadContent(root).captions["U-01"][1], "Hello");
});

test("captionProblem flags selector syntax, key material and private addresses but not plain captions or URLs", () => {
  for (const bad of ["Click **xpath=//input**", "Click css=.btn", "a >> b", "Click //div[1]", "Click [@id=x]", "normalize-space()", "Click nth=2"]) assert.match(captionProblem(bad), /selector/, bad);
  assert.match(captionProblem('Fill with "-----BEGIN CERTIFICATE-----"'), /PEM/);
  assert.match(captionProblem(`Fill with ${"A".repeat(60)}`), /PEM/);
  for (const bad of ["Fill with 10.1.2.3", "host 172.16.0.9", "host 172.31.255.1", "host 192.0.2.166:18099"]) assert.match(captionProblem(bad), /private/, bad);
  for (const ok of ["Fill **ITSM URL** with \"https://acme.atlassian.net\"", "Fill with 172.32.0.1", "Fill with 8.8.8.8", `Fill ${"A".repeat(59)}`, "Click **Save** on the SMTP host row"]) assert.equal(captionProblem(ok), null, ok);
});

test("validate fails on a bad caption, naming the spec, the step and captions.json, and passes once overridden", () => {
  const root = fixture({ unlisted: { "U-02": "x" } });
  const content = loadContent(root);
  manySteps(content, (n) => (n === 3 ? 'Click **xpath=//a[@id="x"]**' : `Step ${n}`));
  const errors = validate(content, root);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /U-01 step 3/);
  assert.match(errors[0], /selector syntax/);
  assert.match(errors[0], /captions\.json/);
  content.captions = { "U-01": { 3: "Click **Save**" } };
  assert.deepEqual(validate(content, root), []);
});

test("validate catches a PEM blob and a private IPv4 address in a rendered caption", () => {
  const root = fixture({ unlisted: { "U-02": "x" } });
  const content = loadContent(root);
  manySteps(content, (n) => (n === 2 ? 'Fill **CSR** with "-----BEGIN CERTIFICATE REQUEST-----\nMIIB"' : n === 4 ? 'Fill **Host** with "192.0.2.166"' : `Step ${n}`));
  const errors = validate(content, root);
  assert.equal(errors.length, 2);
  assert.ok(errors.some((e) => /U-01 step 2.*PEM/.test(e)));
  assert.ok(errors.some((e) => /U-01 step 4.*private IPv4/.test(e)));
});

test("validate only checks captions of the steps a walkthrough shows", () => {
  const root = fixture({ unlisted: { "U-02": "x" } });
  const content = loadContent(root);
  manySteps(content, (n) => (n === 3 ? "Click css=.x" : `Step ${n}`));
  assert.equal(validate(content, root).length, 1);
  content.hubs[0].walkthroughs[0].steps = { "U-01": [1, 2, 4] };
  assert.deepEqual(validate(content, root), []);
});

test("validate flags an override for a spec or step that does not exist", () => {
  const root = fixture({ unlisted: { "U-02": "x" } });
  const content = loadContent(root);
  manySteps(content);
  content.captions = { "U-01": { 9: "x", 2: "" }, "U-77": { 1: "x" } };
  const errors = validate(content, root);
  assert.ok(errors.some((e) => /U-01 has no step 9/.test(e)));
  assert.ok(errors.some((e) => /U-01 step 2 must be a non-empty/.test(e)));
  assert.ok(errors.some((e) => /spec U-77 is not on any walkthrough/.test(e)));
});

test("selectedSteps and stepCount follow the steps selection, in the order given", () => {
  const root = fixture({ unlisted: { "U-02": "x" } });
  const content = loadContent(root);
  const spec = manySteps(content);
  const w = content.hubs[0].walkthroughs[0];
  assert.equal(stepCount(w, content.specs), 5);
  w.steps = { "U-01": [4, 1, 2] };
  assert.deepEqual(selectedSteps(w, spec).map((x) => x.n), [4, 1, 2]);
  assert.equal(stepCount(w, content.specs), 3);
});

test("walkthroughImages lists only the shown steps, as a union across walkthroughs, plus the hub-card thumb", () => {
  const root = fixture({ unlisted: { "U-02": "x" } });
  const content = loadContent(root);
  manySteps(content);
  const hub = content.hubs[0];
  hub.walkthroughs[0].steps = { "U-01": [2, 3] };
  hub.walkthroughs.push({ slug: "w2", title: "W2", summary: "s", specs: ["U-01"], steps: { "U-01": [3, 5] } });
  const outs = walkthroughImages(content).map((j) => j.out).filter((o) => !o.includes("cover-dark"));
  assert.deepEqual(outs.sort(), ["shots/U-01/02-s2.webp", "shots/U-01/03-s3.webp", "shots/U-01/05-s5.webp"]);
  hub.walkthroughs[0].thumb = { spec: "U-01", n: 1 };
  assert.ok(walkthroughImages(content).some((j) => j.out === "shots/U-01/01-s1.webp"));
});

test("thumbImage defaults to the last shown image", () => {
  const root = fixture({ unlisted: { "U-02": "x" } });
  const content = loadContent(root);
  manySteps(content);
  const w = content.hubs[0].walkthroughs[0];
  assert.equal(thumbImage(w, content.specs).n, 5);
  w.steps = { "U-01": [1, 2] };
  assert.equal(thumbImage(w, content.specs).n, 2);
});

test("validate rejects a steps selection with an unknown spec, a missing step, a duplicate or an empty list", () => {
  const root = fixture({ unlisted: { "U-02": "x" } });
  const content = loadContent(root);
  manySteps(content);
  const w = content.hubs[0].walkthroughs[0];
  w.steps = { "U-02": [1] };
  assert.ok(validate(content, root).some((e) => /steps U-02 is not one of the walkthrough's specs/.test(e)));
  w.steps = { "U-01": [1, 9] };
  assert.ok(validate(content, root).some((e) => /step 9 does not exist/.test(e)));
  w.steps = { "U-01": [1, 1] };
  assert.ok(validate(content, root).some((e) => /more than once/.test(e)));
  w.steps = { "U-01": [] };
  assert.ok(validate(content, root).some((e) => /non-empty list/.test(e)));
  w.steps = { "U-01": [1, 5] };
  assert.deepEqual(validate(content, root), []);
});

test("a hand-written page listed under pages must exist on disk", () => {
  const root = fixture({ unlisted: { "U-02": "not on the site" } });
  const file = path.join(root, "site/content/hubs.json");
  const hubs = JSON.parse(fs.readFileSync(file, "utf8"));
  hubs.pages = [{ url: "/try/", file: "try/index.html", title: "Try" }];
  fs.writeFileSync(file, JSON.stringify(hubs));
  assert.match(validate(loadContent(root), root).join("\n"), /page \/try\/: site\/try\/index\.html does not exist/);
  fs.mkdirSync(path.join(root, "site/try"), { recursive: true });
  fs.writeFileSync(path.join(root, "site/try/index.html"), "<html></html>");
  assert.deepEqual(validate(loadContent(root), root), []);
});
