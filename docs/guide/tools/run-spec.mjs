#!/usr/bin/env node
// Guide-scribe capture runner: replays docs/guide/specs/<id>.json against a real hub UI,
// gates every capture (A blank, B error, C premature), writes screenshots and updates the
// spec in place with capture.gates / boundingBox / attempts.
//
//   node run-spec.mjs --base http://127.0.0.1:14180 --tokens tokens.json [--api http://127.0.0.1:18080] \
//        [--out docs/guide] [--theme dark|light] [--vp 1440x900] [--final-only] spec1.json spec2.json ...
//
// Step actions: goTo click dblclick fill type select check uncheck press hover wait screenshot
//               api(setup, no capture) eval(setup, no capture) upload viewport scroll
// Target: {role,name,exact} | {label} | {text} | {placeholder} | {css} | {testid}; optional nth, within(css)
// Step extras: expect:{...target} (must be visible before capture), allow:[regex strings] (Gate-B allowlist),
//   expectError:true (documented error state, recorded not failed), redact:[css] (mask secrets),
//   fullPage:true, capture:false (action only), noAnnotate:true, settle:ms
import { chromium } from "../../../ui/node_modules/playwright-core/index.mjs";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

const args = process.argv.slice(2);
const opt = { base: "", tokens: "", api: "", out: "docs/guide", theme: "light", vp: "1440x900", finalOnly: false, specs: [] };
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--base") opt.base = args[++i];
  else if (a === "--tokens") opt.tokens = args[++i];
  else if (a === "--tokdir") opt.tokdir = args[++i];
  else if (a === "--api") opt.api = args[++i];
  else if (a === "--out") opt.out = args[++i];
  else if (a === "--theme") opt.theme = args[++i];
  else if (a === "--vp") opt.vp = args[++i];
  else if (a === "--finals") opt.finals = true;
  else if (a === "--final-only") opt.finalOnly = true;
  else if (a === "--no-write") opt.noWrite = true;
  else opt.specs.push(a);
}
const [VW, VH] = opt.vp.split("x").map(Number);
const ROOT = process.cwd();

// ---------- minimal PNG decode (8-bit RGB/RGBA, non-interlaced) ----------
function decodePng(buf) {
  let p = 8, w = 0, h = 0, ct = 0; const idat = [];
  while (p < buf.length) {
    const len = buf.readUInt32BE(p), type = buf.toString("ascii", p + 4, p + 8);
    if (type === "IHDR") { w = buf.readUInt32BE(p + 8); h = buf.readUInt32BE(p + 12); ct = buf[p + 17]; }
    else if (type === "IDAT") idat.push(buf.subarray(p + 8, p + 8 + len));
    p += 12 + len;
  }
  const bpp = ct === 6 ? 4 : 3, raw = zlib.inflateSync(Buffer.concat(idat)), stride = w * bpp;
  const out = Buffer.alloc(h * stride);
  for (let y = 0; y < h; y++) {
    const f = raw[y * (stride + 1)], src = y * (stride + 1) + 1, dst = y * stride;
    for (let x = 0; x < stride; x++) {
      const a = x >= bpp ? out[dst + x - bpp] : 0, b = y ? out[dst - stride + x] : 0, c = x >= bpp && y ? out[dst - stride + x - bpp] : 0;
      let v = raw[src + x];
      if (f === 1) v += a; else if (f === 2) v += b; else if (f === 3) v += (a + b) >> 1;
      else if (f === 4) { const pa = Math.abs(b - c), pb = Math.abs(a - c), pc = Math.abs(a + b - 2 * c); v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c; }
      out[dst + x] = v & 255;
    }
  }
  return { w, h, bpp, data: out };
}
function gateA(buf) {
  const im = decodePng(buf), n = im.w * im.h, hist = new Map(); let sum = 0, sum2 = 0;
  for (let i = 0; i < n; i += 7) {
    const o = i * im.bpp, key = (im.data[o] << 16) | (im.data[o + 1] << 8) | im.data[o + 2];
    hist.set(key, (hist.get(key) || 0) + 1);
    const l = 0.3 * im.data[o] + 0.59 * im.data[o + 1] + 0.11 * im.data[o + 2]; sum += l; sum2 += l * l;
  }
  const m = Math.ceil(n / 7), mean = sum / m, sd = Math.sqrt(Math.max(0, sum2 / m - mean * mean));
  const dom = Math.max(...hist.values()) / m;
  const pass = buf.length > 6000 && sd > 4 && dom < 0.985 && hist.size > 8;
  return { pass, sd: +sd.toFixed(2), dominant: +dom.toFixed(3), colours: hist.size, bytes: buf.length };
}
function diffFrac(a, b) {
  const A = decodePng(a), B = decodePng(b);
  if (A.w !== B.w || A.h !== B.h) return 1;
  let d = 0; const n = A.w * A.h;
  for (let i = 0; i < n; i++) { const o = i * A.bpp; if (Math.abs(A.data[o] - B.data[o]) + Math.abs(A.data[o + 1] - B.data[o + 1]) + Math.abs(A.data[o + 2] - B.data[o + 2]) > 24) d++; }
  return d / n;
}

// ---------- helpers ----------
const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48);
function loc(page, t) {
  let scope = page; if (t.within) { let w = page.locator(t.within); if (t.withinText) w = w.filter({ hasText: t.withinText }); scope = w.first(); }
  let l;
  if (t.role) l = scope.getByRole(t.role, { name: t.name instanceof Array ? undefined : t.name, exact: t.exact ?? false });
  else if (t.label) l = scope.getByLabel(t.label, { exact: t.exact ?? false });
  else if (t.text) l = scope.getByText(t.text, { exact: t.exact ?? false });
  else if (t.placeholder) l = scope.getByPlaceholder(t.placeholder, { exact: t.exact ?? false });
  else if (t.testid) l = scope.getByTestId(t.testid);
  else if (t.css) l = scope.locator(t.css);
  else throw new Error("target has no locator: " + JSON.stringify(t));
  if (t.filterText) l = l.filter({ hasText: t.filterText });
  return t.nth === undefined ? l.first() : l.nth(t.nth);
}
const BUSY = '[aria-busy="true"], [class*="spinner" i], [class*="skeleton" i], [role="progressbar"]:not([aria-valuenow])';
const TEXT_ERR = /something went wrong|unhandled exception|uncaught|internal server error|unexpected error|failed to load|could not load|forbidden|status 5\d\d/i;

async function bboxOf(l) { try { return await l.boundingBox({ timeout: 800 }); } catch { return null; } }

async function annotate(page, box, n) {
  await page.evaluate(({ b, n }) => {
    const d = document.createElement("div");
    d.id = "__kk_anno";
    d.style.cssText = `position:fixed;left:${b.x - 4}px;top:${b.y - 4}px;width:${b.width + 8}px;height:${b.height + 8}px;border:3px solid #e11d48;border-radius:8px;box-shadow:0 0 0 2px rgba(255,255,255,.85);pointer-events:none;z-index:2147483647`;
    const k = document.createElement("div");
    k.textContent = String(n);
    k.style.cssText = "position:absolute;left:-14px;top:-14px;width:24px;height:24px;border-radius:12px;background:#e11d48;color:#fff;font:700 13px/24px system-ui;text-align:center;box-shadow:0 0 0 2px #fff";
    d.appendChild(k); document.body.appendChild(d);
  }, { b: box, n });
}
const unannotate = (page) => page.evaluate(() => document.getElementById("__kk_anno")?.remove());


// {{fp:<common name>}} -> certificate SHA-256 fingerprint, {{caid:<name>}} -> CA id, resolved against the live hub at run time
async function resolveValue(page, v, tokens) {
  if (typeof v !== "string" || !v.includes("{{")) return v;
  const m = v.match(/\{\{(fp|caid):([^}]+)\}\}/); if (!m) return v;
  const got = await page.evaluate(async ({ kind, name, tk }) => {
    const tok = sessionStorage.getItem("auth_token") || tk; const h = { authorization: "Bearer " + tok };
    if (kind === "fp") { const r = await (await fetch("/api/v1/certificates?q=" + encodeURIComponent(name), { headers: h })).json(); return (r.data || []).find((c) => c.common_name === name)?.fingerprint_sha256 || ""; }
    const r = await (await fetch("/api/v1/cas", { headers: h })).json(); return (r.data || []).find((c) => c.name === name || c.display_name === name)?.id || "";
  }, { kind: m[1], name: m[2], tk: tokens?.access_token ?? "" });
  if (!got) throw new Error("could not resolve " + m[0]);
  return v.replace(m[0], got);
}
const tokenCache = {};
function tokensFor(spec) { const f = opt.tokdir ? path.join(opt.tokdir, `tok-${spec.principal || "ada"}.json`) : opt.tokens; if (!f) return null; return (tokenCache[f] ??= JSON.parse(fs.readFileSync(f, "utf8"))); }

async function main() {
  const browser = await chromium.launch();
  const summary = [];
  for (const specPath of opt.specs) {
    const spec = JSON.parse(fs.readFileSync(specPath, "utf8")); const tokens = tokensFor(spec); const specViewport = opt.finals ? undefined : spec.viewport;
    const sid = spec.task;
    const ctx = await browser.newContext({ permissions: ["clipboard-read", "clipboard-write"], viewport: { width: specViewport?.width ?? VW, height: specViewport?.height ?? VH }, deviceScaleFactor: 1, colorScheme: opt.theme, reducedMotion: "reduce", acceptDownloads: true });
    if (tokens && !spec.signedOut) {
      await ctx.addInitScript((tk) => {
        try {
          if (!sessionStorage.getItem("auth_token") && !sessionStorage.getItem("__kk_loggedout")) {
            sessionStorage.setItem("auth_token", tk.access_token);
            if (tk.refresh_token) sessionStorage.setItem("kk_refresh_token", tk.refresh_token);
            sessionStorage.setItem("kk_session", "1");
          }
          if (tk.theme) localStorage.setItem("kk_theme", tk.theme);
        } catch {}
      }, { ...tokens, theme: opt.theme === "dark" ? "dark" : undefined });
    }
    const page = await ctx.newPage(); page.setDefaultTimeout(8000); page.setDefaultNavigationTimeout(15000);
    const ev = { console: [], resp: [], pageerr: [] };
    page.on("console", (m) => { if (m.type() === "error") ev.console.push(m.text()); });
    page.on("pageerror", (e) => ev.pageerr.push(String(e)));
    page.on("response", (r) => { const s = r.status(); if (s >= 400) ev.resp.push(`${s} ${r.request().method()} ${r.url().replace(/^https?:\/\/[^/]+/, "")}`); });
    const shotDir = path.join(ROOT, opt.out, "screenshots", sid + (opt.theme === "dark" || opt.vp !== "1440x900" ? "" : ""));
    fs.mkdirSync(shotDir, { recursive: true });
    const result = { task: sid, steps: 0, shots: 0, annotated: 0, blocked: 0, retries: 0, errors: [] };
    const apiBase = opt.api || opt.base;
    const stepsOut = [];
    let lastBox = null;
    const finalOnly = opt.finalOnly || opt.finals;
    let steps = spec.steps;
    if (opt.finals) { const fu = spec.lastRun?.finalUrl || "/"; steps = [{ action: "goTo", target: { url: fu }, caption: "Final state", slug: "final", n: 1 }]; }
    let reached = -1;
    for (let si = 0; si < steps.length; si++) {
      reached = si;
      const st = steps[si];
      const n = st.n ?? si + 1;
      ev.console.length = ev.resp.length = ev.pageerr.length = 0;
      let target = null, box = null;
      try {
        // ---- action ----
        switch (st.action) {
          case "goTo": {
            const u = st.target?.url ?? st.url;
            await page.goto(u.startsWith("http") ? u : opt.base + u, { waitUntil: "domcontentloaded" });
            break;
          }
          case "viewport": await page.setViewportSize({ width: st.width, height: st.height }); break;
          case "api": {
            const r = await page.evaluate(async ({ base, req, tk }) => {
              const tok = sessionStorage.getItem("auth_token") || tk;
              const res = await fetch(base + "/api/v1" + req.path, { method: req.method || "GET", headers: { "content-type": "application/json", authorization: "Bearer " + tok }, body: req.body ? JSON.stringify(req.body) : undefined });
              return { status: res.status, body: await res.text() };
            }, { base: "", req: st.request, tk: tokens?.access_token ?? "" }).catch((e) => ({ status: 0, body: String(e) }));
            if (st.expectStatus ? !st.expectStatus.includes(r.status) : r.status >= 400) throw new Error(`api ${st.request.path} -> ${r.status} ${r.body.slice(0, 200)}`);
            break;
          }
          case "eval": await page.evaluate(st.script); break;
          case "approveAs": {
            // hidden setup: another principal approves a pending action (their own UI side is captured in the approver stories)
            const ptk = tokensFor({ principal: st.as });
            const h = { authorization: "Bearer " + ptk.access_token, "content-type": "application/json" };
            const inbox = await (await fetch(apiBase + "/api/v1/approvals/inbox", { headers: h })).json();
            const hit = (inbox.data || []).find((x) => x.type === "pending_action" && String(x.summary).includes(st.match));
            if (!hit) throw new Error("no pending action matching " + st.match);
            const r = await fetch(`${apiBase}/api/v1/approvals/inbox/pending_action/${hit.id}/approve`, { method: "POST", headers: h });
            if (!r.ok) throw new Error("approve failed " + r.status + " " + (await r.text()).slice(0, 120));
            break;
          }
          case "wait": if (st.ms) await page.waitForTimeout(st.ms); break;
          case "screenshot": break;
          case "press": await page.keyboard.press(st.value); break;
          case "scroll": await page.mouse.wheel(0, st.value ?? 600); await page.waitForTimeout(300); break;
          default: {
            target = loc(page, st.target);
            await target.waitFor({ state: "visible", timeout: 8000 });
            if (st.action === "click") { await target.scrollIntoViewIfNeeded(); await target.click({ timeout: 8000 }); }
            else if (st.action === "dblclick") await target.dblclick();
            else if (st.action === "fill") await target.fill(String(await resolveValue(page, st.value, tokens)));
            else if (st.action === "type") await target.pressSequentially(String(st.value), { delay: 20 });
            else if (st.action === "select") await target.selectOption(typeof st.value === "object" ? st.value : { label: String(st.value) });
            else if (st.action === "check") await target.check();
            else if (st.action === "uncheck") await target.uncheck();
            else if (st.action === "hover") { await target.scrollIntoViewIfNeeded(); await target.hover(); }
            else if (st.action === "upload") await target.setInputFiles(st.value);
            else if (st.action === "find") { await target.scrollIntoViewIfNeeded(); }
            else throw new Error("unknown action " + st.action);
          }
        }
        result.steps++;
        if (st.capture === false || finalOnly && si !== steps.length - 1) { stepsOut.push(st); continue; }
        // ---- wait for result, then gates with retry ----
        const file = `${String(n).padStart(2, "0")}-${slug(st.slug || st.caption || st.action)}.png`;
        const rel = path.join(opt.out, "screenshots", sid, file);
        const outName = finalOnly ? `final-${opt.theme}-${VW}.png` : file;
        let gates, attempts = 0, buf = null, evidence = [];
        for (attempts = 1; attempts <= 3; attempts++) {
          evidence = [];
          await page.waitForTimeout(st.settle ?? 350);
          if (st.expect) await loc(page, st.expect).waitFor({ state: "visible", timeout: 6000 }).catch(() => evidence.push("C: expected element not visible " + JSON.stringify(st.expect)));
          await page.evaluate(() => document.fonts?.ready).catch(() => {});
          // Gate C: no busy markers
          const busy = await page.locator(BUSY).evaluateAll((els) => els.filter((e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== "hidden"; }).length).catch(() => 0);
          if (busy) evidence.push(`C: ${busy} loader/skeleton element(s) visible`);
          // Gate B
          const allow = (st.allow || []).map((r) => new RegExp(r, "i"));
          const okAllowed = (s) => allow.some((r) => r.test(s));
          const bProbs = [];
          for (const c of ev.console) if (!okAllowed(c)) bProbs.push("console: " + c.slice(0, 160));
          for (const e of ev.pageerr) if (!okAllowed(e)) bProbs.push("pageerror: " + e.slice(0, 160));
          for (const r of ev.resp) if (!okAllowed(r)) bProbs.push("http: " + r);
          const alerts = await page.locator('[role="alert"]:visible').allInnerTexts().catch(() => []);
          for (const a of alerts) if (a.trim() && !okAllowed(a)) bProbs.push("role=alert: " + a.trim().slice(0, 160));
          const body = await page.locator("main").first().innerText({ timeout: 1500 }).catch(() => "");
          const m = body.match(TEXT_ERR); if (m && !okAllowed(m[0])) bProbs.push("text: " + m[0]);
          // shot 1 + stability shot 2
          const shotOpts = { animations: "disabled", caret: "hide", fullPage: !!st.fullPage, mask: [] };
          for (const r of st.redact || []) shotOpts.mask.push(page.locator(r)); shotOpts.maskColor = "#1f2937";
          const s1 = await page.screenshot(shotOpts);
          await page.waitForTimeout(700);
          const s2 = await page.screenshot(shotOpts);
          const df = diffFrac(s1, s2);
          if (df > 0.004) evidence.push(`C: unstable, ${(df * 100).toFixed(2)}% pixels changed between shots`);
          const ga = gateA(s2);
          if (!ga.pass) evidence.push(`A: blank/near-blank ${JSON.stringify(ga)}`);
          buf = s2;
          const bFail = bProbs.length > 0 && !st.expectError;
          if (bFail) evidence.push(...bProbs.map((x) => "B: " + x));
          gates = { A: ga.pass ? "PASS" : "FAIL", B: bProbs.length === 0 ? "PASS" : st.expectError ? "DOCUMENTED" : "FAIL", C: evidence.some((e) => e.startsWith("C")) ? "FAIL" : "PASS", attempts };
          if (st.expectError && bProbs.length) gates.errorEvidence = bProbs;
          if (!evidence.length) break;
          if (attempts < 3) { result.retries++; await page.waitForTimeout(1200 * attempts); }
        }
        const cap = { file: finalOnly ? path.join(opt.out, "screenshots", sid, outName) : rel, annotated: null, gates, viewport: { width: specViewport?.width ?? VW, height: specViewport?.height ?? VH, deviceScaleFactor: 1 } };
        if (evidence.length) {
          cap.gates.evidence = evidence; cap.status = "BLOCKED"; result.blocked++;
          const bd = path.join(ROOT, opt.out, "screenshots", "bugs"); fs.mkdirSync(bd, { recursive: true });
          const bf = path.join(bd, `${sid}-step-${String(n).padStart(2, "0")}.png`);
          if (!opt.noWrite) fs.writeFileSync(bf, buf);
          cap.evidenceShot = path.relative(ROOT, bf);
          result.errors.push(`step ${n}: ${evidence.join(" | ")}`);
        } else {
          if (!opt.noWrite) fs.writeFileSync(path.join(ROOT, cap.file), buf);
          result.shots++;
          const ov = await page.evaluate(() => { const d = document.querySelector("[role=dialog]"); if (!d) return null; const r = d.getBoundingClientRect(); return r.top < -1 || r.bottom > innerHeight + 1 ? { top: Math.round(r.top), bottom: Math.round(r.bottom), viewportHeight: innerHeight } : null; }).catch(() => null);
          if (ov) { cap.dialogOverflow = ov; (result.overflow ||= []).push(`step ${n}: ${JSON.stringify(ov)}`); }
          if (target && !st.noAnnotate && !finalOnly && st.action !== "goTo") {
            box = await bboxOf(target);
            if (box && box.width > 0 && box.height > 0 && box.y >= 0 && box.y < VH && !st.fullPage) {
              await annotate(page, box, n);
              const ab = await page.screenshot({ animations: "disabled", caret: "hide", mask: (st.redact || []).map((r) => page.locator(r)), maskColor: "#1f2937" });
              await unannotate(page);
              const af = file.replace(/\.png$/, "-annotated.png");
              cap.annotated = path.join(opt.out, "screenshots", sid, af);
              if (!opt.noWrite) fs.writeFileSync(path.join(ROOT, cap.annotated), ab);
              cap.boundingBox = { x: Math.round(box.x), y: Math.round(box.y), w: Math.round(box.width), h: Math.round(box.height) };
              result.annotated++;
            }
          }
        }
        stepsOut.push({ ...st, n, capture: cap });
      } catch (e) {
        result.blocked++; result.errors.push(`step ${n} ${st.action}: ${String(e.message).replace(/\n\s*/g, " ").slice(-500)}`);
        const bd = path.join(ROOT, opt.out, "screenshots", "bugs"); fs.mkdirSync(bd, { recursive: true });
        const bf = path.join(bd, `${sid}-step-${String(n).padStart(2, "0")}-fail.png`);
        try { if (!opt.noWrite) fs.writeFileSync(bf, await page.screenshot({ animations: "disabled", caret: "hide" })); } catch {}
        stepsOut.push({ ...st, n, capture: { status: "BLOCKED", error: String(e.message).split("\n")[0].slice(0, 300), evidenceShot: path.relative(ROOT, bf) } });
        if (st.optional) { result.blocked--; stepsOut[stepsOut.length - 1].capture.status = "SKIPPED-OPTIONAL"; continue; }
        if (!st.continueOnFail) break;
      }
    }
    result.finalUrl = (() => { try { const u = new URL(page.url()); return u.pathname + u.search; } catch { return "/"; } })();
    if (!opt.finalOnly && !opt.finals && !opt.noWrite) {
      for (let k = reached + 1; k < steps.length; k++) stepsOut.push({ ...steps[k], n: steps[k].n ?? k + 1, capture: { status: "NOT-RUN" } });
      delete spec.finals; spec.steps = stepsOut; spec.lastRun = { at: new Date().toISOString(), base: opt.base, theme: opt.theme, viewport: `${VW}x${VH}`, ...result };
      fs.writeFileSync(specPath, JSON.stringify(spec, null, 2) + "\n");
    }
    if (opt.finals && !opt.noWrite) { spec.finals = { ...(spec.finals || {}), [`${opt.theme}-${VW}`]: stepsOut[0]?.capture }; fs.writeFileSync(specPath, JSON.stringify(spec, null, 2) + "\n"); }
    summary.push(result);
    console.log(`${sid}: steps=${result.steps} shots=${result.shots} annotated=${result.annotated} blocked=${result.blocked} retries=${result.retries}`);
    for (const e of result.errors) console.log("   !! " + e);
    for (const o of result.overflow || []) console.log("   ^^ dialog overflows viewport: " + o);
    await ctx.close();
  }
  await browser.close();
}
main().catch((e) => { console.error(e); process.exit(1); });
