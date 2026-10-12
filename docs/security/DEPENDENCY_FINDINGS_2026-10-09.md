# Dependency Findings — 2026-10-09 (--deep, pre-public-release)

Category: `dependency` · Auditor: dependency-auditor · Scope: all Go modules + `ui/` npm

## Summary

| Severity | Reachable | Not reachable | Total |
|---|---|---|---|
| CRITICAL | 0 | 0 | 0 |
| HIGH | 1 | 0 | 1 |
| MEDIUM | 2 | 3 | 5 |
| LOW | 0 | 4 | 4 |
| **Total** | **3** | **7** | **10** |

One of the 3 reachable findings, DEP-003, is reachable only when the binary is built with Go 1.27.0–1.27.1.
Raw vs adjusted: `npm audit --omit=dev` reports 1 critical and 18 high. All of them come in through the
`shadcn` CLI, which is wrongly declared as a production dependency (DEP-005), so the adjusted shipped count is 0 critical.

Reachability for Go comes from govulncheck symbol traces. For npm it comes from whether the package
reaches the shipped `vite build` bundle and, if it does, whether the app calls the vulnerable code path.

**Package counts.** Go root module: 67 modules scanned, 0 vulnerable at the pinned toolchain except
module-level GO-2026-5932. terraform-provider: 24 modules, 4 vulnerable. sdk/delivery-go,
plugins/{example,f5,citrix}: 1–3 modules each, 0 third-party vulns. ui/: 655 packages (407 marked
prod, 249 dev). `npm audit` reports 34 advisories in all deps and 26 with `--omit=dev`. 1 package
(react-router) with advisories actually ships in the bundle.

**Tools.** govulncheck v1.8.0 (installed to scratch, not the repo), run once with the local Go
1.27.1 and again for the root with `GOTOOLCHAIN=go1.26.9`. Also used: `npm audit --json` (prod and
all), `go list -m -u`, license-file classification of the module cache and `package-lock.json`, and
npm registry lookups. **syft/grype were not installed, so the SBOM/SCA phase was skipped and no
automated CISA KEV correlation was done.** None of the CVE/GHSA IDs below is known to me to be on
KEV, but this has not been verified by a tool.

## Findings

### DEP-001 · HIGH · REACHABLE — gRPC-Go authz bypass + HTTP/2 DoS in terraform-provider
- **Module:** `terraform-provider-kryptkeeper` → `google.golang.org/grpc@v1.79.2`
- **Advisories (all symbol-reachable via `main.go:22 providerserver.Serve`):** GO-2026-4762 / CVE-2026-33186 / GHSA-p77j-4mvh-x3m3 (`:path` missing leading slash bypasses authorization, fixed 1.79.3); GO-2026-6061 (xDS RBAC + HTTP/2 server, fixed 1.82.1); GO-2026-6348 / CVE-2026-84304 (DATA-frame fragmentation OOM, fixed 1.83.1); GO-2026-6443 / CVE-2026-84445 (panic on missing authority, fixed 1.82.2). GO-2026-6441 is module-level only.
- **Preconditions:** attacker can connect to the provider's go-plugin gRPC listener. That listener is local loopback/unix and guarded by the go-plugin handshake and auto-mTLS, so the attacker needs a local foothold on the host running `terraform`.
- **Yields:** crash/OOM of the provider process (aborts the apply). The authz bypass gives little extra because the provider has no per-method interceptors.
- **Why HIGH and not CRITICAL:** the base CVSS for CVE-2026-33186 is high, but the attack needs local access.
- **Fix:** in `terraform-provider-kryptkeeper/go.mod`, bump `google.golang.org/grpc` to ≥ v1.83.1 (root already uses v1.83.2), or bump `terraform-plugin-go`/`-framework` so it comes in transitively.

### DEP-002 · MEDIUM · REACHABLE — stale x/net and x/text in terraform-provider (the x/net bump only reached the root module)
- **Module:** `terraform-provider-kryptkeeper` → `golang.org/x/net@v0.48.0`, `golang.org/x/text@v0.32.0` (root has x/net v0.60.0, x/text v0.42.0)
- **Symbol-reachable:** GO-2026-6617 / CVE-2026-97032 (HPACK encoder race → HTTP/2 crash; 31 traces through `providerserver.Serve` and `HubClient.do`; fixed x/net 0.60.0; this is the path that does not depend on the toolchain), GO-2026-6603, -6611, -6612 (HTTP/2 server memory/CPU/flow-control, fixed x/net 0.60.0), GO-2026-5026 / CVE-2026-39821 (idna Punycode, fixed 0.55.0), GO-2026-5970 / CVE-2026-56852 (x/text infinite loop, fixed 0.39.0). Package-level: GO-2026-4918. Module-level: GO-2026-5025/5027–5030/5942 (x/net/html, dnsmessage), GO-2026-6629 (x/text precis), GO-2026-5024 (x/sys v0.39.0 windows).
- **Preconditions:** a peer on the plugin channel (local) for the HTTP/2-server issues. A malicious/MITM'd Kryptkeeper hub response for the client-side paths (`HubClient.do`, `provider.go:136-142`).
- **Yields:** DoS of the provider process.
- **Fix:** in the provider module, bump x/net to ≥ v0.60.0, x/text to ≥ v0.42.0 and x/sys to ≥ v0.44.0 so they match the root module.

### DEP-003 · MEDIUM · REACHABLE (conditional) — `toolchain go1.26.9` is a floor, not a pin; Go 1.27.1 builds pull 11 reachable stdlib CVEs
- **Evidence:** the root module is clean at `GOTOOLCHAIN=go1.26.9`. With the local go1.27.1 (which wins because it is newer than the `toolchain` line), govulncheck reports 11 symbol-reachable stdlib vulns, all fixed in go1.27.2: GO-2026-6599/6600 (html/template context/escaping), -6603/-6611/-6612/-6617 (HTTP/2 server DoS/crash), -6605/-6613 (HTTP/1 CONNECT desync), -6607 (crypto/tls ECH), -6608 (MIME header memory bypass), -6610 (HTTP/2 transport framing). Package-level: -6604 (os.Root on Windows: affects agent Windows builds), -6609 (Range header size). The same set appears at module/package level in sdk/delivery-go and all plugins.
- **Preconditions:** a release or agent binary is built on a machine or image with Go 1.27.0–1.27.1 (developer laptops, any runner whose setup-go resolves differently). Release Dockerfiles use `golang:1.26-alpine` and CI uses `setup-go` with `go-version-file: go.mod`, so official artifacts are probably on 1.26.x. That has not been verified per-artifact.
- **Yields:** unauthenticated remote DoS of the HTTP/2 API, ACME/EST/SCEP/OCSP endpoints; possible html/template XSS in server-rendered pages; request smuggling via CONNECT desync.
- **Fix:** move to go1.27.2+ (or stay on the patched 1.26.x line). Set `GOTOOLCHAIN=go1.26.9` (or `+auto` with an exact pin) in release scripts. Add a `govulncheck` step against the exact release toolchain to CI.

### DEP-004 · MEDIUM · NOT REACHABLE (shipped) — react-router 7.14.0 in the production bundle
- **Package:** `react-router@7.14.0` / `react-router-dom@7.14.0` (direct). 9 advisories, up to CVSS 8.1: GHSA-49rj-9fvp-4h2h (turbo-stream RCE), GHSA-337j-9hxr-rhxg, GHSA-h8fp-f39c-q6mh, GHSA-qwww-vcr4-c8h2, GHSA-84g9-w2xq-vcv6, GHSA-8x6r-g9mw-2r78, GHSA-2j2x-hqr9-3h42 (SSR/RSC/framework-mode/server redirect), and the client-side GHSA-wrjc-x8rr-h8h6 (backslash open redirect in `<Link>`/`useNavigate`) and GHSA-chx6-hx7r-mcp5 (route-match DoS).
- **Reachability:** the UI is a client-only SPA using declarative `BrowserRouter` (3 occurrences). It has no SSR, RSC or turbo-stream. A grep of `ui/src` found no `navigate()`/`<Link>` targets taken from query params (`next`/`redirect`/`returnTo`), so the open-redirect sink has no attacker-controlled source today.
- **Preconditions (future):** someone adds a post-login `?returnTo=` that feeds `useNavigate`.
- **Yields:** open redirect / phishing pivot from the PKI console.
- **Fix:** `react-router-dom@^7.18.2` (non-breaking minor). Do this before going public: the advisory count is visible to anyone who runs `npm audit`.

### DEP-005 · MEDIUM · NOT REACHABLE — dev tooling declared as production dependencies (`shadcn`, `msw`)
- **Evidence:** `ui/package.json` puts the `shadcn` CLI and `msw` under `dependencies`. With `--omit=dev`, the audit reports 26 advisories, including **1 CRITICAL** (`proxy-addr@2.0.7`, GHSA-jqcg-44mw-7w3h, CVSS 9.1, via shadcn → @modelcontextprotocol/sdk@1.29.0 → express@5.2.1). Others on this path: MCP SDK GHSA-6qxp-vccf-f47h (7.5), hono (25 advisories), @hono/node-server, fast-uri, ip-address, express-rate-limit, body-parser, qs, braces/micromatch/fast-glob (shadcn major-version fix), ts-morph, js-yaml, nanoid, postcss, source-map-js, browserslist. `msw` has an install script and is used only behind `import.meta.env.DEV` in `src/main.tsx:8`, which Vite removes from prod builds.
- **Reachability:** none of these packages reach `dist/`. The risk is install-time and to dev/CI, plus a misleading "1 critical in production deps" result for public scanners (Dependabot/Snyk/OSV badges).
- **Preconditions:** `npm ci` on a dev/CI machine; anyone running a prod-only audit.
- **Yields:** install-time code execution surface (msw `postinstall`) and false-positive critical alerts.
- **Fix:** move `shadcn` and `msw` to `devDependencies`. Upgrade shadcn so @modelcontextprotocol/sdk ≥ 1.31.0 and express/proxy-addr ≥ 2.0.8 come in.

### DEP-006 · MEDIUM · NOT REACHABLE — build/test toolchain CVEs (vite, vitest, postcss, undici, js-yaml, fflate)
- **Packages:** `vite@8.0.7` (GHSA-fx2h-pf6j-xcff `server.fs.deny` bypass on Windows, 7.5; GHSA-v6wh-96g9-6wx3 launch-editor NTLM leak; fixed > 8.0.15). `vitest`/`@vitest/ui`/`@vitest/mocker` < 4.1.11 (GHSA-82fw-gwwq-j7x9 path traversal). `postcss@8.5.9` (sourceMappingURL arbitrary file read GHSA-6g55/-r28c/-fxqj, 7.5; `</style>` XSS GHSA-qx2v). `undici@7.24.7` via jsdom (21 advisories incl. TLS-validation bypass GHSA-vmh5/-w293, 7.4). `js-yaml` via @redocly/openapi-core (quadratic CPU). `fflate` (ZIP64 loop). `@humanfs/node`, `brace-expansion`, `baseline-browser-mapping`, `@babel/core` (low).
- **Reachability:** dev server, test runner and build only. Nothing ships. The dev server is exposed only if it is run with `--host`.
- **Preconditions:** a developer runs `vite dev --host` on Windows, or builds attacker-supplied CSS/source maps.
- **Yields:** local file read on a developer machine.
- **Fix:** `npm audit fix`, then vite ≥ 8.0.16, vitest ≥ 4.1.11, postcss ≥ 8.5.23, jsdom so that undici ≥ 7.29.1.

### DEP-007 · LOW · NOT REACHABLE — x/crypto/openpgp deprecation advisory
- `golang.org/x/crypto@v0.57.0` (latest) carries GO-2026-5932 (openpgp unmaintained/unsafe) at module level only. No `crypto/openpgp` import exists in `internal/` or `cmd/`. **Preconditions:** none (informational; the package would first have to be imported). **Yields:** none. **Fix:** none needed. Add a lint/depguard rule that bans `golang.org/x/crypto/openpgp`.

### DEP-008 · LOW · NOT REACHABLE (no CVE) — unmaintained PKCS#7 parser on an untrusted-input path
- `go.mozilla.org/pkcs7@v0.10.0` (upstream archived) is imported by `internal/est/server.go` and `internal/connectors/est_client.go`. `github.com/smallstep/pkcs7@v0.2.3` (the maintained fork) is also in go.mod. There is no current advisory, but the EST server parses PKCS#7 from unauthenticated or partly authenticated clients, and no upstream maintainer would ship a fix.
- **Preconditions:** a future parser bug in the archived module. **Yields:** EST endpoint DoS or verification confusion.
- **Fix:** move EST onto `smallstep/pkcs7` and drop `go.mozilla.org/pkcs7`.

### DEP-009 · LOW · NOT REACHABLE (no CVE) — outdated security-relevant Go libraries
None of these has an open advisory at the pinned version. Updates are available:
`russellhaering/goxmldsig` 1.6.0→1.6.1 and `gosaml2` 0.11.0→0.12.0 (SAML signature verification; this library family has a history of CVEs, so bump first). `beevik/etree` 1.6.0→1.8.1. `jackc/pgx/v5` 5.9.2→5.11.0. `modernc.org/sqlite` 1.58.0→1.60.1. `ThalesGroup/crypto11` 1.6.1→1.6.8. `cloudflare/circl` 1.6.3→1.6.5. `google.golang.org/grpc` 1.83.2→1.84.0. `spiffe/go-spiffe` 2.8.1→2.9.0. `mark3labs/mcp-go` 0.55.0→1.2.1 (major; MCP is the proposal-only write path, so review the changelog). Already current: `x/crypto` v0.57.0, `x/net` v0.60.0, `x/text` v0.42.0, `wazero` v1.12.0, `tink-go` v2.8.0, `go-pkcs12` v0.7.3. No JWT/JOSE library is linked into the root module's binaries: `go-jose/v4` 4.1.4 (update 4.1.5) is in the module graph only and absent from `go list -deps`. XML: `mattermost/xml-roundtrip-validator` v0.1.0 is current. React 19.2.4 has no advisories.
- **Preconditions:** a future advisory against a pinned version (most likely in the SAML/XML-DSig path). **Yields:** none today; it lengthens the patch window when one lands.

### DEP-010 · LOW · NOT REACHABLE — license obligations for Apache-2.0 public release
- **No GPL, AGPL, SSPL, BUSL or unlicensed dependencies** in any Go module or in `ui/` (Go: 33 Apache, 23 BSD, 21 MIT, 8 MPL-2.0. npm: 555 MIT, 33 ISC, 22 Apache, 20 BSD, plus the items below).
- **MPL-2.0 (weak, file-level copyleft):** 8 HashiCorp modules in `terraform-provider-kryptkeeper` only (go-plugin, go-uuid, terraform-plugin-framework/-go/-log, terraform-registry-address, terraform-svchost, yamux). The MPL text names LGPL only as a Secondary License option. Compatible with Apache-2.0 distribution if the files are unmodified and a source pointer is kept. Also `lightningcss*` (dev/build only, not distributed).
- **Ship-with-attribution:** `@fontsource-variable/geist` is **OFL-1.1** and its font files are in `dist/`, so the OFL text must go into NOTICE / third-party licenses. `CC-BY-4.0` (1, build data), `Python-2.0` (1, dev), `BlueOak-1.0.0`/`MIT-0`/`0BSD`/`CC0` are permissive.
- **Preconditions:** public distribution of binaries or images without the attribution files. **Yields:** license non-compliance (legal, not exploitable).
- **Fix:** generate `THIRD_PARTY_NOTICES` (go-licenses + license-checker) covering Geist (OFL) and the MPL modules.

## Supply-chain checks

- **Slopsquatting:** none found. The less common npm names were checked against the registry (official repos, weekly downloads): `tw-animate-css` 40.6M, `@base-ui/react` 16.3M (mui/base-ui, created 2025-12), `@fontsource-variable/geist` 2.8M, `cmdk` 43.5M, `sonner` 50.8M, `next-themes` 27.2M, `class-variance-authority` 67.6M, `shadcn` 11.6M. All Go direct deps are well-known upstreams. No typo-adjacent names.
- **Install-time scripts:** only `fsevents` (dev, optional) and `msw` (see DEP-005). No suspicious lifecycle hooks.
- **Dependency confusion:** no private npm scopes. Go `github.com/bpmforge/kryptkeeper/sdk/delivery-go` is resolved by `replace => ./sdk/delivery-go`. Before going public, make sure the `bpmforge` GitHub org is owned so that external plugin authors who drop the replace get the real module.
- **SBOM/KEV:** skipped because syft/grype are absent. Rerun with `syft dir:. -o cyclonedx-json | grype` before release.

## Top 5
1. DEP-001 HIGH: bump grpc in terraform-provider from 1.79.2 to ≥ 1.83.1 (reachable authz bypass/DoS).
2. DEP-003 MEDIUM: pin the release toolchain; Go 1.27.1 builds have 11 reachable stdlib CVEs (fixed 1.27.2).
3. DEP-002 MEDIUM: the x/net v0.60.0 bump did not reach terraform-provider (x/net v0.48.0, x/text v0.32.0 reachable).
4. DEP-005 MEDIUM: move shadcn/msw to devDependencies; clears the "critical" proxy-addr in the prod audit.
5. DEP-004 MEDIUM: react-router-dom 7.14.0 → ≥ 7.18.2 (shipped; currently not reachable in SPA mode).

## Addendum (coordinator, 2026-10-09): SBOM and grype

syft 1.54.1 produced a CycloneDX SBOM of the whole repository (591 components): docs/security/sbom_2026-10-09.cdx.json. grype 0.120.1 over it: 104 matches (Medium 47, High 42, Low 7, Unknown 6, Critical 2). **CISA KEV: 0** (no match carries a known-exploited flag).

Critical and High by location (all already covered by DEP-001/002/004/005 above):

| Severity | Location | Matches |
|---|---|---|
| Critical | terraform-provider-kryptkeeper | 1 |
| Critical | ui | 1 |
| High | .github | 2 |
| High | terraform-provider-kryptkeeper | 8 |
| High | ui | 32 |

The root Go module (the hub) has no Critical or High grype matches; the Terraform provider (grpc v1.79.2, x/net v0.48.0) and ui/ build tooling and the misfiled shadcn CLI dependencies account for all of them, as the reachability analysis above concluded.

**DEP-011 (LOW, CI supply chain):** grype's two `.github` matches (GHSA-cxww-7g56-2vh6) are `actions/download-artifact@v4` in terraform-provider.yml and agent-build.yml. The floating `v4` tag resolves at run time to the latest v4 (past the 4.1.3 fix), so the advisory does not apply as written; the real issue is that these and the other actions listed by `grep -rhoE "uses: [^ ]+@[^ ]+" .github/workflows/` are referenced by mutable tag, not commit SHA, which W20-01 asked for ("every action pinned"). Remediation: pin every `uses:` to a full commit SHA with the version in a comment. GitHub Actions is currently disabled on the repo, so this matters from the moment it is re-enabled.
