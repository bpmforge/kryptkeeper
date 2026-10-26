# kryptkeeper.io: how the website is built and kept current

The website is plain static HTML in `site/`, deployed to Cloudflare Pages. Most of it is
generated from the verified UI guide in `docs/guide/`, so the walkthroughs on the site show
exactly what the captured screens show, and a new feature cannot ship without someone
deciding where it goes on the site.

## What lives where

| Path | What it is | Edit by hand? |
|---|---|---|
| `site/content/release.json` | The release version the site advertises (downloads, cosign command, status label). The only place a version is written. | Yes |
| `site/content/hubs.json` | The site map: feature pages ("hubs"), their walkthroughs, the role paths, and the stories deliberately left off the site (`unlisted`). | Yes, this is the source of truth |
| `docs/guide/STORIES.md`, `docs/guide/specs/U-*.json` | The user stories and the capture specs. Step captions on the site come from each spec step's `caption`. | Yes, through the guide workflow |
| `docs/guide/screenshots/` | Gated screenshots from a capture run. Gitignored. | No, regenerate them |
| `site/shots/<spec>/<nn>-<slug>.webp` | Screenshots converted for the site (the annotated version when a step has one). Committed. | No, run `images.mjs` |
| `site/features/**`, `site/paths/**`, `site/sitemap.xml` | Generated pages. | No, run `build.mjs` |
| `site/index.html` | Home page. The regions between `<!-- hubs:start/end -->` and `<!-- paths:start/end -->` are generated; the rest is hand-written. | Outside the markers only |
| `site/style.css`, `site/lightbox.js`, `site/_headers`, `site/_redirects` | Hand-written. | Yes |
| `site/tools/` | `content.mjs` (loading and validation), `build.mjs` (pages and `--check`), `images.mjs` (WebP conversion), `content.test.mjs`. | Yes |

## Structure

- **Feature hub** `/features/<hub>/`: what the feature is, why it matters, optional key points,
  then "How it works": one card per walkthrough. Docs links go to the public GitHub repo.
  A `pending` note shows a visible callout when the client-side screens are not captured yet.
- **Walkthrough** `/features/<hub>/<slug>/`: every captured step of one or more specs, in order,
  with the caption and screenshot. A walkthrough made of several specs (for example a key
  ceremony with three people) shows each spec as a part with its persona.
- **Path** `/paths/<id>/`: an ordered list of walkthroughs across hubs for one role.
- A spec can appear in more than one hub (for example U-05 is both "Certificate authorities"
  and "Windows and Active Directory"). The image is stored once and the later copies point
  their canonical link at the first.

## When you add or change a feature

Every user-facing feature gets a guide story, and every guide story is either on the site or
explicitly unlisted. CI enforces this (`ci-pr`, step "Website in sync with the guide").

1. Add the story to `docs/guide/STORIES.md` and its spec to `docs/guide/specs/U-NN.json`
   (see the guide workflow in `docs/guide/tools/`).
2. Add a walkthrough to the right hub in `site/content/hubs.json`:
   `{"slug": "...", "title": "...", "summary": "one sentence", "specs": ["U-NN"]}`.
   If no hub fits, add a hub. If it belongs in a role path, add `"<hub>/<slug>"` to that
   path's `steps`. If it should not be on the site at all, add it to `unlisted` with a reason.
3. Capture the screenshots (below), then run:

   ```bash
   node site/tools/images.mjs --shots docs/guide/screenshots
   node site/tools/build.mjs
   node site/tools/build.mjs --check --shots docs/guide/screenshots --public ../kryptkeeper-public
   node --test site/tools/content.test.mjs
   ```

4. Commit `site/content/hubs.json`, the new `site/shots/U-NN/`, and the regenerated pages
   in the same PR as the feature.

`build.mjs --check` fails when:
- a spec on disk is on no hub and not in `unlisted` (a new story nobody placed);
- `hubs.json` names a spec that does not exist;
- a path step points at a walkthrough that does not exist;
- a docs link points at a file missing from this repo, or from the public checkout with `--public`;
- a generated page on disk differs from what the generator would write, or is stale;
- with `--shots`, a screenshot a walkthrough needs is missing.

## Regenerating all screenshots

Screenshots come from a fresh hub driven by Playwright (`docs/guide/tools/run-all.sh`; it
needs `RUN` and `BIN`, see the header of that script). After a full run:

```bash
node site/tools/images.mjs --shots docs/guide/screenshots --force
node site/tools/build.mjs
```

`images.mjs` uses the Chromium that `ui/node_modules/playwright-core` already provides
(run `npm ci` in `ui/` first), so the site needs no image library. WebP quality 0.8 averages
about 35 KB per 1440-pixel screen; the whole site is about 16 MB of images.

## Changing the advertised release

1. Make sure the public GitHub release exists (`github.com/bpmforge/kryptkeeper/releases/tag/vX.Y.Z`).
2. Set `version` in `site/content/release.json`, update the hand-written "What's proven"
   section in `site/index.html` from that release's lab record, then run `node site/tools/build.mjs`.
   The build stamps the version into every download link, image tag and label.
3. `node site/tools/build.mjs --check --check-release` must pass before deploying. `--check`
   fails on any other `vX.Y.Z` anywhere on the site; `--check-release` fails if the release
   page does not exist yet, so the site never links to a download that is not there.

## Preview and deploy

- Preview: `python3 -m http.server 18532 --directory site`, then open `http://127.0.0.1:18532/`.
  Pages use root-relative links, so serve the `site/` folder as the web root.
- Deploy: Cloudflare Pages project `kryptkeeper-site`, deployed by hand (no auto-deploy):
  `CLOUDFLARE_API_TOKEN="$(cat ~/.config/kryptkeeper-site/cloudflare-token)" npx wrangler@4.144.0 pages deploy site --project-name kryptkeeper-site --branch main`
  (plus `CLOUDFLARE_ACCOUNT_ID`). That file holds the kryptkeeper.io token; do not use
  `~/.config/kryptkeeper-lab/cloudflare-token`, which is a different account. Never print or commit it. Run `--check --check-release` first. Deploy only from
  `main` after the site PR has merged and the owner has said to publish; use
  `--branch <name>` for a preview deploy.
- `site/tools/` is in the deploy folder but holds no secrets; Pages serves it as plain files.
- The `_headers` CSP allows scripts and images from the site itself only. Keep new scripts
  as files under `site/` and images under `site/shots/`.

## Docs links and the public repo

Docs links on hub pages point at `github.com/bpmforge/kryptkeeper` (the public repo), which
is published as a snapshot at each release. Run `build.mjs --check --public <public checkout>`
before deploying; a link to a doc that is not in the public snapshot yet will 404 until the
next snapshot.
