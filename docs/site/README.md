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
| `site/content/proof.json` | Source of the `/proof/` page and the home page's proof summary: one entry per lab record in `docs/release/` (environment, what ran, result, counts, version, what is not proven, record path) plus the "Not proven yet" list from `docs/ROADMAP.md`. Only record what the record shows. Each entry also has `evidence` (excerpts that must appear verbatim in a file under `docs/`, at most 25 lines, checked by `--check`) and optional `shots` (images under `site/`, with a caption and capture date). Evidence, labels and captions fail the check if they hold a private IPv4 address, a lab hostname or a token pattern. | Yes |
| `site/proof/shots/*.webp` | Public-evidence screenshots (crt.sh, the release page, a rendered terminal), cropped from 1440-wide captures. Check each for lab IPs and hostnames before committing. | No (captured once) |
| `site/features/**`, `site/paths/**`, `site/proof/index.html`, `site/sitemap.xml` | Generated pages. | No, run `build.mjs` |
| `site/index.html` | Home page. The regions between `<!-- hubs:start/end -->`, `<!-- paths:start/end -->` and `<!-- proof:start/end -->` are generated; the rest is hand-written. | Outside the markers only |
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
   record links in `site/content/proof.json` (they point at the release tag, so the files must exist at that tag), then run `node site/tools/build.mjs`.
   The build stamps the version into every download link, image tag and label.
3. `node site/tools/build.mjs --check --check-release` must pass before deploying. `--check`
   fails on any other `vX.Y.Z` anywhere on the site; `--check-release` fails if the release
   page does not exist yet, so the site never links to a download that is not there.

## Preview and deploy

- Preview: `python3 -m http.server 18532 --directory site`, then open `http://127.0.0.1:18532/`.
  Pages use root-relative links, so serve the `site/` folder as the web root.
- Deploy: `node site/tools/deploy.mjs` is the only supported way. Never run
  `wrangler pages deploy site` by hand: the folder holds build tooling and inputs, and an
  earlier hand deploy published `site/tools/build.mjs` with the lab-name pattern in it.
  The script:
  1. refuses uncommitted changes under `site/` (a preview may pass `--allow-dirty`);
  2. runs `build.mjs --check --check-release` (`--check` only for a preview branch);
  3. stages the payload from `site/tools/payload.mjs` into a temporary folder: every file
     except `tools/`, `content/`, dotfiles other than `.well-known/`, underscore files below
     the top level (scratch pages such as `shots/_sheet.html`) and editor leftovers;
  4. scans every staged file, binaries included, with the pattern in
     `site/tools/private-ref.txt` (lab names, private addresses, local paths), for private
     keys and common tokens, and for the deploy token and account id themselves; any hit
     stops the deploy;
  5. uploads that folder to the Cloudflare Pages project `kryptkeeper-site`.
- Options: `--dry-run` stages and scans without uploading; `--branch <name>` makes a
  preview deploy (default `main`).
- Credentials: `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`, or the files
  `~/.config/kryptkeeper-site/cloudflare-token` and `~/.config/kryptkeeper-site/account-id`.
  That token is for kryptkeeper.io only; never print or commit it. Deploy only from `main`
  after the site PR has merged and the owner has said to publish.
- `site/tools/private-ref.txt` is kept out of the public repository, so the deploy only
  runs from the development repository. `build.mjs --check` runs the same payload scan,
  and `node --test site/tools/payload.test.mjs` covers the payload rules.
- The `_headers` CSP allows scripts and images from the site itself only. Keep new scripts
  as files under `site/` and images under `site/shots/`.

## Docs links and the public repo

Docs links on hub pages point at `github.com/bpmforge/kryptkeeper` (the public repo), which
is published as a snapshot at each release. Run `build.mjs --check --public <public checkout>`
before deploying; a link to a doc that is not in the public snapshot yet will 404 until the
next snapshot.
