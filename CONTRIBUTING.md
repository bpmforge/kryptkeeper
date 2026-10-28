# Contributing to Kryptkeeper

Thank you for your interest in contributing.

Development happens in a private repository. This public repository receives a
signed snapshot at each release, so commit hashes in lab records point at the
development history. An accepted pull request reaches this repository with
the next snapshot.

## Getting started

```bash
git clone https://github.com/bpmforge/kryptkeeper.git
cd kryptkeeper
go test ./...          # all tests must pass
npm --prefix ui ci
npm --prefix ui run test   # frontend tests
```

## Development requirements

- Go 1.27 (matches `go.mod`; its `toolchain` line pins the patch)
- Node.js 24 (`ui/.nvmrc`) and npm for the frontend (`ui/`). Use npm, not pnpm.
- `golangci-lint`, needed by `make lint` and `make gate`:
  `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`
- Optional: SoftHSM2 for PKCS#11 tests (`brew install softhsm`)
- Optional: Docker for integration testing

## Pull request process

1. **Fork** the repository and create a branch: `git checkout -b feat/my-feature`
2. **Write tests** alongside any new code — we aim for >80% coverage on new packages.
3. **Run the gate** before pushing (see below): `make gate`.
4. **Keep commits atomic** — one logical change per commit, and use
   [Conventional Commits](https://www.conventionalcommits.org/) (`type(scope): subject`, e.g.
   `fix(notifications): retry on 503`). The pre-commit hook rejects other messages.
5. **Open a PR** against `main`. The PR description should explain *why*, not just *what*.

## Before you push: `make gate`

`make gate` runs the checks your change needs. It compares your branch with
`origin/main` (`scripts/ci/changed-areas.sh`) and picks from:

1. `scripts/ci/check-slop.py`: clear-cut slop in the lines you add (always)
2. `go build ./...`, `go test ./...`, `make lint` and `bash tests/protocol/run.sh` (Go changes)
3. `bash scripts/validate-openapi.sh` (Go or `docs/openapi.yaml` changes)
4. `cd ui && npm run lint && npm test -- --run` (UI or API contract changes)
5. `node site/tools/build.mjs --check` and the site tool tests (docs or site changes)

A change to `.github/`, `scripts/`, the `Makefile` or build config runs everything, and
`make gate-full` always does. ci-pr in CI uses the same areas, and ci-main runs the full
suite on every merge to `main`.

`make fix` rewrites safe formatting issues in the files you changed (`gofmt -s`,
`eslint --fix`). `make hooks` installs a pre-commit hook that does the same for staged
files and then runs the slop check, plus a pre-push hook that runs `make gate` for pushes
to `main`. A line that trips the slop check on purpose can carry a
`slop:allow <reason>` marker. If `make lint` reports that `golangci-lint` is missing,
install it with the command under [Development requirements](#development-requirements).

## Where things are

- [`docs/plugins/README.md`](docs/plugins/README.md): writing a delivery plugin and the SDK (`make plugins` builds them; the vetted list is [`docs/plugins/REGISTRY.md`](docs/plugins/REGISTRY.md)).
- [`docs/APP_MAP.md`](docs/APP_MAP.md): screens and routes of the UI.
- [`docs/site/README.md`](docs/site/README.md): the website. A new user-facing feature needs a guide story and a place in `site/content/hubs.json`; CI checks that every story is on the site or explicitly unlisted.
- [`docs/COMPONENT_MAP.md`](docs/COMPONENT_MAP.md): Go packages and components.
- [`docs/openapi.yaml`](docs/openapi.yaml): the API contract, validated by `scripts/validate-openapi.sh`.

## Code conventions

The rules in [`docs/design/SECURITY_PRINCIPLES.md`](docs/design/SECURITY_PRINCIPLES.md)
are not negotiable: a change that breaks one is rejected regardless of what it
adds.


- Follow existing package layout: feature-sliced, not layered.
- No new global state; inject dependencies via constructor arguments.
- No comments explaining *what* the code does — only *why* (hidden constraints, workarounds).
- New packages must have at least one `_test.go` file.
- Build-tag-guarded files (`//go:build windows`, `//go:build pkcs11`) must have a
  corresponding stub for the default build.

## What to expect from maintainers

- We aim to give a first response within **5 business days** on issues and PRs. A first response
  may be a question or a triage label rather than a fix.
- Issues labelled `good first issue` are scoped to one package and point at a test to copy.
- The label set is defined in [`.github/labels.yml`](.github/labels.yml).
- Security reports go through [SECURITY.md](SECURITY.md), not public issues.

## Reporting bugs

Open a [GitHub Issue](https://github.com/bpmforge/kryptkeeper/issues) using the
**Bug Report** template. For security issues, see [SECURITY.md](SECURITY.md).

## Proposing features

Open a [GitHub Discussion](https://github.com/bpmforge/kryptkeeper/discussions) or a
**Feature Request** issue before writing code — we want to confirm the design fits before
you invest time in implementation.

## Licence

By contributing you agree that your changes will be licensed under the
[Apache 2.0 License](LICENSE).
