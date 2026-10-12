# Contributing to Kryptkeeper

Thank you for your interest in contributing.

## Getting started

```bash
git clone https://github.com/bpmforge/kryptkeeper.git
cd kryptkeeper
go test ./...          # all tests must pass
cd ui && npm install && npm test -- --run  # frontend tests
```

## Development requirements

- Go 1.22+ (see `go.mod` for exact version)
- Node.js 20+ for the frontend (`ui/`)
- Optional: SoftHSM2 for PKCS#11 tests (`brew install softhsm`)
- Optional: Docker for integration testing

## Pull request process

1. **Fork** the repository and create a branch: `git checkout -b feat/my-feature`
2. **Write tests** alongside any new code — we aim for >80% coverage on new packages.
3. **Run the full test suite** before pushing:
   ```bash
   go test ./...
   cd ui && npm run lint && npm test -- --run
   ```
4. **Keep commits atomic** — one logical change per commit with a clear message.
5. **Open a PR** against `main`. The PR description should explain *why*, not just *what*.

## Code conventions

- Follow existing package layout: feature-sliced, not layered.
- No new global state; inject dependencies via constructor arguments.
- No comments explaining *what* the code does — only *why* (hidden constraints, workarounds).
- New packages must have at least one `_test.go` file.
- Build-tag-guarded files (`//go:build windows`, `//go:build pkcs11`) must have a
  corresponding stub for the default build.

## Reporting bugs

Open a [GitHub Issue](https://github.com/bpmforge/kryptkeeper/issues) using the
**Bug Report** template. For security issues, see [SECURITY.md](SECURITY.md).

## Proposing features

Open a [GitHub Discussion](https://github.com/bpmforge/kryptkeeper/discussions) or a
**Feature Request** issue before writing code — we want to make sure the design fits before
you invest time in implementation.

## Licence

By contributing you agree that your changes will be licensed under the
[Apache 2.0 License](LICENSE).
