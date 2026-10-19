# Kryptkeeper API SDK (TypeScript)

Generated from `docs/openapi.yaml` by openapi-generator (version pinned in
`scripts/gen-sdks.sh`). Do not edit and do not commit generated files:
this directory only keeps this README and `.gitignore`.

Regenerate: `bash scripts/gen-sdks.sh --check` (needs Java 11+, else podman/docker
to run the pinned generator image). Verify: `(cd sdk/api-ts && npm install --no-audit --no-fund && npx tsc --noEmit)`.

Base URL: the spec's server is relative (`/api/v1`); configure the client with
`BASE_URL = https://hub.example.com/api/v1` and a Bearer token.
Released with each `v*` tag as `kryptkeeper-api-ts-<version>` on the GitHub Release.
