# Migration verification (W33-19)

`scripts/migration-verify.sh` compares a manifest of source-estate SHA-256
fingerprints with the hub inventory and exits non-zero unless every one is mapped
(present with `origin` `imported` or `synced`; `--require-owner` also needs an
`owner_team`).

## Fast tests (always run)

`verify_script_test.go` drives the script against a stub HTTP hub:

    go test ./tests/live/migration/... -count=1

## Seeded 200-certificate run (opt in)

`run.sh` boots a hub on an engine-assigned loopback port, generates 200
self-signed certificates with `openssl`, bulk-imports them, then asserts: full
manifest exits 0 with `total=200 mapped=200 unmatched=0 percent=100.0`; a manifest
with one extra fingerprint exits 1; a second import adds 0. Needs `openssl`,
`python3`, `go`.

    KK_LIVE_MIGRATION=1 go test ./tests/live/migration/... -count=1 -v

Optional: `KK_MIG_HUB_PORT` (default engine-assigned), `KK_KEEP=1` to keep the
work directory.

## Using the script on a real estate

    openssl x509 -in cert.pem -fingerprint -sha256 -noout | cut -d= -f2 | tr -d ':' | tr 'A-Z' 'a-z'
    export KK_HUB_URL=https://hub.example KK_TOKEN=...   # token is never put in argv
    scripts/migration-verify.sh --manifest manifest.txt [--origin imported] [--require-owner]

Exit codes: 0 all mapped, 1 unmatched or empty manifest, 2 usage / auth / HTTP error.

The recorded ADCS lab rehearsal is `docs/release/ADCS_CUTOVER_REHEARSAL_v0.21.md`
and needs a human and a Windows AD CS lab.
