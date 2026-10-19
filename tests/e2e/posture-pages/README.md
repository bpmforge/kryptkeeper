# Posture pages journey (W28-18)

One Playwright test visits Algorithm Sunset, Issuance Velocity, CA Health,
Revocation Activity, Change Audit and Search against 1,000 seeded
certificates, asserts the on-page numbers equal the API, and follows the
drill-through links shipped by W28-21 (D-141).

Prerequisites: podman, openssl, python3, curl, node 24.
`@playwright/test` is pinned to 1.59.1 (chromium build 1217).

```bash
export APP_BOOTSTRAP_TOKEN=<token> KRYPTKEEPER_KEYSTORE_PASSPHRASE=<different passphrase> \
       KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true
podman compose -p kk-e2e up -d --build      # from the repo root; dashboard on :3000

cd tests/e2e/posture-pages
npm ci
npx playwright install chromium             # skipped if the browser is already cached
bash seed.sh                                # idempotent; ~30 s
npx playwright test
```

`KK_E2E_BASE_URL` overrides `http://localhost:3000`. Tear down with
`podman compose -p kk-e2e down -v`.

Known product gap: the Algorithm Sunset "+N more" link uses the group label as
`q`, which matches no certificate, so the test asserts the filter and count
equal the API's, not that the list is non-empty.
