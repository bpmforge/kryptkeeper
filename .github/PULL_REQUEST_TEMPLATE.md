## Summary

<!-- What does this change do, and why? -->

## Related issue

<!-- Link the issue this change addresses, if any -->

## Gate checklist

- [ ] `go build ./...` passes
- [ ] `go test ./...` passes (note the ok package count)
- [ ] `make lint` reports 0 issues
- [ ] If `ui/` was touched: `cd ui && npm run lint && npm test -- --run`
- [ ] If a response shape or endpoint changed: `docs/openapi.yaml` updated and
      `ui/src/generated/api-types.ts` regenerated/committed
- [ ] `CHANGELOG.md` has an entry for this change (user-visible changes)
- [ ] No key material, secrets, internal hostnames/IPs, or personal paths added

## Notes for reviewers

<!-- Anything a reviewer should specifically check -->
