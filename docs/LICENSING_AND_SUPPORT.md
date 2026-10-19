# Licensing and Support

What you may do with Kryptkeeper, what we check about the code it depends on, and
what support and security response you can expect.

## Licence

Kryptkeeper is licensed under the [Apache License 2.0](../LICENSE).

## Feature availability

Kryptkeeper has no paywalled features: everything in this repository is available under Apache-2.0 with no feature gates, licence keys or editions.

## Dependency licences

Every Go module and npm package Kryptkeeper ships is checked against a licence
denylist before it can merge:

| Licence family | Policy |
|----------------|--------|
| GPL (any version, including bare `GPL`) | Denied |
| AGPL | Denied |
| SSPL | Denied |
| LGPL | Allowed |
| Anything the tooling cannot classify (`Unknown`, empty) | Denied unless explicitly listed with a reason |

For an SPDX `OR` expression the dependency passes if any alternative is allowed;
for `AND` it fails if any part is denied.

The `license-check` workflow (`.github/workflows/license-check.yml`) enforces this
on every pull request and weekly, using `scripts/check-licenses.sh`. The full
inventory of direct and transitive Go and npm dependencies, with their licences, is
[`THIRD_PARTY_LICENSES.md`](../THIRD_PARTY_LICENSES.md); CI verifies it lists every
dependency and has not drifted. The older, Go-only
[`docs/THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) is superseded by it.

## Support model

| Channel | What you get |
|---------|--------------|
| Community support via [GitHub issues](https://github.com/bpmforge/kryptkeeper/issues) | Best effort. No SLA is promised for community support. |
| Paid support | None offered today. |

Do not report security vulnerabilities in public issues; see below.

## Security response

Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).

| Stage | Target |
|-------|--------|
| Acknowledgement | Within 3 business days |
| Fix, Critical severity | 7 days |
| Fix, High severity | 30 days |
| Fix, Medium severity | 90 days |
| Fix, Low severity | Next minor release |
| Coordinated-disclosure window | 90 days (may be extended for complex issues) |

These are targets, not guarantees.

## Supported versions

See [SECURITY.md](../SECURITY.md#supported-versions) for which release lines
receive security fixes.
