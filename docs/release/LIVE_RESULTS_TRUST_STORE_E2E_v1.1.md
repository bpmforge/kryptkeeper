# Live validation W40-03: trust store push, hub to agent end to end (gap P12), v1.1

Date: 2026-10-26. Base: 66b2f9c0 (v1.1.0), no product code changed. Harness:
`bash tests/live/trust-store/e2e.sh` (with `e2e-inner.sh`), reusing the
`tests/live/ca-revoke/fixture.sh` hub fixture.
Host: macOS arm64, podman 6.1.3, Go 1.27.1. Hub: the linux/arm64 `kryptkeeper` binary built from
this checkout, in a container, with Postgres 16 (default) or embedded SQLite (`FX_DB_MODE=sqlite`).
Agents: the real `kryptkeeper-agent` in `debian:12` and `rockylinux:9`, running as the unprivileged
`kryptkeeper-agent` account with only the generated opt-in sudoers drop-in and
`KRYPTKEEPER_TRUST_STORE_PUSH=true`. Two humans (alice, bob; both pki-admin) come from API keys.

## Scope, honestly

This closes the gap named in `LIVE_RESULTS_TRUST_STORE_v1.1.md`: one run takes a bundle from a hub
API call through approval to the OS trust store of two real distributions, and back to the hub's
per-host status. There is no stub hub in this run. It does not replace that earlier run, which
additionally proves the sudoers rule, the opted-out refusal and the `visudo` check.

Two phases, each with an add and a remove:

1. A throwaway external root (key deleted right after it signs the leaf).
2. The hub's own root "UAT Root R", with a leaf issued by the hub. Only a root a hub CA owns can
   trigger the removal blast-radius warning, so the warning is asserted here.

## Verdict: PASS, Postgres (49 of 49) and SQLite (49 of 49)

| Step | Debian 12 | Rocky 9 | Hub |
|---|---|---|---|
| Hub boots, two agents enrol via `/agent/register`, hub lists both active | | | PASS |
| Leaf untrusted before the push (`openssl verify`) | PASS | PASS | |
| alice POST `/trust-bundles` (add) returns 202 and snapshots 2 targets | | | PASS |
| alice approving her own proposal: 403 | | | PASS |
| No bundle exists and no host changes while pending | PASS | PASS | PASS |
| bob approves: 200, bundle created | | | PASS |
| Agents apply; `openssl verify` against the system store accepts the leaf | PASS | PASS | |
| `GET /trust-bundles/{id}`: both hosts `applied` | | | PASS |
| Anchor `kryptkeeper-<sha256>.crt` in the distribution directory | PASS | PASS | |
| bob proposes the removal: 202 | | | PASS |
| Removal warning: none for the throwaway root; for the hub root "removing the root of hub CA ... distrusts 2 live managed certificate(s)" | | | PASS |
| bob approving his own removal: 403; root still trusted while pending | PASS | PASS | PASS |
| alice approves the removal: 200 | | | PASS |
| Leaf no longer trusted after removal | PASS | PASS | |
| Removal status `applied` on both hosts; anchor files removed | PASS | PASS | PASS |

Every step ran in both phases. No product defect was found, so no fix was made.

## Not proven here

- Windows (`certutil`) and macOS (`security`) on real hosts: NOT RUN. Out of scope, and this Mac's
  keychain and trust settings were deliberately not touched. The ROADMAP row stays.
- Opted-out refusal, `refused_not_opted_in` and `failed` outcomes through the hub (the opted-out
  refusal is proven agent-side in the earlier run; here both agents opt in).
- A third approver, quorum rules, multi-tenancy (bundles are platform-super-admin only, D-203), selectors
  other than explicit agent ids, and agents registered after proposal.
- Ubuntu, Alma, Fedora, SUSE. Postgres and SQLite were each run once.
- The hub-to-agent channel here is the container network with the hub's own TLS trust export; the
  agent's own TLS to the hub does not depend on the pushed root.
- Timing: agents polled every 2 s (`KRYPTKEEPER_POLL_INTERVAL`); production defaults are slower.

The throwaway root's private key is deleted on the host right after it signs the leaf; no key material
is in the repository or the logs. Containers, network and the work directory are removed on exit.
