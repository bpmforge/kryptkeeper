# Live validation W40-03: trust store push (Linux leg), v1.1

Date: 2026-10-25. Base: a91c4f29 plus the W40-03 changes. Harness: `tests/live/trust-store/run.sh`.
Host: macOS arm64, podman; containers `debian:12` and `rockylinux:9` (arm64), real
`kryptkeeper-agent` built for linux/arm64, running as the unprivileged account
`kryptkeeper-agent` with only the generated opt-in sudoers drop-in.

## Scope, honestly

This proves the **agent half** against real distributions: opt-in, the one exact sudoers
rule, the root helper, the OS commands and the OS's own verification. The hub is a stub
(`tests/live/trust-store/stubhub`) that serves one scripted bundle; the hub half (CA-only
validation, dual-control gating, proposer cannot approve, status per host, removal
warning) is covered by `internal/bootstrap/trust_bundle_test.go`. The Windows and macOS
commands are covered by exact-command unit tests only, not run on real hosts (ROADMAP:
"Needs partner hardware").

## Verdict: PASS on both distributions (13 of 13 steps each)

| Step | Debian 12 | Rocky 9.3 |
|---|---|---|
| Agent's `--generate-trust-store-sudoers` output passes `visudo -cf` | PASS | PASS |
| Drop-in contains no wildcard | PASS | PASS |
| Agent account cannot run any other command as root (`sudo -n /bin/true` refused) | PASS | PASS |
| Leaf issued by a throwaway root is not trusted before the push | PASS | PASS |
| Opted out: agent reports `refused_not_opted_in` | PASS | PASS |
| Opted out: trust store unchanged (leaf still untrusted) | PASS | PASS |
| Opted in: agent reports `applied` | PASS | PASS |
| `openssl verify` against the system store accepts the leaf | PASS | PASS |
| Anchor file `kryptkeeper-<sha256>.crt` in the distribution's directory | PASS (`/usr/local/share/ca-certificates`) | PASS (`/etc/pki/ca-trust/source/anchors`) |
| State file records the fingerprint | PASS | PASS |
| Remove: agent reports `applied` | PASS | PASS |
| Leaf no longer trusted after removal | PASS | PASS |
| Anchor file removed | PASS | PASS |

Commands exercised: Debian `update-ca-certificates` (add) and `update-ca-certificates
--fresh` (remove); Rocky `update-ca-trust extract` (both).

## Not proven here

- The full hub to agent path in one run (hub approval, then agent apply). The two halves
  are each proven; a combined run belongs with the next wave's integration live pass.
- Windows (`certutil`) and macOS (`security`) on real hosts. Check first: the agent treats a nonzero exit of
  `certutil -store <store> <sha1>` as "certificate not present" (Microsoft's page does not state that exit-code
  contract), and a zero exit as "already trusted before us, do not take ownership". Likewise on macOS it reads
  `security find-certificate -a -Z` output for the SHA-1 hash.
- Ubuntu, Alma, Fedora (same code path as the two proven families, not run).

The throwaway root's private key is deleted inside the container right after it signs the
leaf; no key material is in the repository or the logs.
