# Discovery rates, v0.12 (W24)

Date: 2026-10-15 (local EDT; hub timestamps are Z). Hub build: commit
`be954c07f06dc7e5bd8c233b04c005fe665f73a3` (branch `kk/w24-a`, linux/arm64 build
inside podman). Host: Apple M4 Max, macOS 27.0.1, podman 6.1.3 (podman machine).
The host was also running unrelated containers and a CI job, so the scan
times below are not a quiet-machine benchmark.

Commands run (all podman, private /24 per run, cleaned up afterwards):

```bash
KK_EVIDENCE_DIR=<dir> bash tests/live/discovery/run.sh
KK_EVIDENCE_DIR=<dir> bash tests/live/discovery-protocols/run.sh
KK_EVIDENCE_DIR=<dir> bash tests/live/discovery/scheduled-case.sh
```

All three finished `ALL PASS`. Values below are copied from the archived
`report.json` files of these runs.

## Network TLS corpus (W24-01)

| class | expected | found | recall |
|---|---|---|---|
| tls10 | 4 | 4 | 1.00 |
| tls11 | 4 | 4 | 1.00 |
| tls12 | 6 | 6 | 1.00 |
| tls13 | 6 | 6 | 1.00 |
| selfsigned | 6 | 6 | 1.00 |
| expired | 5 | 5 | 1.00 |
| mlkem_hybrid | 5 | 5 | 1.00 |
| sni_only | 4 | 4 | 1.00 |
| not_tls | 3 | 3 | 1.00 |

- Overall recall: 43/43 = 1.0000
- False-positive rate: 0.0000 (45 endpoints reported on the /24; the 2 extras are the :8443/:9443 clone listeners, found 2 of 2 expected, not counted as false positives)
- Posture mismatches: 0
- /24 fast scan: 88 s (limit 300 s). Two earlier runs of the same harness on this Mac measured 85 s and 86 s.

```json
{
 "expected": 43,
 "found": 43,
 "recall": 1.0,
 "false_positive_rate": 0.0,
 "false_positives": [],
 "posture_mismatches": 0,
 "posture_detail": [],
 "extra_port_found": 2,
 "extra_port_expected": 2,
 "classes": {
  "tls10": {
   "found": 4,
   "expected": 4
  },
  "tls11": {
   "found": 4,
   "expected": 4
  },
  "tls12": {
   "found": 6,
   "expected": 6
  },
  "tls13": {
   "found": 6,
   "expected": 6
  },
  "selfsigned": {
   "found": 6,
   "expected": 6
  },
  "expired": {
   "found": 5,
   "expected": 5
  },
  "mlkem_hybrid": {
   "found": 5,
   "expected": 5
  },
  "sni_only": {
   "found": 4,
   "expected": 4
  },
  "not_tls": {
   "found": 3,
   "expected": 3
  }
 },
 "fast_scan_seconds": 88
}
```

## Protocols (W24-03)

| protocol | expected | found | recall |
|---|---|---|---|
| smtp | 2 | 2 | 1.00 |
| imap | 1 | 1 | 1.00 |
| pop3 | 1 | 1 | 1.00 |
| postgres | 1 | 1 | 1.00 |
| ldap | 1 | 1 | 1.00 |
| rdp | 1 | 1 | 1.00 |
| ssh | 1 | 1 | 1.00 |

Total 8/8. `rdp_mode`: `xrdp` (a real xrdp listener, not the stub).

```json
{
 "recall": {
  "smtp": {
   "found": 2,
   "expected": 2
  },
  "imap": {
   "found": 1,
   "expected": 1
  },
  "pop3": {
   "found": 1,
   "expected": 1
  },
  "postgres": {
   "found": 1,
   "expected": 1
  },
  "ldap": {
   "found": 1,
   "expected": 1
  },
  "rdp": {
   "found": 1,
   "expected": 1
  },
  "ssh": {
   "found": 1,
   "expected": 1
  }
 },
 "total": {
  "found": 8,
  "expected": 8
 },
 "rdp_mode": "xrdp"
}
```

## Thresholds and verdict

| Row | Target | Measured | Verdict |
|---|---|---|---|
| Recall, every TLS class | >= 95% | 100% (43/43) | MET |
| False-positive rate | <= 2% | 0% | MET |
| Fast /24 scan | <= 5 min | 88 s | MET |
| Recall, every protocol | >= 95% | 100% (8/8) | MET |
| Windows store recall (My, Root, CA) | delta 0 / documented rejects | not run | PENDING RUN |

## Not measured here

- Windows store recall (section below).
- Anything outside the corpus: IPv6, real-world networks, hosts behind load balancers, non-default ports other than 8443/9443.
- The corpus is synthetic and seeded by us; 100% on it shows the scanner finds what the harness serves, not a rate for arbitrary networks.

## Scheduled-scan proof (scheduled-case.sh)

```
PASS: scheduler refreshed last_scanned unattended: 2026-10-16T02:08:10Z -> 2026-10-16T02:09:09Z
```

Hub started with a 1 minute scan interval and one target; the script never
created a scan (audit shows 0 `discovery.scan.create` entries) and the
`/discovery/schedules` row for the target had a non-null `last_run`.

## Windows store recall (WinRM lab)

**Manual lab run pending.** This block needs a Windows 11 host; follow
"Repeatable lab recipe and store recall report" in
`docs/ops/WINRM_ENABLEMENT.md` and replace each `TBD`.

| store | Get-ChildItem Cert:\LocalMachine\<store> count | inventory count | delta |
|---|---|---|---|
| My | TBD | TBD | TBD |
| Root | TBD | TBD | TBD |
| CA | TBD | TBD | TBD |

Certificates rejected by `crypto/x509` (logged warnings): TBD
