# WSTEP / XCEP failure runbook (W26-14)

Maps what the client or hub shows to the audit row and the fix. Design:
[WSTEP_AUTOENROLLMENT.md](WSTEP_AUTOENROLLMENT.md). Lab recipe:
[WSTEP_LAB_RUNBOOK.md](WSTEP_LAB_RUNBOOK.md). Kerberos errors are surfaced only through
audit and logs, not the UI.

Audit actions in code are `wstep.enroll`, `wstep.renew` and `xcep.policy`, outcome
`success` or `denied` (`internal/wstep/server.go`, `internal/xcep/server.go`). There is no
dedicated Kerberos event. Query:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  "$HUB/api/v1/audit?action=wstep.enroll&limit=100"   # also wstep.renew, xcep.policy
```

Rows with `"outcome":"denied"` carry the reason in `change_summary`.

| Symptom (client) | Hub log / audit | Cause | Fix |
|---|---|---|---|
| Request refused, no certificate; Kerberos `KRB_AP_ERR_SKEW` | `denied` row for `wstep.enroll` or `xcep.policy`, detail `Kerberos authentication failed` | Client clock differs from the hub by more than the 5 minute Kerberos skew | `w32tm /resync` on the client. (The hub backdates NotBefore by 5 minutes, so smaller skews still work.) |
| Hub serves no `/wstep` or `/xcep` (404); client cannot add the policy server | Startup log: `keytab has no entry for <spn>`, or `<KRYPTKEEPER_WSTEP_KEYTAB_FILE> and <KRYPTKEEPER_WSTEP_SPN> must both be set` (`internal/wstep/kerberos.go`) | SPN not in the keytab (matching is case-sensitive), or one of the two variables unset | Regenerate the keytab with the exact SPN, mode 0600, set both variables, restart |
| 401 with `WWW-Authenticate: Negotiate` and no credential | Not audited | Normal first leg of every Negotiate exchange | None |
| 401 `authentication required` after the client sent a ticket | `denied` row, detail `Kerberos authentication failed` | The presented credential was rejected: wrong name (IP instead of DNS name, so NTLM), wrong SPN, or stale ticket | Address the hub by its DNS name, check the SPN and keytab, `klist purge` on the client |
| Template missing from the list / not offered | `xcep.policy` normally `success`; WSTEP refusing the other kind logs a `denied` `wstep.enroll` row naming the rule | XCEP offers only templates matching the enrollee type (machine vs user, W20-17); template inactive or without an OID | Set `enrollee_type`, make the template active with an OID, republish, then `certutil -f -PolicyServer * -PolicyCache delete` |
| `WS_E_ENDPOINT_FAULT_RECEIVED` on enroll | Hub log line `wstep: SOAP fault ...`; a `denied` `wstep.enroll` row when the refusal was a rule | The client reports every SOAP fault as this opaque error | Read the hub log for the real reason |
| Old policy/template still applied after a change | None | Windows caches the policy for 8 hours (`nextUpdateHours`) | `certutil -f -PolicyServer * -PolicyCache delete`, then `certutil -pulse` |
| Renewal refused | `denied` `wstep.renew` row with the reason | Presented certificate expired, revoked or not valid for client auth (TLS-client-cert path) | Re-enroll over Kerberos |

Each row except the clock-skew and Kerberos-401 ones is verified against code; the
live reproduction of skew and template filtering belongs to the W26-13 matrix, which is
still `PENDING-RUN`.

## Alert `wstep.kerberos.failure` (planned)

Intended rule: more than 5 Kerberos failures per hour raises an alert. **This event is
planned and is not emitted by the hub in v0.14** (`grep -rn "kerberos.failure" internal cmd`
finds nothing) and no alert rule ships. Do not rely on it.

Interim detection: count `denied` rows for `wstep.enroll` and `xcep.policy` per hour from
the audit API and alert when the count exceeds 5:

```bash
for a in wstep.enroll xcep.policy; do
  curl -sS -H "Authorization: Bearer $TOKEN" "$HUB/api/v1/audit?action=$a&limit=100"
done | python3 -c '
import sys,json,datetime as d
n=0; cut=d.datetime.now(d.timezone.utc)-d.timedelta(hours=1)
dec=json.JSONDecoder(); s=sys.stdin.read(); i=0
while i<len(s):
    o,j=dec.raw_decode(s,i); i=j
    while i<len(s) and s[i].isspace(): i+=1
    for a in o.get("data",[]):
        t=d.datetime.fromisoformat(a["timestamp"].replace("Z","+00:00"))
        n+= a["outcome"]=="denied" and t>cut
print(n, "denied in the last hour", "(ALERT)" if n>5 else "")'
```

A follow-up code ticket is needed to emit a dedicated Kerberos-failure event.
