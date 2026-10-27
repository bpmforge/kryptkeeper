# Core API endpoints

Paths are relative to `/api/v1`. The full spec is [`docs/openapi.yaml`](../openapi.yaml).

```
GET    /meta                      — service health and version
POST   /auth/login                — login with email + password
POST   /auth/logout               — expire session cookie
GET    /authz-check               — verify current token + get role

GET    /cas                       — list CAs
POST   /cas                       — create root or intermediate CA
GET    /cas/{id}                  — get CA detail
PATCH  /cas/{id}                  — update CA metadata
POST   /cas/{id}/activate         — activate a suspended CA
POST   /cas/{id}/suspend          — suspend a CA

GET    /certificates              — list certificates (filter, paginate)
POST   /certificates              — issue a certificate
POST   /certificates/{fp}/renew   — renew a certificate
POST   /certificates/{fp}/revoke  — revoke a certificate
POST   /certificates/import       — import an external certificate

GET    /templates                 — list certificate templates
POST   /templates                 — create a template
PUT    /templates/{id}            — update a template
DELETE /templates/{id}            — delete a template

GET    /discovery/endpoints       — list discovered endpoints
POST   /discovery/scans           — queue a discovery scan
GET    /discovery/scan-jobs       — list scan jobs

GET    /notifications/summary     — notification health summary
GET    /notifications/deliveries  — delivery queue
GET    /notifications/rules       — list alert rules
POST   /notifications/rules       — create an alert rule
PUT    /notifications/rules/{id}  — update a rule
DELETE /notifications/rules/{id}  — delete a rule

GET    /users                     — list users
POST   /users/invite              — invite a user
PATCH  /users/{id}                — change role or status
DELETE /users/{id}                — deactivate a user

GET    /audit                     — audit log (filter, paginate)
GET    /search                    — cross-inventory search

PATCH  /certificates/{fp}/ownership — set owner email/team/service/labels
POST   /certificates/bulk-revoke  — bulk revoke (≤500 certs)
POST   /certificates/bulk-reissue — bulk re-issue (≤200 certs)

GET    /approvals                 — pending approval requests
POST   /approvals/{id}/approve    — approve a pending request
POST   /approvals/{id}/reject     — reject a pending request

POST   /keys/{id}/rotate          — rotate a CA key
POST   /keys/{id}/export          — passphrase-wrapped key backup
POST   /keys/import               — restore a key from backup

GET    /reports/ca-health         — CA health report
GET    /reports/expiry-timeline   — expiry calendar by CA/team/owner
GET    /reports/revocation-activity — revocations in a window
GET    /reports/issuance-velocity — certs/day by CA and requester
GET    /reports/change-audit      — full lifecycle history per cert
GET    /reports/compliance-evidence — SOC 2 / PCI DSS evidence pack
GET    /reports/algorithm-sunset  — post-2030 non-compliant certs
```
