# Kryptkeeper v0.20.0

This release is the ecosystem: the OpenAPI spec served by the hub, generated Go,
TypeScript and Python SDKs, Terraform provider tests and data sources, a plugin
registry page, signed webhooks, an ITSM framework with ServiceNow and Jira,
CMDB ownership sync, acting-channel audit on approvals, Slack and Teams
interactive approvals, and contributor documentation. It is feature group W32 of
the v1.0 release train. 26 of 33 tickets are `done`; 4 are `todo` and 3 are
`in_progress`. Decisions: D-182 to D-193.

## Upgrade notes (read first)

- **Migrations 000300, 000301 and 000302 run on upgrade (both engines):**
  `itsm` (connections, ticket events, ticket links), `itsm_approval_map`
  (`itsm_principal_map`), and a widened notification channel CHECK so the `itsm`
  channel is allowed.
- **Outgoing webhooks are signed.** Every delivery carries
  `X-Kryptkeeper-Timestamp`, `X-Kryptkeeper-Event-Id` and `X-Kryptkeeper-Signature`
  = `v1=HMAC-SHA256(ts.body)`. The event id is stable across retries. During
  secret rotation the previous secret also signs for 24 h (`v1=new,v1=old`).
  With no secret configured, deliveries are sent unsigned with one WARN per
  process. Receivers should reject stale (over 5 minutes) or unsigned deliveries
  (D-183).
- **Approval audit rows change shape.** `approval.*` rows now lead with `channel`
  (`ui`, `itsm` or `chatops`) and `external_id` detail keys; `action.*` rows
  append them. No schema or openapi change (D-186). Update any audit parser that
  keys on position.
- **New environment variables for ChatOps:** `SLACK_SIGNING_SECRET` (Slack
  interaction endpoint, 5-minute skew, replay guard) and `TEAMS_APP_ID` (Teams
  token audience; empty fails closed) (D-187, D-188). Teams tokens are validated
  with the standard library, RS256 only.
- **ITSM endpoints are admin-only** (`/api/v1/itsm/**`). Connection credentials
  come from the encrypted credential store; connectors use the egress client
  (D-184). Tickets are created once per event id across retries, backoff 5 min to
  6 h.
- **ITSM approvals are polled every 60 s**, not delivered by webhook (D-185).
  Reopening a ticket after approval does not undo it per the bridge rules in the
  decision.
- **ChatOps posting never blocks an approval.** A single worker with a 256-slot
  queue drops with a warning when full (D-189).
- **`GET /api/v1/openapi.yaml`** serves the embedded spec byte-identical, and the
  release workflow fails when the spec `info.version` differs from the tag
  (`scripts/check-spec-version.sh`, D-182). At the time of writing
  `docs/openapi.yaml` reads `0.12.0`, so release prep must bump it before tagging.

## New

- **Spec and SDKs:** the spec endpoint with build version (W32-01); Go,
  TypeScript and Python SDKs generated in the release workflow with pinned
  generators (W32-02); an SDK contract smoke against a live hub (W32-03). ITSM and
  ChatOps routes are in `openapi.yaml` (W32-24).
- **Terraform provider:** acceptance test against a compose hub in CI (W32-04);
  `ca` and `template` data sources, import support, docs and examples (W32-05).
  Provider publication and signing are not part of this release.
- **Plugins:** a registry index page listing verified delivery plugins (W32-07).
  There is no marketplace.
- **Webhooks and notifications:** HMAC-signed deliveries with rotation (W32-08);
  live verification harness for Slack, PagerDuty, Teams, webhook signature and
  CEF (W32-09, see Pending).
- **ITSM:** idempotent framework with ticket links and a backoff queue (W32-10);
  ServiceNow connector with incident or `change_request` ticket types and
  auto-resolve (W32-11, D-191); Jira connector (W32-14); approval through a ticket
  mapped to the real approve route with no bypass (W32-12, W32-26); daily CMDB
  ownership sync from ServiceNow CIs (W32-13); `event_classes` as `{class,
  ticket_type}` pairs and `POST /itsm/connections/{id}/test` (W32-25, D-190);
  producers for renewal-failed, approval-pending and expiry-no-owner (W32-28,
  D-192); the `itsm` channel is allowed in notification rules (W32-33). A
  documented signed-webhook recipe remains as a fallback (W32-16). The
  Integrations UI persists the webhook target and ITSM connection settings
  (W32-17).
- **ChatOps:** acting channel recorded on approval decisions (W32-15); Slack
  interactive approvals, posted to the owner team's channel with the outcome
  updated (W32-21, W32-22, W32-27); Teams adaptive-card approvals with token
  validation and user mapping (W32-23). Issuing or revoking from chat is out of
  scope.
- **Docs:** CONTRIBUTING corrected (Go 1.26, plugin guide, make gate, APP_MAP and
  COMPONENT_MAP, SLA and labels) (W32-19).

## Decisions

D-182 to D-193.

## Pending human runs (D-193: these ship as harnesses, not results)

- **W32-06 `in_progress`: F5 BIG-IP and Citrix ADC plugins are NOT validated.**
  `docs/release/LIVE_RESULTS_PLUGINS_F5_CITRIX_v0.20.md` is `PENDING-RUN`; no
  appliance or vendor VM has run them.
- **W32-18 `in_progress`:** ServiceNow dev instance and Jira Cloud are not run;
  needs human-provided accounts. A stand-in rerun found the missing `itsm` rule
  channel, fixed by W32-33.
- **W32-20 `in_progress`:** the contributor dry run on a clean VM is
  `PENDING-RUN` (`docs/release/CONTRIBUTOR_DRYRUN_v0.20.md`); it needs a
  non-maintainer operator.
- **W32-09:** the ticket is `done`, but per D-193 real Slack, PagerDuty and Teams
  legs need accounts and are not claimed as run against real services.

## Known gaps (board `todo`, not in this release)

- W32-29 Teams as a notification delivery channel (Teams approvals work; the
  notification channel does not).
- W32-30 `owner_team` notification routing and an ownerless queue, filed from
  W32-09. Note that W30-02 (v0.18.0) also lists owner_team routing; how the two
  relate is not verified here.
- W32-31 notification retries of 8 attempts with exponential backoff; the current
  contract is 3 linear attempts.
- W32-32 a failed manual renewal opens an ITSM ticket.
