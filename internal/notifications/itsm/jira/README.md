# Jira Cloud connector (W32-14)

Implements `itsm.Connector` and `itsm.ApprovalConnector` on Jira Cloud REST v3. Register kind `jira`;
base URL is `https://<site>.atlassian.net` (plain http only for loopback tests).

## Credential-store JSON
```json
{"email":"svc@example.com","api_token":"<Atlassian API token>","project_key":"KK",
 "issue_type":"Task","approved_status":"Approved","rejected_status":"Rejected","done_status":""}
```
`project_key` and `email`/`api_token` are required; `issue_type` defaults to `Task`; `rejected_status` and
`done_status` (a transition name) are optional. Without `done_status`, the first transition into a status
category of `done` is used. Status names are per project and may be localised: enter them exactly as
shown in Jira (matching is case-insensitive).

## Required Jira permissions (project level, for the API-token user)
Browse Projects, Create Issues, Transition Issues, Add Comments.

## Behaviour
- Create: `POST /rest/api/3/issue`, summary `Certificate renewal failed: <CN>`, ADF description (CN, Serial,
  Expires, Risk, Link), labels `kk-<event id>` (chars outside `[A-Za-z0-9_-]` become `_`) and `kryptkeeper`.
- Find: `GET /rest/api/3/search/jql` on that label, so a created-but-unacknowledged issue is adopted, not duplicated.
- Resolve: ADF comment, then the done transition (looked up per workflow, never hard-coded). Already-done is success.
- Approval: issue status name equals `approved_status` -> approved; equals `rejected_status` -> rejected; else pending.
  The approver is the `accountId` of the latest changelog status change to that status; if Jira gives none the
  call fails permanently (`approver unknown`) so the bridge never approves anonymously.
- Errors: network, 408, 429, 5xx -> `itsm.ErrTemporary`; other 4xx -> `itsm.ErrPermanent` (Jira `errorMessages`, max 200 bytes). Tokens never appear in errors.

## Live check (status: PENDING-RUN, stub-only so far; real Jira Cloud proof is W32-18)
1. Create an API token, store the credential JSON above, add a connection `kind=jira`.
2. Force a failed renewal 5 times with one event id; confirm exactly one issue.
3. Move the issue to the approved status; confirm the approval bridge sees it within 2 polls.
4. Complete the renewal; confirm the issue reaches a done status within 5 minutes.

Unit coverage: `go test ./internal/notifications/itsm/jira/...`
