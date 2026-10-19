# Security claims

Scope: calls to user-supplied URLs, the hub's own client-IP resolution, and its inbound rate limits.
Each claim names the Go test that proves it; if the test fails, the claim is withdrawn.
Knobs are environment variables read at start-up; changing one needs a restart.

## Outbound requests (SSRF guard)

| Claim | Knob (default) | Tested limit | Proving test |
|---|---|---|---|
| Link-local (cloud metadata 169.254.169.254), unspecified and multicast addresses are always refused. RFC1918, ULA and CGNAT 100.64/10 follow the policy. Loopback is allowed only where a caller's `Policy` sets `AllowLoopback`; the env knob does not change that. | `KRYPTKEEPER_EGRESS_DENY_PRIVATE` (unset: private space allowed; `true`: refused) | the address table in the test | `internal/egress.TestCheckIPTable` |
| The address actually dialled is checked at connect time, so a literal loopback or metadata address is refused when the policy does not allow it. (Resolution of a hostname to a forbidden IP goes through the same dial check, but no test resolves a hostname, so that case is not claimed as tested.) | none | loopback blocked and allowed by policy; 169.254.169.254 blocked | `internal/egress.TestClientDialGuard` |
| `KRYPTKEEPER_EGRESS_DENY_PRIVATE=true` switches private space off. | `KRYPTKEEPER_EGRESS_DENY_PRIVATE` | set and unset | `internal/egress.TestPolicyFromEnv` |
| Redirects are refused at `MaxRedirects=0`, blocked when they land on a forbidden address, and refused across hosts when `SameHostRedirectsOnly` is set. | none (per-caller `Policy`) | metadata-redirect, cross-host, none | `internal/egress.TestRedirects` |
| Redirect chains are capped at `MaxRedirects`. | none (per-caller `Policy`) | hop cap in the test | `internal/egress.TestRedirectHopLimit` |
| Proxy environment variables are ignored. | none | `HTTP_PROXY` and `http_proxy` set | `internal/egress.TestClientIgnoresProxyEnv` |
| Raw `net/http` clients outside the reviewed list cannot be added unnoticed. | none | scan of `internal/` and `cmd/` | `internal/egress.TestNoRawHTTPOutsideAllowlist` |

## Client IP and trusted proxies

| Claim | Knob (default) | Tested limit | Proving test |
|---|---|---|---|
| `X-Forwarded-For` is honoured only from peers inside the CIDR list. The default is an empty list, so it is never trusted. | `APP_TRUSTED_PROXY_CIDRS` (comma-separated CIDRs; empty) | table cases in each test | `internal/clientip.TestResolve`, `internal/clientip.TestPeerTrusted`, `internal/clientip.TestFromEnv` |
| A spoofed header from an untrusted peer cannot change the limiter key. | `APP_TRUSTED_PROXY_CIDRS` | 31 requests with 31 different `X-Forwarded-For` values share one bucket | `internal/ratelimit.TestClientIP_UntrustedPeerCannotSpoofXForwardedFor`, `internal/ratelimit.TestMiddleware_TrustedProxyIgnoresSpoofedLeftmostXFF`, `internal/ratelimit.TestProtocolLimiter_SpoofedXFFFromUntrustedPeerSharesOneBucket` |

## Rate limits

The window is one minute for every row.

| Claim | Knob (default) | Tested limit | Proving test |
|---|---|---|---|
| ACME and EST protocol requests that carry a credential the hub knows (ACME account, ACME EAB key id, EST Basic user) are limited per credential. | `RATELIMIT_PROTOCOL_PER_CREDENTIAL` (600) | 600 pass, the 601st gets 429; the same IP's unauthenticated bucket is untouched | `internal/ratelimit.TestProtocolLimiter_CredentialLimit600` |
| 1,000 credentials behind one IP, 10 requests each per minute, see no 429. | `RATELIMIT_PROTOCOL_PER_CREDENTIAL` | 10,000 requests, 0 throttled | `internal/ratelimit.TestProtocolLimiter_ThousandCredentialsBehindOneIPNever429` |
| Unauthenticated protocol requests are limited per client IP; the 31st in a minute gets 429 with `Retry-After`. | `RATELIMIT_UNAUTH_PER_IP` (30) | 30 pass, the 31st gets 429; another IP is unaffected | `internal/ratelimit.TestProtocolLimiter_UnauthenticatedIPLimitIs30` |
| An invented credential id does not escape the per-IP limit. | `RATELIMIT_UNAUTH_PER_IP` | 31 requests with 31 invented ids, the 31st gets 429 | `internal/ratelimit.TestProtocolLimiter_InventedCredentialFallsBackToIP` |
| Invalid, zero or negative knob values fall back to the defaults. | both `RATELIMIT_*` knobs | the cases in the test | `internal/bootstrap.TestProtocolRateLimitsFromEnv` |
| A limiter key idle for 10 minutes does not survive the next new-key insertion. | none (constant `IdleEvictAfter`) | 1,000 keys, one new key after 10 minutes, 1 key left | `internal/ratelimit.TestProtocolLimiter_EvictsIdleKeysAfterTenMinutes` |
| Throttle audit rows (`ratelimit.throttled`) are sampled to 1 per key per minute. | none | 100 denied requests give 1 callback; one more after 61 s | `internal/ratelimit.TestProtocolLimiter_ThrottleCallbackSampledPerKeyPerMinute` |
| A renewal storm of 2,000 accounts (3 requests each, spread over an hour, one IP) is not throttled. | none | 6,000 requests, 0 throttled | `internal/ratelimit.TestRenewalStormSeesNoThrottle` |
| Login attempts are limited per client IP. | none (10 per minute, fixed) | 10 pass, then 429 | `internal/bootstrap.TestAuthHandlerRateLimitsLoginAttempts` |
| Pending-action proposals and `/api/v1/reports/*` are limited per principal. | `API_RATE_LIMIT_PENDING_ACTIONS_PER_MIN` (20), `API_RATE_LIMIT_REPORTS_PER_MIN` (60) | per-principal cases in each test | `internal/bootstrap.TestWithAPIRateLimiting_PendingActionsWriteIsLimitedPerPrincipal`, `internal/bootstrap.TestWithAPIRateLimiting_ReportsPathIsLimitedPerPrincipal` |
| OCSP (200/min), CRL, SCEP, CMP, WSTEP and XCEP (30/min) stay per client IP and are not configurable. | none | not tested here | none: constants in `cmd/kryptkeeper/main.go`, so this is a description, not a tested claim |

A credential is keyed from the request before its signature or password is checked. A caller who knows an existing account id or EST user name can therefore spend that credential's per-minute budget. The budget is a throttle, not an authentication result.

## What is not claimed

- The egress guard covers user-supplied URL calls only. Discovery scanners, cloud and vendor API clients, operator-configured infrastructure clients and issuer connectors are internal by design. They are listed with reasons in [`internal/egress/lint_test.go`](../../internal/egress/lint_test.go) (`rawHTTPAllowlist`); rows marked FOLLOW-UP there take operator-typed URLs and are not yet guarded.
- SCEP and EST client-certificate requests are limited per client IP, not per credential.
- No WAF, and no per-tenant egress allow-list.
- Limits are per process; a multi-replica hub multiplies them by the replica count.

## Verifying these claims

```sh
go test ./internal/egress/... ./internal/clientip/... ./internal/ratelimit/... \
  -run 'TestCheckIPTable|TestClientDialGuard|TestPolicyFromEnv|TestRedirects|TestRedirectHopLimit|TestClientIgnoresProxyEnv|TestNoRawHTTPOutsideAllowlist|TestResolve|TestPeerTrusted|TestFromEnv|TestClientIP_|TestMiddleware_|TestProtocolLimiter_|TestRenewalStormSeesNoThrottle' -v
go test ./internal/bootstrap/ -run 'TestAuthHandlerRateLimitsLoginAttempts|TestWithAPIRateLimiting_|TestProtocolRateLimitsFromEnv' -v
```
