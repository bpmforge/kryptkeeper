import { http, HttpResponse } from "msw";
import * as fx from "./fixtures";
import { cloudKeyInventory } from "./cloud-keys";

const base = "/api/v1";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ok = (data: any) => HttpResponse.json(data);

export const handlers = [
  // Auth
  http.get(`${base}/authz-check`, () => ok(fx.authzCheck)),
  http.get(`${base}/delivery-plugins`, () => ok(fx.deliveryPlugins)),
  // The shape here is the wire contract api.ts reads, not an approximation:
  // storeTokens() looks for access_token, so returning only {token} left the
  // bearer fallback unset and the very first authenticated request fell into
  // the refresh path.
  http.post(`${base}/auth/login`, () =>
    ok({
      access_token: "mock-access-token",
      refresh_token: "mock-refresh-token",
      role: "admin",
    }),
  ),
  // Without this handler the refresh request fell through to the real
  // network (onUnhandledRequest: "bypass"), failed, and the app correctly
  // concluded the session had died — which is why `npm run dev` could not
  // get past the login screen at all.
  http.post(`${base}/auth/refresh`, () =>
    ok({
      access_token: "mock-access-token-2",
      refresh_token: "mock-refresh-token-2",
    }),
  ),
  http.post(`${base}/auth/logout`, () => ok({})),

  // Dashboard
  http.get(`${base}/dashboard/summary`, () => ok(fx.dashboardSummary)),
  http.get(`${base}/dashboard/actions/history`, () => ok(fx.actionsHistory)),

  // Certificates
  http.get(`${base}/certificates`, () => ok(fx.certificates)),
  http.post(`${base}/certificates`, () =>
    ok({ data: fx.certificates.data[0] }),
  ),
  http.post(`${base}/certificates/import`, () =>
    ok({ data: fx.certificates.data[0] }),
  ),
  http.post(`${base}/certificates/:fp/renew`, () =>
    ok({ data: fx.certificates.data[0] }),
  ),
  http.post(`${base}/certificates/:fp/revoke`, () =>
    ok({ data: fx.certificates.data[0] }),
  ),
  http.patch(`${base}/certificates/:fp/ownership`, () =>
    ok({ data: fx.certificates.data[0] }),
  ),

  // CAs
  http.get(`${base}/cas`, () => ok(fx.cas)),
  http.post(`${base}/cas`, () => ok({ data: fx.cas.data[0] })),
  http.patch(`${base}/cas/:id`, () => ok({ data: fx.cas.data[0] })),
  http.post(`${base}/cas/:id/activate`, () => ok({ data: fx.cas.data[0] })),
  http.post(`${base}/cas/:id/suspend`, () => ok({ data: fx.cas.data[0] })),

  // Keys
  http.get(`${base}/keys`, () => ok(fx.keys)),
  http.post(`${base}/keys`, () => ok({ data: fx.keys.data[0] })),
  http.delete(`${base}/keys/:id`, () => ok({})),
  http.post(`${base}/keys/:id/rotate`, () => ok({ data: fx.keys.data[0] })),
  http.post(`${base}/keys/:id/export`, () =>
    ok({
      data: "-----BEGIN KRYPTKEEPER BACKUP KEY-----\nmock\n-----END KRYPTKEEPER BACKUP KEY-----",
    }),
  ),
  http.post(`${base}/keys/import`, () => ok({ data: fx.keys.data[0] })),

  // Templates
  http.get(`${base}/templates`, () => ok(fx.templates)),
  http.get(`${base}/templates/:id`, () => ok({ data: fx.templates.data[0] })),
  http.post(`${base}/templates`, () => ok({ data: fx.templates.data[0] })),
  http.put(`${base}/templates/:id`, () => ok({ data: fx.templates.data[0] })),
  http.delete(`${base}/templates/:id`, () => ok({})),

  // Discovery
  http.get(`${base}/discovery/summary`, () => ok(fx.discoverySummary)),
  http.get(`${base}/discovery/endpoints`, () => ok(fx.discoveryEndpoints)),
  http.get(`${base}/discovery/scan-jobs`, () => ok(fx.discoveryScanJobs)),
  http.post(`${base}/discovery/scans`, () =>
    ok({ data: { scan_job: fx.discoveryScanJobs.data.scan_jobs[0] } }),
  ),
  http.post(`${base}/discovery/scan-jobs/cancel`, () =>
    ok({ data: { scan_job_id: "job-1" } }),
  ),
  http.post(`${base}/discovery/scan-jobs/requeue`, () =>
    ok({ data: { scan_job_id: "job-1" } }),
  ),

  // Notifications
  http.get(`${base}/notifications/summary`, () => ok(fx.notificationsSummary)),
  http.get(`${base}/notifications/deliveries`, () =>
    ok(fx.notificationDeliveries),
  ),
  http.get(`${base}/notifications/rules`, () => ok(fx.notificationRules)),
  http.post(`${base}/notifications/rules`, () =>
    ok({ data: fx.notificationRules.data[0] }),
  ),
  http.put(`${base}/notifications/rules/:id`, () =>
    ok({ data: fx.notificationRules.data[0] }),
  ),
  http.delete(`${base}/notifications/rules/:id`, () => ok({})),
  http.post(`${base}/notifications/test-delivery`, () =>
    ok({ data: { delivery: fx.notificationDeliveries.data[0] } }),
  ),
  http.post(`${base}/notifications/deliveries/retry`, () =>
    ok({ data: { retry_job_id: "r-1" } }),
  ),
  http.post(`${base}/notifications/deliveries/ack`, () =>
    ok({ data: { delivery_id: "nd-1" } }),
  ),

  // Users
  http.get(`${base}/users`, () => ok(fx.users)),
  http.post(`${base}/users/invite`, () => ok({ data: fx.users.data[0] })),
  http.patch(`${base}/users/:id`, () => ok({ data: fx.users.data[0] })),
  http.delete(`${base}/users/:id`, () => ok({})),

  // Audit / History
  http.get(`${base}/audit`, () => ok(fx.auditList)),

  // Search
  http.get(`${base}/search`, ({ request }) => {
    const q = new URL(request.url).searchParams.get("q") ?? "";
    return ok(fx.searchResults(q));
  }),

  // Multi-tenancy is flag-gated off in demo mode, as on a default install.
  http.get(`${base}/tenants/context`, () =>
    ok({
      data: {
        enabled: false,
        super_admin: false,
        tenant: "default",
        scoped: false,
        tenants: [],
      },
    }),
  ),

  // Approvals
  http.get(`${base}/approvals`, ({ request }) => {
    const status = new URL(request.url).searchParams.get("status");
    return ok({
      data: status
        ? fx.approvals.data.filter((a) => a.status === status)
        : fx.approvals.data,
    });
  }),
  http.post(`${base}/approvals/:id/approve`, () =>
    ok({ data: fx.certificates.data[0] }),
  ),
  http.post(`${base}/approvals/:id/reject`, () => ok({ status: "rejected" })),

  // PQC migration
  http.get(`${base}/reports/pqc-migration`, () => ok(fx.pqcMigration)),
  http.get(`${base}/reports/pqc-countdown`, () => ok(fx.pqcCountdown)),
  http.get(`${base}/reports/pqc-waves`, () => ok(fx.pqcWaves)),
  http.post(`${base}/reports/pqc-waves/auto-derive`, () => ok(fx.pqcWaves)),
  http.post(`${base}/reports/pqc-waves`, () =>
    ok({ data: fx.pqcWaves.data[1] }),
  ),
  http.post(`${base}/reports/pqc-waves/:id/members`, () =>
    ok({ data: { status: "added" } }),
  ),
  http.post(`${base}/reports/pqc-waves/:id/accept`, () =>
    ok({ data: { status: "accepted" } }),
  ),
  http.delete(`${base}/reports/pqc-waves/:id`, () =>
    ok({ data: { status: "deleted" } }),
  ),

  // Reports
  http.get(`${base}/reports/crypto-posture`, () => ok(fx.cryptoPosture)),
  http.get(`${base}/reports/ca-health`, () => ok(fx.caHealth)),
  http.get(`${base}/reports/expiry-timeline`, () => ok(fx.expiryTimeline)),
  http.get(`${base}/reports/revocation-activity`, () =>
    ok(fx.revocationActivity),
  ),
  http.get(`${base}/reports/issuance-velocity`, () => ok(fx.issuanceVelocity)),
  http.get(`${base}/reports/change-audit`, () => ok(fx.changeAudit)),
  http.get(`${base}/reports/compliance-evidence`, () =>
    ok(fx.complianceEvidence),
  ),
  http.get(`${base}/reports/algorithm-sunset`, () => ok(fx.algorithmSunset)),

  // Cloud key inventory
  http.get(`${base}/inventory/keys`, () => ok(cloudKeyInventory)),

  // Agents
  http.get(`${base}/agents`, () => ok(fx.agents)),
];
