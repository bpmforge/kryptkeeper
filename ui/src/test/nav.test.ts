import { describe, expect, it } from "vitest";
import {
  filterNavSections,
  isRequesterOnly,
  navSections,
  requesterNavSections,
} from "../lib/nav";
// ?raw keeps this in Vite's world — no node types needed just to read a file.
import appSource from "../App.tsx?raw";

// The nav was regrouped from 4 groups (max 11 items) to 6 grouped by job.
// A regroup that quietly loses a page still renders fine, so these pin the
// things a reshuffle can break without anyone noticing.

const allItems = navSections.flatMap((s) => s.items);

describe("navigation", () => {
  it("still reaches every page it did before the regroup", () => {
    // The full route set, recorded at the time of the regroup. Adding a
    // page means adding it here deliberately; losing one fails.
    const expected = [
      "/",
      "/inbox",
      "/alerts",
      "/ct-findings",
      "/automation",
      "/targets",
      "/targets/setup",
      "/targets/renewal-policy",
      "/renewal/rollout-groups",
      "/delivery-plugins",
      "/agents",
      "/nhi",
      "/integrations",
      "/certificates",
      "/cas",
      "/ceremonies",
      "/keys",
      "/code-signing",
      "/spiffe",
      "/ssh-certificates",
      "/templates",
      "/discovery",
      "/search",
      "/reports/compliance-evidence",
      "/reports/key-custody",
      "/audit",
      "/reports/change-audit",
      "/history",
      "/crypto-posture",
      "/reports/pqc-migration",
      "/reports/algorithm-sunset",
      "/blast-radius",
      "/reports/expiry-timeline",
      "/reports/anomalies",
      "/reports/ca-health",
      "/reports/slo",
      "/reports/issuance-velocity",
      "/reports/revocation-activity",
      "/inventory/keys",
      "/inventory-sources",
      "/acme",
      "/enrollment",
      "/migration",
      "/users",
      "/access-review",
      "/tenants",
      "/policies",
      "/roles",
      "/settings",
    ].sort();
    expect(allItems.map((i) => i.to).sort()).toEqual(expected);
  });

  it("lists no route twice", () => {
    const routes = allItems.map((i) => i.to);
    expect(new Set(routes).size).toBe(routes.length);
  });

  it("points only at routes the app actually registers", () => {
    const app = appSource;
    const registered = new Set(
      [...app.matchAll(/<Route\s+path="([^"]+)"/g)].map((m) => m[1]),
    );
    // index route renders at "/"
    if (app.includes("<Route index")) registered.add("/");
    const missing = allItems
      .map((i) => i.to)
      .filter((to) => !registered.has(to));
    expect(missing, `nav links with no route: ${missing.join(", ")}`).toEqual(
      [],
    );
  });

  it("keeps the permission gates the regroup moved", () => {
    const gated = allItems
      .filter((i) => i.permission)
      .map((i) => i.to)
      .sort();
    expect(gated).toEqual([
      "/access-review",
      "/acme",
      "/audit",
      "/ceremonies",
      "/ct-findings",
      "/enrollment",
      "/integrations",
      "/inventory/keys",
      "/policies",
      "/renewal/rollout-groups",
      "/reports/key-custody",
      "/roles",
      "/users",
    ]);
  });

  it("keeps every group small enough to scan", () => {
    // The old "System" group held 11 unrelated items; that is the failure
    // this guards against, not group count.
    for (const section of navSections) {
      expect(
        section.items.length,
        `${section.label} has ${section.items.length} items`,
      ).toBeLessThanOrEqual(8);
    }
  });

  it("names groups by the job, not by the object type", () => {
    expect(navSections.map((s) => s.label)).toEqual([
      "Today",
      "Automation",
      "Connect",
      "Estate",
      "Evidence",
      "Analysis",
      "Administration",
    ]);
  });

  describe("Tenants flag", () => {
    const paths = (flags?: { multiTenancy?: boolean }) =>
      filterNavSections(navSections, "pki-admin", [], flags).flatMap((s) =>
        s.items.map((i) => i.to),
      );

    it("hides /tenants by default", () => {
      expect(paths()).not.toContain("/tenants");
      expect(paths({ multiTenancy: false })).not.toContain("/tenants");
    });

    it("shows /tenants when multiTenancy is true", () => {
      expect(paths({ multiTenancy: true })).toContain("/tenants");
    });

    it("flag does not affect other items", () => {
      expect(paths({ multiTenancy: true }).length).toBe(paths().length + 1);
    });
  });
  describe("requester role (W33-22)", () => {
    const paths = (role?: string, scopes: string[] = []) =>
      filterNavSections(navSections, role, scopes, { multiTenancy: true }).flatMap(
        (s) => s.items.map((i) => i.to),
      );

    it("sees exactly Request and My Requests", () => {
      expect(paths("requester")).toEqual(["/certificates/issue", "/my-requests"]);
    });

    it("stays at two items even with broad scopes", () => {
      expect(paths("requester", ["*", "ops:write"])).toEqual([
        "/certificates/issue",
        "/my-requests",
      ]);
    });

    it("only matches the exact role", () => {
      expect(isRequesterOnly("requester")).toBe(true);
      expect(isRequesterOnly(" requester ")).toBe(true);
      expect(isRequesterOnly("pki-operator")).toBe(false);
      expect(isRequesterOnly(undefined)).toBe(false);
    });

    it("leaves pki-admin with the full list", () => {
      expect(paths("pki-admin")).toContain("/users");
      expect(paths("pki-admin")).not.toContain("/my-requests");
    });

    it("points only at registered routes", () => {
      const registered = new Set(
        [...appSource.matchAll(/<Route\s+path="([^"]+)"/g)].map((m) => m[1]),
      );
      for (const item of requesterNavSections.flatMap((s) => s.items)) {
        expect(registered.has(item.to), item.to).toBe(true);
      }
    });
  });
});
