import { describe, expect, it } from "vitest";
import { navSections } from "../lib/nav";
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
      "/approvals",
      "/pending-actions",
      "/alerts",
      "/automation",
      "/targets/setup",
      "/targets/renewal-policy",
      "/delivery-plugins",
      "/agents",
      "/integrations",
      "/certificates",
      "/cas",
      "/keys",
      "/code-signing",
      "/spiffe",
      "/templates",
      "/discovery",
      "/search",
      "/reports/compliance-evidence",
      "/audit",
      "/reports/change-audit",
      "/history",
      "/crypto-posture",
      "/reports/pqc-migration",
      "/reports/algorithm-sunset",
      "/reports/expiry-timeline",
      "/reports/ca-health",
      "/reports/issuance-velocity",
      "/reports/revocation-activity",
      "/inventory/keys",
      "/users",
      "/tenants",
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
      "/audit",
      "/integrations",
      "/inventory/keys",
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
      "Estate",
      "Evidence",
      "Analysis",
      "Administration",
    ]);
  });
});
