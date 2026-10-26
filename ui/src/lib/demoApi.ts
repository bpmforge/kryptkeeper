import { fetchJSON } from "./api";

export const DEMO_LABEL = "demo=true";
const MARKER_KEY = "demo.seeded_at";

export type DemoStatus = { demo: boolean; seeded_at?: string };

export const getDemoStatus = () =>
  fetchJSON<{ data: DemoStatus }>("/demo/status").then((r) => r.data);

type DemoCert = {
  fingerprint_sha256: string;
  labels?: string[];
  origin?: string;
  revoked_at?: string | null;
};

// Same steps as `kryptkeeper demo reset`, through the same public API: revoke the
// certificates labelled demo=true, then clear the marker. CAs stay (revoking one is
// dual control), so a re-seed reuses them.
export async function resetDemoData(): Promise<{ revoked: number }> {
  let revoked = 0;
  let cursor = 0;
  for (;;) {
    const page = await fetchJSON<{
      data: DemoCert[];
      meta?: { next_cursor?: number | null };
    }>(`/certificates?limit=100&cursor=${cursor}`);
    for (const c of page.data) {
      if (c.revoked_at || !c.labels?.includes(DEMO_LABEL)) continue;
      const scope =
        c.origin && c.origin !== "internal" ? "?scope=inventory_only" : "";
      await fetchJSON(
        `/certificates/${encodeURIComponent(c.fingerprint_sha256)}/revoke${scope}`,
        {
          method: "POST",
          body: JSON.stringify({ reason_code: 5, reason_text: "demo reset" }),
        },
      );
      revoked++;
    }
    const next = page.meta?.next_cursor;
    if (next == null || page.data.length === 0) break;
    cursor = next;
  }
  await fetchJSON(`/config/${MARKER_KEY}`, { method: "DELETE" });
  return { revoked };
}
