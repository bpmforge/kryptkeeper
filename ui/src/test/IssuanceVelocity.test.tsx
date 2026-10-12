import { act, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    issuanceVelocity: vi.fn(),
    cas: vi.fn(),
    templates: vi.fn(),
  },
}));

import IssuanceVelocity from "../pages/IssuanceVelocity";
import { api } from "../lib/api";

const IDENTIFIER_TITLE =
  "No display name on record — showing the raw identifier";

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <IssuanceVelocity />
    </QueryClientProvider>,
  );
}

const report = {
  generated_at: "2026-08-01T00:00:00Z",
  total_issued: 8,
  windows: { last_7d: 2, last_30d: 5, last_90d: 8 },
  daily_buckets: [{ date: "2026-08-01", count: 2 }],
  by_ca: { "ca-root": 5, unknown: 2, "ca-orphan": 1 },
  by_team: { "00000000-0000-0000-0000-000000000102": 5, unassigned: 3 },
  by_template: { "tpl-1": 5, none: 2, "tpl-orphan": 1 },
  anomaly_days: [],
};

const cas = [{ id: "ca-root", name: "Root CA", type: "root" }];
const templates = [{ id: "tpl-1", name: "server-tls", display_name: "" }];

beforeEach(() => {
  vi.mocked(api.issuanceVelocity).mockReset();
  vi.mocked(api.cas).mockReset();
  vi.mocked(api.templates).mockReset();
  vi.mocked(api.issuanceVelocity).mockResolvedValue({
    data: report,
  } as never);
  vi.mocked(api.cas).mockResolvedValue({
    data: { items: cas },
    meta: { total: cas.length },
  } as never);
  vi.mocked(api.templates).mockResolvedValue({
    data: { items: templates },
    meta: { total: templates.length },
  } as never);
});

describe("IssuanceVelocity (S-46)", () => {
  it("resolves By CA and By Template raw ids to their display names", async () => {
    renderPage();

    expect(await screen.findByText("Root CA")).toBeInTheDocument();
    expect(screen.getByText("server-tls")).toBeInTheDocument();
    expect(screen.queryByText("ca-root")).not.toBeInTheDocument();
    expect(screen.queryByText("tpl-1")).not.toBeInTheDocument();
  });

  it("marks an id-only entry as an identifier once the name lookup has settled, and leaves sentinels unmarked", async () => {
    renderPage();

    await screen.findByText("Root CA");

    // ca-orphan/tpl-orphan have no matching CA/template in the lookup --
    // real "no name exists" cases -- so they render as marked identifiers.
    const marked = screen.getAllByTitle(IDENTIFIER_TITLE);
    const markedText = marked.map((el) => el.textContent);
    expect(markedText).toEqual(
      expect.arrayContaining(["ca-orphan", "tpl-orphan"]),
    );
    // Team keys are NOT in the marked set — team_id IS the team's name in
    // this product's data model (see the By Team test below).
    expect(markedText).not.toContain("00000000-0000-0000-0000-000000000102");
    expect(screen.getAllByText("ID")).toHaveLength(marked.length);

    // Sentinel fallbacks ("unknown"/"unassigned"/"none") are words, not
    // identifiers -- they must never get the identifier marking.
    expect(screen.getByText("unknown")).not.toHaveAttribute("title");
    expect(screen.getByText("unassigned")).not.toHaveAttribute("title");
    expect(screen.getByText("none")).not.toHaveAttribute("title");
  });

  it("does not mark an id as identifier-only while its name lookup is still in flight", async () => {
    let resolveCas!: (value: unknown) => void;
    const pendingCas = new Promise((resolve) => {
      resolveCas = resolve;
    });
    vi.mocked(api.cas).mockReturnValue(pendingCas as never);

    renderPage();

    // Report has loaded (ca-orphan is on screen) but the CA lookup hasn't
    // settled yet -- it must render unmarked, not flash a false "no name".
    expect(await screen.findByText("ca-orphan")).not.toHaveAttribute("title");

    await act(async () => {
      resolveCas({ data: { items: cas }, meta: { total: cas.length } });
      await pendingCas;
    });

    await waitFor(() =>
      expect(screen.getByText("ca-orphan")).toHaveAttribute(
        "title",
        IDENTIFIER_TITLE,
      ),
    );
  });

  it("renders By Team keys as plain labels — team_id IS the name in this data model", async () => {
    renderPage();
    await screen.findByText("Root CA");

    // There is no teams registry or /teams API; team_id is a free-form
    // string ("platform", a principal id) that already IS the label. It
    // must render unmarked — the ID badge is reserved for keys that have
    // a name somewhere we failed to join.
    const teamKey = screen.getByText("00000000-0000-0000-0000-000000000102");
    expect(teamKey).not.toHaveAttribute("title");
  });
});
