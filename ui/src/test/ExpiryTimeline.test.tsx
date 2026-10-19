import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    expiryTimeline: vi.fn(),
    cas: vi.fn(),
  },
}));

import ExpiryTimeline from "../pages/ExpiryTimeline";
import { api } from "../lib/api";

const IDENTIFIER_TITLE =
  "No display name on record — showing the raw identifier";

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <ExpiryTimeline />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const report = {
  generated_at: "2026-08-01T00:00:00Z",
  total_certs: 8,
  buckets: [{ label: "0–7 days", days_from: 0, days_to: 7, count: 3 }],
  by_ca: { "ca-root": 5, unknown: 2, "ca-orphan": 1 },
  by_owner_team: { "platform-security": 6, unassigned: 2 },
};

const cas = [{ id: "ca-root", name: "Root CA", type: "root" }];

beforeEach(() => {
  vi.mocked(api.expiryTimeline).mockReset();
  vi.mocked(api.cas).mockReset();
  vi.mocked(api.expiryTimeline).mockResolvedValue({ data: report } as never);
  vi.mocked(api.cas).mockResolvedValue({
    data: { items: cas },
    meta: { total: cas.length },
  } as never);
});

describe("ExpiryTimeline (S-46)", () => {
  it("resolves By Certificate Authority raw ids to CA display names", async () => {
    renderPage();

    expect(await screen.findByText("Root CA")).toBeInTheDocument();
    expect(screen.queryByText("ca-root")).not.toBeInTheDocument();
  });

  it("marks an id-only CA as an identifier, leaves the unknown sentinel unmarked, and keeps Renew wired to the raw ca_id", async () => {
    renderPage();

    await screen.findByText("Root CA");

    expect(screen.getByText("ca-orphan")).toHaveAttribute(
      "title",
      IDENTIFIER_TITLE,
    );
    expect(screen.getByText("Unknown CA")).not.toHaveAttribute("title");

    // Root CA's row still renders a Renew button keyed on the raw ca_id
    // (renewalPath("ca-root")), not the resolved display name.
    const rootRow = screen.getByText("Root CA").closest("div.flex");
    expect(rootRow).not.toBeNull();
    expect(rootRow!.querySelector("button")).toHaveTextContent(/renew/i);

    // "unknown" is the no-CA sentinel -- there is nothing for ca_id= to
    // filter on, so its Renew button is disabled and explains why.
    const unknownRow = screen.getByText("Unknown CA").closest("div.flex")!;
    expect(unknownRow.querySelector("button")).toBeDisabled();
    expect(unknownRow.querySelector("span[title]")).toHaveAttribute(
      "title",
      expect.stringMatching(/no CA on record/i),
    );
  });

  it("does not touch By Owner Team, which already carries a free-text name", async () => {
    renderPage();

    await screen.findByText("Root CA");
    expect(screen.getByText("platform-security")).not.toHaveAttribute("title");
  });
});
