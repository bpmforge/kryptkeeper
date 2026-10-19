import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    ctFindings: vi.fn(),
    acknowledgeCTFinding: vi.fn(),
    markCTFindingKnownIssuer: vi.fn(),
  },
}));

import CTFindings from "./CTFindings";
import { api } from "../lib/api";

function finding(over: Record<string, unknown> = {}) {
  return {
    id: "crtsh:12345",
    log_id: "12345",
    domain: "example.com",
    common_name: "www.example.com",
    dns_names: ["www.example.com"],
    ca: "C=US, O=Example CA",
    serial: "0abc1234deadbeef",
    not_before: "2026-10-01T12:00:00Z",
    not_after: "2027-01-01T00:00:00Z",
    source: "crtsh",
    status: "open",
    created_at: "2026-10-02T00:00:00Z",
    ours: false,
    ...over,
  };
}

function list(...f: unknown[]) {
  return { data: { findings: f, total: f.length } } as never;
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <CTFindings />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.mocked(api.ctFindings).mockReset();
  vi.mocked(api.acknowledgeCTFinding).mockReset();
  vi.mocked(api.markCTFindingKnownIssuer).mockReset();
  vi.mocked(api.acknowledgeCTFinding).mockResolvedValue({ data: {} } as never);
  vi.mocked(api.markCTFindingKnownIssuer).mockResolvedValue({
    data: {},
  } as never);
});

describe("CTFindings", () => {
  it("lists findings with log id, CA, serial, not-before", async () => {
    vi.mocked(api.ctFindings).mockResolvedValue(list(finding()));
    renderPage();
    expect(await screen.findByText("C=US, O=Example CA")).toBeInTheDocument();
    expect(screen.getByText("0abc1234deadbeef")).toBeInTheDocument();
    expect(screen.getByText("12345")).toBeInTheDocument();
    expect(screen.getByText(/Oct 1, 2026/)).toBeInTheDocument();
    expect(screen.getByText("open", { selector: "span" })).toBeInTheDocument();
  });

  it("acknowledges in one click", async () => {
    const user = userEvent.setup();
    vi.mocked(api.ctFindings).mockResolvedValue(list(finding()));
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Acknowledge" }));
    await waitFor(() =>
      expect(api.acknowledgeCTFinding).toHaveBeenCalledTimes(1),
    );
    expect(api.acknowledgeCTFinding).toHaveBeenCalledWith("crtsh:12345");
    await waitFor(() =>
      expect(vi.mocked(api.ctFindings).mock.calls.length).toBeGreaterThan(1),
    );
  });

  it("marks known issuer in one click", async () => {
    const user = userEvent.setup();
    vi.mocked(api.ctFindings).mockResolvedValue(list(finding()));
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Known issuer" }));
    await waitFor(() =>
      expect(api.markCTFindingKnownIssuer).toHaveBeenCalledTimes(1),
    );
    expect(api.markCTFindingKnownIssuer).toHaveBeenCalledWith("crtsh:12345");
    await waitFor(() =>
      expect(vi.mocked(api.ctFindings).mock.calls.length).toBeGreaterThan(1),
    );
  });

  it("resolved rows have no action buttons", async () => {
    vi.mocked(api.ctFindings).mockResolvedValue(
      list(
        finding({
          status: "acknowledged",
          resolved_by: "alice",
          resolved_at: "2026-10-03T00:00:00Z",
        }),
      ),
    );
    renderPage();
    expect(await screen.findByText(/by alice/)).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Acknowledge" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Known issuer" }),
    ).not.toBeInTheDocument();
  });

  it("revoke link only when ours", async () => {
    const user = userEvent.setup();
    vi.mocked(api.ctFindings).mockResolvedValue(
      list(
        finding({ ours: true, revoke_url: "/certificates?q=0abc" }),
        finding({ id: "crtsh:2", log_id: "2", ours: false }),
      ),
    );
    renderPage();
    const links = await screen.findAllByRole("link", {
      name: /find in inventory to revoke/i,
    });
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveAttribute("href", "/certificates?q=0abc");
    await user.click(links[0]);
    expect(api.acknowledgeCTFinding).not.toHaveBeenCalled();
    expect(api.markCTFindingKnownIssuer).not.toHaveBeenCalled();
    expect("revokeCertificate" in api).toBe(false);
  });

  it("empty state", async () => {
    vi.mocked(api.ctFindings).mockResolvedValue(list());
    renderPage();
    expect(await screen.findByText(/No open findings/)).toBeInTheDocument();
    expect(screen.getByText(/KRYPTKEEPER_CT_DOMAINS/)).toBeInTheDocument();
  });

  it("error state with retry", async () => {
    const user = userEvent.setup();
    vi.mocked(api.ctFindings).mockRejectedValueOnce(new Error("boom"));
    vi.mocked(api.ctFindings).mockResolvedValue(list(finding()));
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Retry" }));
    expect(await screen.findByText("0abc1234deadbeef")).toBeInTheDocument();
  });
});
