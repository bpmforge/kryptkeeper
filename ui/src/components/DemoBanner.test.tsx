import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../lib/api")>();
  return { ...orig, fetchJSON: vi.fn(), api: { authzCheck: vi.fn() } };
});

import { DemoBanner } from "./DemoBanner";
import { api, fetchJSON } from "../lib/api";

const fetchMock = vi.mocked(fetchJSON);
const authzMock = vi.mocked(api.authzCheck);

type Cert = {
  fingerprint_sha256: string;
  labels?: string[];
  origin?: string;
  revoked_at?: string | null;
};

function hub(opts: { demo: boolean; certs?: Cert[] }) {
  fetchMock.mockImplementation(async (path: string, init?: RequestInit) => {
    if (path === "/demo/status")
      return { data: { demo: opts.demo, seeded_at: "2026-10-25T00:00:00Z" } };
    if (path.startsWith("/certificates?"))
      return { data: opts.certs ?? [], meta: { next_cursor: null } };
    void init;
    return undefined;
  });
}

function role(r: string) {
  authzMock.mockResolvedValue({
    service: "kryptkeeper",
    authenticated: true,
    principal: "p",
    role: r,
    scopes: [],
  });
}

function renderBanner() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <DemoBanner />
    </QueryClientProvider>,
  );
}

describe("DemoBanner", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    authzMock.mockReset();
  });

  it("renders nothing when the hub holds no demo data", async () => {
    hub({ demo: false });
    role("pki-admin");
    renderBanner();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/demo/status"));
    expect(screen.queryByTestId("demo-banner")).not.toBeInTheDocument();
  });

  it("offers reset to admins only", async () => {
    hub({ demo: true });
    role("viewer");
    renderBanner();
    expect(await screen.findByTestId("demo-banner")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Reset demo data" }),
    ).not.toBeInTheDocument();
  });

  it("asks for confirmation, then revokes only demo-labelled certificates and clears the marker", async () => {
    hub({
      demo: true,
      certs: [
        { fingerprint_sha256: "aa", labels: ["demo=true"], origin: "internal" },
        { fingerprint_sha256: "bb", labels: ["demo=true"], origin: "imported" },
        {
          fingerprint_sha256: "cc",
          labels: ["demo=true"],
          revoked_at: "2026-10-01T00:00:00Z",
        },
        { fingerprint_sha256: "dd", labels: [] },
      ],
    });
    role("pki-admin");
    const user = userEvent.setup();
    renderBanner();
    await user.click(
      await screen.findByRole("button", { name: "Reset demo data" }),
    );

    const dialog = await screen.findByRole("dialog", {
      name: "Reset demo data",
    });
    expect(
      fetchMock.mock.calls.some(([p]) => String(p).includes("/revoke")),
    ).toBe(false);
    await user.click(within(dialog).getByRole("button", { name: "Reset" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/config/demo.seeded_at", {
        method: "DELETE",
      }),
    );
    const paths = fetchMock.mock.calls.map(([p]) => String(p));
    expect(paths).toContain("/certificates/aa/revoke");
    expect(paths).toContain("/certificates/bb/revoke?scope=inventory_only");
    expect(paths.filter((p) => p.includes("/revoke"))).toHaveLength(2);
  });

  it("cancel leaves everything alone", async () => {
    hub({
      demo: true,
      certs: [{ fingerprint_sha256: "aa", labels: ["demo=true"] }],
    });
    role("pki-admin");
    const user = userEvent.setup();
    renderBanner();
    await user.click(
      await screen.findByRole("button", { name: "Reset demo data" }),
    );
    const dialog = await screen.findByRole("dialog", {
      name: "Reset demo data",
    });
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(
      fetchMock.mock.calls.some(([p]) => String(p).includes("/revoke")),
    ).toBe(false);
  });
});
