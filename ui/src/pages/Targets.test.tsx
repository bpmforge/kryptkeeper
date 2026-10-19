import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: { targets: vi.fn(), unblockTarget: vi.fn() },
}));

import Targets from "./Targets";
import { api } from "../lib/api";

const base = {
  discovery_mode: "network",
  install_mode: "ssh",
  renewal_method: "manual",
  tenant: "default",
  created_at: "",
  updated_at: "",
};

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Targets />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("Targets (W34-10)", () => {
  it("shows Blocked with the recipe and the coverage counts", async () => {
    vi.mocked(api.targets).mockResolvedValue({
      data: [
        {
          ...base,
          id: "t1",
          name: "web-1",
          host: "10.0.0.5",
          last_scanned_at: "2026-10-17T10:00:00Z",
          last_privilege_mode: "none",
          unreadable_count: 3,
          renewal_privilege_required: true,
          blocked: {
            kind: "privilege",
            reason: "renewal needs root on this host",
            fix: "Add a privileged credential. Or make the files writable: chown svc /etc/ssl/a.pem",
          },
        },
        { ...base, id: "t2", name: "web-2", host: "10.0.0.6", last_scanned_at: "2026-10-17T10:00:00Z", last_privilege_mode: "helper", unreadable_count: 0, credential_privileged: true },
      ],
    } as never);
    renderPage();
    const row = await screen.findByTestId("target-t1");
    expect(row).toHaveTextContent("Blocked");
    expect(row).toHaveTextContent("renewal needs root on this host; add a privileged credential or fix ownership");
    expect(row).toHaveTextContent("chown svc /etc/ssl/a.pem");
    expect(row).toHaveTextContent("Scan ran unprivileged; 3 paths unreadable");
    expect(screen.getByRole("link", { name: "Open Target Setup" })).toBeInTheDocument();
    const ok = screen.getByTestId("target-t2");
    expect(ok).not.toHaveTextContent("Blocked");
    expect(ok).toHaveTextContent("Privileged credential");
    expect(ok).toHaveTextContent("Scan ran with helper; every path readable");
  });

  it("unblocks a rollback block", async () => {
    vi.mocked(api.targets).mockResolvedValue({
      data: [{ ...base, id: "t3", name: "db", host: "h", blocked: { kind: "rollback", reason: "renewal rollback failed", fix: "Check the host." } }],
    } as never);
    vi.mocked(api.unblockTarget).mockResolvedValue(undefined as never);
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Unblock" }));
    await waitFor(() => expect(api.unblockTarget).toHaveBeenCalledWith("t3"));
  });
});
