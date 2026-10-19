import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: { preflightTarget: vi.fn(), targetPreflight: vi.fn() },
}));

import { TargetPreflightPanel } from "./TargetPreflightPanel";
import { api } from "../lib/api";

function renderPanel() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <TargetPreflightPanel targetId="target-1" />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.mocked(api.preflightTarget).mockReset();
  vi.mocked(api.targetPreflight).mockReset();
  vi.mocked(api.targetPreflight).mockRejectedValue(new Error("none yet"));
});

describe("TargetPreflightPanel (W34-15)", () => {
  it("renders a row per capability with the fix inline, including the exact requiretty line", async () => {
    vi.mocked(api.preflightTarget).mockResolvedValue({
      data: {
        checked_at: "2026-10-17T12:00:00Z",
        mode: "nopasswd",
        roles: ["scan", "install"],
        ok: false,
        privileged_all: false,
        rows: [
          { capability: "ssh_auth", status: "ok" },
          { capability: "requiretty", status: "fail", detail: "sudo wants a tty and the scan has none", fix: "Defaults:kkscan !requiretty" },
          { capability: "command:cat", status: "skipped", detail: "blocked by an earlier failure" },
        ],
      },
    } as never);
    const user = userEvent.setup();
    renderPanel();
    await user.click(screen.getByRole("button", { name: /test credential/i }));
    expect(await screen.findByText("SSH login")).toBeInTheDocument();
    expect(screen.getByText("Defaults:kkscan !requiretty")).toBeInTheDocument();
    expect(screen.getByText("command cat")).toBeInTheDocument();
    expect(screen.getByText("fail")).toBeInTheDocument();
    expect(screen.getByText("ok")).toBeInTheDocument();
    expect(api.preflightTarget).toHaveBeenCalledWith("target-1");
  });

  it("shows the last stored report before any run", async () => {
    vi.mocked(api.targetPreflight).mockResolvedValue({
      data: { checked_at: "2026-10-16T08:00:00Z", mode: "helper", ok: true, privileged_all: true, rows: [{ capability: "helper_sha", status: "ok" }] },
    } as never);
    renderPanel();
    expect(await screen.findByText("helper hash matches the pin")).toBeInTheDocument();
  });

  it("surfaces a request error", async () => {
    vi.mocked(api.preflightTarget).mockRejectedValue(new Error("target has no credential_ref"));
    const user = userEvent.setup();
    renderPanel();
    await user.click(screen.getByRole("button", { name: /test credential/i }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("no credential_ref"));
  });
});
