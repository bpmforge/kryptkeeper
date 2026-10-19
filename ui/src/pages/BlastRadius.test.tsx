import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({ api: { blastRadius: vi.fn() } }));

import BlastRadius from "./BlastRadius";
import { api } from "../lib/api";

function wrap() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <BlastRadius />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function result(
  over: Record<string, unknown> = {},
  kinds: Record<string, string[]> = {
    cert: ["cert-1", "cert-2"],
    service: ["svc-a", "svc-b", "svc-c"],
  },
) {
  return {
    data: {
      action: "retire_ca",
      target: "ca-1",
      total_affected: 5,
      severity: "high",
      affected_by_kind: kinds,
      graph_size: "9 nodes",
      ...over,
    },
  } as unknown as never;
}

async function simulate(
  user: ReturnType<typeof userEvent.setup>,
  action: string,
  target: string,
) {
  await user.selectOptions(screen.getByLabelText("Action"), action);
  await user.type(screen.getByLabelText("Target"), target);
  await user.click(screen.getByRole("button", { name: "Simulate" }));
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("BlastRadius page (W31-17)", () => {
  it("simulate submits action and target and lists impacted certs and services", async () => {
    const services = Array.from({ length: 25 }, (_, i) => `svc-${i + 1}`);
    vi.mocked(api.blastRadius).mockResolvedValue(
      result({ total_affected: 27 }, { cert: ["cert-1", "cert-2"], service: services }),
    );
    const user = userEvent.setup();
    wrap();
    await simulate(user, "retire_ca", "ca-1");
    expect(api.blastRadius).toHaveBeenCalledWith("retire_ca", "ca-1");
    expect(
      await screen.findByText("2 certificates, 25 services affected"),
    ).toBeInTheDocument();
    expect(screen.getAllByText("high").length).toBeGreaterThan(0);
    const region = await screen.findByRole("region", {
      name: "Impacted items (text)",
    });
    expect(within(region).getByText("cert-1")).toBeInTheDocument();
    expect(within(region).getByText("cert-2")).toBeInTheDocument();
    for (const s of services) {
      expect(within(region).getByText(s)).toBeInTheDocument();
    }
  });

  it.each([
    ["revoke", "fp-1"],
    ["retire_ca", "ca-1"],
    ["deprecate_algorithm", "RSA-2048"],
  ])("supports all three actions: %s", async (action, target) => {
    vi.mocked(api.blastRadius).mockResolvedValue(result({ action, target }));
    const user = userEvent.setup();
    wrap();
    await simulate(user, action, target);
    expect(api.blastRadius).toHaveBeenCalledWith(action, target);
    expect(
      await screen.findByRole("region", { name: "Impacted items (text)" }),
    ).toBeInTheDocument();
  });

  it("graph has an accessible name and a text-list equivalent", async () => {
    vi.mocked(api.blastRadius).mockResolvedValue(result());
    const user = userEvent.setup();
    wrap();
    await simulate(user, "retire_ca", "ca-1");
    expect(
      await screen.findByRole("img", {
        name: /Dependency graph for retire_ca ca-1: 2 certificates, 3 services/,
      }),
    ).toBeInTheDocument();
    const region = screen.getByRole("region", { name: "Impacted items (text)" });
    for (const id of ["cert-1", "cert-2", "svc-a", "svc-b", "svc-c"]) {
      expect(within(region).getByText(id)).toBeInTheDocument();
    }
  });

  it("empty target does not call the API", async () => {
    const user = userEvent.setup();
    wrap();
    await user.click(screen.getByRole("button", { name: "Simulate" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Enter a target to simulate.",
    );
    expect(api.blastRadius).not.toHaveBeenCalled();
  });

  it("shows 404 and 403 messages from the shared component, never an empty list", async () => {
    const user = userEvent.setup();
    vi.mocked(api.blastRadius).mockRejectedValue(
      Object.assign(new Error("x"), { status: 404 }),
    );
    const { unmount } = wrap();
    await simulate(user, "revoke", "fp-9");
    expect(
      await screen.findByText("Blast radius target not found"),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("region", { name: "Impacted items (text)" }),
    ).toBeNull();
    unmount();

    vi.mocked(api.blastRadius).mockRejectedValue(
      Object.assign(new Error("x"), { status: 403 }),
    );
    wrap();
    await simulate(user, "revoke", "fp-9");
    expect(
      await screen.findByText("Blast radius not permitted"),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("region", { name: "Impacted items (text)" }),
    ).toBeNull();
  });

  it("shows edge coverage when present and nothing when absent", async () => {
    vi.mocked(api.blastRadius).mockResolvedValue(
      result({
        edge_coverage: {
          certs_total: 4,
          certs_with_ca_edge: 4,
          certs_with_service_edge: 2,
          basis: "served-by endpoints",
        },
      }),
    );
    const user = userEvent.setup();
    const { unmount } = wrap();
    await simulate(user, "retire_ca", "ca-1");
    expect(
      await screen.findByText(
        /Edge coverage: 2 of 4 certificates have a served-service edge \(served-by endpoints\)\. Impact is only as complete as these edges\./,
      ),
    ).toBeInTheDocument();
    unmount();

    vi.mocked(api.blastRadius).mockResolvedValue(result());
    wrap();
    await simulate(user, "retire_ca", "ca-2");
    await screen.findByRole("region", { name: "Impacted items (text)" });
    expect(screen.queryByText(/Edge coverage/)).toBeNull();
  });

  it("form is keyboard operable", async () => {
    vi.mocked(api.blastRadius).mockResolvedValue(result());
    const user = userEvent.setup();
    wrap();
    await user.tab();
    expect(screen.getByLabelText("Action")).toHaveFocus();
    await user.tab();
    expect(screen.getByLabelText("Target")).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "Simulate" })).toHaveFocus();
    await user.click(screen.getByLabelText("Target"));
    await user.keyboard("fp-1{Enter}");
    expect(api.blastRadius).toHaveBeenCalledWith("revoke", "fp-1");
  });
});
