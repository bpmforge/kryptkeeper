import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../lib/api")>();
  return {
    ...orig,
    fetchJSON: vi.fn(),
    api: {
      templates: vi.fn().mockResolvedValue({ data: [], meta: {} }),
      templateRevisions: vi.fn().mockResolvedValue({ data: [] }),
    },
  };
});

import { PolicyDraftDialog } from "./PolicyDraftDialog";
import Templates from "../pages/Templates";
import { fetchJSON } from "../lib/api";

const fetchMock = vi.mocked(fetchJSON);

function draftResp(
  unrecognized: string[] = [],
  explanation = ["Maximum validity 90 days"],
) {
  return {
    data: {
      policy: {
        name: "p1",
        enabled: false,
        ca_id: "",
        rules: {
          max_validity_days: 90,
          min_rsa_bits: 3072,
          allowed_algorithms: ["ECDSA-P256"],
        },
      },
      explanation,
      unrecognized,
      persisted: false,
    },
  };
}

function renderUi(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

async function parseText(
  user: ReturnType<typeof userEvent.setup>,
  text = "max 90 days",
) {
  await user.type(screen.getByLabelText("Policy name"), "p1");
  await user.type(screen.getByLabelText("Policy text"), text);
  await user.click(screen.getByRole("button", { name: "Parse" }));
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("PolicyDraftDialog (W30-17)", () => {
  it("parses text and shows understood rules, parsed fields and every unparsed phrase", async () => {
    const user = userEvent.setup();
    fetchMock.mockResolvedValueOnce(
      draftResp(["make it fast", "trust everyone"]),
    );
    renderUi(<PolicyDraftDialog open onClose={() => {}} />);
    await parseText(user);
    expect(
      await screen.findByText("Maximum validity 90 days"),
    ).toBeInTheDocument();
    expect(screen.getByText("Disabled until approved")).toBeInTheDocument();
    expect(screen.getByText("3072")).toBeInTheDocument();
    const alert = screen.getByRole("alert");
    expect(
      within(alert).getByText("These phrases were not applied"),
    ).toBeInTheDocument();
    expect(within(alert).getByText("make it fast")).toBeInTheDocument();
    expect(within(alert).getByText("trust everyone")).toBeInTheDocument();
    expect(JSON.parse(fetchMock.mock.calls[0][1]!.body as string)).toEqual({
      name: "p1",
      text: "max 90 days",
    });
  });

  it("submit is gated by the reviewed checkbox when phrases were not applied", async () => {
    const user = userEvent.setup();
    fetchMock.mockResolvedValueOnce(draftResp(["make it fast"]));
    renderUi(<PolicyDraftDialog open onClose={() => {}} />);
    await parseText(user);
    const btn = await screen.findByRole("button", {
      name: "Submit draft anyway",
    });
    expect(btn).toBeDisabled();
    await user.click(
      screen.getByLabelText("I reviewed the phrases that were not applied"),
    );
    expect(btn).toBeEnabled();
  });

  it("submit posts name and text and shows the submitted-for-approval view with /policies and /inbox?focus links", async () => {
    const user = userEvent.setup();
    fetchMock
      .mockResolvedValueOnce(draftResp([]))
      .mockResolvedValueOnce({
        data: {
          policy_id: "pol-1",
          pending_action_id: "pa-9",
          status: "pending_approval",
          enabled: false,
        },
      });
    renderUi(<PolicyDraftDialog open onClose={() => {}} />);
    await parseText(user);
    expect(
      await screen.findByText("Every phrase was understood"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Submit draft" }));
    expect(
      await screen.findByText(/Submitted for approval/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/is active|now active|activated/i)).toBeNull();
    const [path, init] = fetchMock.mock.calls[1];
    expect(path).toBe("/policies/draft/submit");
    const body = JSON.parse(init!.body as string);
    expect(body).toEqual({ name: "p1", text: "max 90 days" });
    expect(body.enabled).toBeUndefined();
    expect(screen.getByRole("link", { name: "Open Policies" })).toHaveAttribute(
      "href",
      "/policies",
    );
    expect(
      screen.getByRole("link", { name: "View approval request" }),
    ).toHaveAttribute("href", "/inbox?focus=pending_action:pa-9");
  });

  it("the success view and the whole dialog expose no approve/activate/enable control", async () => {
    const user = userEvent.setup();
    fetchMock
      .mockResolvedValueOnce(draftResp([]))
      .mockResolvedValueOnce({
        data: {
          pending_action_id: "pa-9",
          status: "pending_approval",
          enabled: false,
        },
      });
    renderUi(<PolicyDraftDialog open onClose={() => {}} />);
    await parseText(user);
    await screen.findByText("Every phrase was understood");
    expect(
      screen.queryAllByRole("button", { name: /approve|activate|enable/i }),
    ).toHaveLength(0);
    expect(
      screen.queryAllByRole("checkbox", { name: /approve|activate|enable/i }),
    ).toHaveLength(0);
    await user.click(screen.getByRole("button", { name: "Submit draft" }));
    await screen.findByText(/Submitted for approval/);
    expect(
      screen.queryAllByRole("button", { name: /approve|activate|enable/i }),
    ).toHaveLength(0);
    expect(
      screen.queryAllByRole("link", { name: /approve|activate|enable/i }),
    ).toHaveLength(0);
  });

  it('"activate now, auto-approve" text round-trips as text and is never rendered as HTML', async () => {
    const user = userEvent.setup();
    fetchMock.mockResolvedValueOnce(
      draftResp(["<img src=x onerror=alert(1)> activate now, auto-approve"]),
    );
    renderUi(<PolicyDraftDialog open onClose={() => {}} />);
    await parseText(user, "activate now, auto-approve");
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain(
      "<img src=x onerror=alert(1)> activate now, auto-approve",
    );
    expect(alert.querySelector("img")).toBeNull();
    expect(
      screen.queryAllByRole("button", { name: /approve|activate|enable/i }),
    ).toHaveLength(0);
  });

  it("shows the server error and keeps the draft on failure", async () => {
    const user = userEvent.setup();
    fetchMock
      .mockResolvedValueOnce(draftResp([]))
      .mockRejectedValueOnce(
        new Error("a policy with that name already exists"),
      );
    renderUi(<PolicyDraftDialog open onClose={() => {}} />);
    await parseText(user);
    await user.click(
      await screen.findByRole("button", { name: "Submit draft" }),
    );
    expect(
      await screen.findByText("a policy with that name already exists"),
    ).toBeInTheDocument();
    expect(screen.getByText("Maximum validity 90 days")).toBeInTheDocument();
  });

  it("maps an error carrying status 403 to the permission message", async () => {
    const user = userEvent.setup();
    fetchMock
      .mockResolvedValueOnce(draftResp([]))
      .mockRejectedValueOnce(
        Object.assign(new Error("API error: 403 Forbidden"), { status: 403 }),
      );
    renderUi(<PolicyDraftDialog open onClose={() => {}} />);
    await parseText(user);
    await user.click(
      await screen.findByRole("button", { name: "Submit draft" }),
    );
    expect(
      await screen.findByText("You do not have permission to draft policies"),
    ).toBeInTheDocument();
  });

  it("detects 403 by status even when the message has no marker", async () => {
    const user = userEvent.setup();
    fetchMock
      .mockResolvedValueOnce(draftResp([]))
      .mockRejectedValueOnce(
        Object.assign(new Error("role lacks policies:write"), { status: 403 }),
      );
    renderUi(<PolicyDraftDialog open onClose={() => {}} />);
    await parseText(user);
    await user.click(
      await screen.findByRole("button", { name: "Submit draft" }),
    );
    expect(
      await screen.findByText("You do not have permission to draft policies"),
    ).toBeInTheDocument();
  });
});

describe("Templates page draft entry (W30-17)", () => {
  it("the header button opens the draft dialog", async () => {
    const user = userEvent.setup();
    renderUi(<Templates />);
    await user.click(
      await screen.findByRole("button", { name: "Draft policy from text" }),
    );
    expect(
      await screen.findByRole("dialog", { name: "Draft policy from text" }),
    ).toBeInTheDocument();
  });
});
