import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  fetchJSON: vi.fn(),
  api: { createCredential: vi.fn() },
}));

import ItsmConnection from "./ItsmConnection";
import { api, fetchJSON } from "../lib/api";

const TOKEN = "super-secret-token-xyz";
const conn = { id: "itsm-1", kind: "servicenow", name: "Prod SN", base_url: "https://sn.example.com", credential_ref: "cred-1", enabled: true };

function renderPanel(canWrite = true) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <ItsmConnection canWrite={canWrite} />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.createCredential).mockResolvedValue({ data: { id: "cred-9" } } as unknown as never);
  vi.mocked(fetchJSON).mockImplementation((async (path: string, init?: RequestInit) => {
    if (init?.method === "POST" && path === "/itsm/connections") return { data: conn };
    return { data: { items: [conn] } };
  }) as never);
});

async function fillBase(user: ReturnType<typeof userEvent.setup>) {
  await user.type(await screen.findByLabelText("ITSM name"), "Prod SN");
  await user.type(screen.getByLabelText("ITSM URL"), "https://sn.example.com");
  await user.type(screen.getByLabelText("ServiceNow username"), "svc");
  await user.type(screen.getByLabelText("ITSM credential"), TOKEN);
}

describe("ItsmConnection", () => {
  it("adds a ServiceNow connection", async () => {
    const user = userEvent.setup();
    renderPanel();
    await fillBase(user);
    await user.click(screen.getByRole("button", { name: "Add connection" }));
    await waitFor(() =>
      expect(api.createCredential).toHaveBeenCalledWith({
        name: "Prod SN ITSM",
        credential_type: "api_token",
        payload: { username: "svc", password: TOKEN },
      }),
    );
    await waitFor(() =>
      expect(fetchJSON).toHaveBeenCalledWith(
        "/itsm/connections",
        expect.objectContaining({ method: "POST" }),
      ),
    );
    const post = vi.mocked(fetchJSON).mock.calls.find((c) => (c[1] as RequestInit | undefined)?.method === "POST")!;
    expect(JSON.parse((post[1] as RequestInit).body as string)).toEqual({
      kind: "servicenow",
      name: "Prod SN",
      base_url: "https://sn.example.com",
      credential_ref: "cred-9",
      event_classes: [
        { class: "renewal_failed", ticket_type: "incident" },
        { class: "approval_pending", ticket_type: "incident" },
        { class: "expiry_no_owner", ticket_type: "incident" },
      ],
    });
    await waitFor(() => expect(screen.getByLabelText("ITSM credential")).toHaveValue(""));
  });

  it("jira requires project key", async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.selectOptions(await screen.findByLabelText("ITSM kind"), "jira");
    await user.type(screen.getByLabelText("ITSM name"), "Jira");
    await user.type(screen.getByLabelText("ITSM URL"), "https://x.atlassian.net");
    await user.type(screen.getByLabelText("ITSM credential"), TOKEN);
    await user.click(screen.getByRole("button", { name: "Add connection" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/project key is required/i);
    expect(api.createCredential).not.toHaveBeenCalled();
  });

  it("rejects non-https URL", async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.type(await screen.findByLabelText("ITSM name"), "Prod");
    await user.type(screen.getByLabelText("ITSM URL"), "http://sn.example.com");
    await user.type(screen.getByLabelText("ITSM credential"), TOKEN);
    await user.click(screen.getByRole("button", { name: "Add connection" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("URL must start with https://");
    expect(api.createCredential).not.toHaveBeenCalled();
  });

  it("test connection shows result", async () => {
    const user = userEvent.setup();
    renderPanel();
    const btn = await screen.findByRole("button", { name: /test connection prod sn/i });
    vi.mocked(fetchJSON).mockResolvedValueOnce({ data: { ok: true, detail: "reachable" } } as never);
    await user.click(btn);
    expect(await screen.findByText("OK: reachable")).toBeInTheDocument();
    expect(fetchJSON).toHaveBeenCalledWith("/itsm/connections/itsm-1/test", { method: "POST" });
    vi.mocked(fetchJSON).mockResolvedValueOnce({ data: { ok: false, detail: "auth rejected" } } as never);
    await user.click(btn);
    expect(await screen.findByText("Failed: auth rejected")).toBeInTheDocument();
    vi.mocked(fetchJSON).mockRejectedValueOnce(new Error("HTTP 404"));
    await user.click(btn);
    expect(await screen.findByText("Failed: HTTP 404")).toBeInTheDocument();
  });

  it("sends the chosen ticket type per class", async () => {
    const user = userEvent.setup();
    renderPanel();
    await fillBase(user);
    await user.selectOptions(screen.getByLabelText("Ticket type for approval_pending"), "change_request");
    await user.selectOptions(screen.getByLabelText("Ticket type for expiry_no_owner"), "");
    await user.click(screen.getByRole("button", { name: "Add connection" }));
    await waitFor(() => expect(api.createCredential).toHaveBeenCalled());
    const post = await waitFor(() => {
      const c = vi.mocked(fetchJSON).mock.calls.find((x) => (x[1] as RequestInit | undefined)?.method === "POST" && x[0] === "/itsm/connections");
      expect(c).toBeTruthy();
      return c!;
    });
    expect(JSON.parse((post[1] as RequestInit).body as string).event_classes).toEqual([
      { class: "renewal_failed", ticket_type: "incident" },
      { class: "approval_pending", ticket_type: "change_request" },
    ]);
  });

  it("never renders a secret", async () => {
    const user = userEvent.setup();
    renderPanel();
    await fillBase(user);
    await user.click(screen.getByRole("button", { name: "Add connection" }));
    await waitFor(() => expect(screen.getByLabelText("ITSM credential")).toHaveValue(""));
    expect(document.body.textContent).not.toContain(TOKEN);
    expect(await screen.findByText(/Stored \(write-only\)/)).toBeInTheDocument();
  });

  it("read-only for non-admin", async () => {
    renderPanel(false);
    expect(await screen.findByText(/Admin role required/)).toBeInTheDocument();
    expect(screen.getByLabelText("ITSM name")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Add connection" })).toBeDisabled();
    expect(await screen.findByRole("button", { name: /test connection prod sn/i })).toBeDisabled();
  });
});
