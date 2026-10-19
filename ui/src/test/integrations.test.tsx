import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    authzCheck: vi.fn(),
    runtimeConfig: vi.fn(),
    setRuntimeConfig: vi.fn(),
    resetRuntimeConfig: vi.fn(),
    testNotificationDelivery: vi.fn(),
    protectedConfig: vi.fn(),
    dcvValidations: vi.fn().mockResolvedValue({ data: [], schedule: [], current_reuse_days: 0 }),
  },
}));

vi.mock("../lib/rolesApi", () => ({
  rolesApi: { preview: vi.fn() },
}));

import Integrations from "../pages/Integrations";
import { api } from "../lib/api";
import { rolesApi } from "../lib/rolesApi";

const adminAuthz = {
  service: "kryptkeeper",
  authenticated: true,
  principal: "admin-1",
  role: "pki-admin",
  scopes: ["*"],
};

const operatorAuthz = {
  service: "kryptkeeper",
  authenticated: true,
  principal: "operator-1",
  role: "pki-operator",
  scopes: [],
};

const NOTIFICATION_SETTINGS = [
  {
    key: "notifications.smtp_host",
    category: "notifications",
    env_var: "SMTP_HOST",
    secret: false,
    source: "env_default",
    effective_source: "env",
    value: "smtp.example.com",
    configured: true,
  },
  {
    key: "notifications.pagerduty_routing_key",
    category: "notifications",
    env_var: "PAGERDUTY_ROUTING_KEY",
    secret: true,
    source: "database",
    effective_source: "override",
    configured: true,
    updated_at: "2026-07-29T00:00:00Z",
    updated_by: "admin-1",
  },
];

const SSO_SETTINGS = [
  {
    key: "sso.oidc_issuer",
    category: "sso",
    env_var: "APP_OIDC_ISSUER",
    secret: false,
    source: "unset",
    effective_source: "env",
    configured: false,
  },
  {
    key: "sso.oidc_jwks_json",
    category: "sso",
    env_var: "APP_OIDC_JWKS_JSON",
    secret: true,
    source: "unset",
    effective_source: "env",
    configured: false,
  },
];

const NEW_SETTINGS = [
  {
    key: "saml.idp_sso_url",
    category: "saml",
    env_var: "APP_SAML_IDP_SSO_URL",
    secret: false,
    source: "unset",
    effective_source: "env",
    configured: false,
  },
  {
    key: "saml.idp_issuer",
    category: "saml",
    env_var: "APP_SAML_IDP_ISSUER",
    secret: false,
    source: "database",
    effective_source: "override",
    value: "https://idp.example",
    configured: true,
    updated_at: "2026-10-01T00:00:00Z",
  },
  {
    key: "scim.token",
    category: "scim",
    env_var: "APP_SCIM_TOKEN",
    secret: true,
    source: "database",
    effective_source: "override",
    value: "leak-me",
    configured: true,
    updated_at: "2026-10-01T00:00:00Z",
  },
  {
    key: "key_backend.kind",
    category: "key_backend",
    env_var: "APP_KEY_BACKEND",
    secret: false,
    source: "env_default",
    effective_source: "env",
    value: "software",
    configured: true,
    restart_required: true,
  },
  {
    key: "agentless.default_privilege_mode",
    category: "agentless",
    env_var: "KRYPTKEEPER_AGENTLESS_DEFAULT_PRIVILEGE_MODE",
    secret: false,
    source: "env_default",
    effective_source: "env",
    value: "nopasswd",
    configured: true,
  },
];

function renderIntegrations() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Integrations />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function fieldContainer(labelText: string) {
  const input = screen.getByLabelText(labelText);
  return within(input.closest("div.space-y-2") as HTMLElement);
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.authzCheck).mockResolvedValue(adminAuthz as unknown as never);
  vi.mocked(api.runtimeConfig).mockResolvedValue({
    data: [...NOTIFICATION_SETTINGS, ...SSO_SETTINGS, ...NEW_SETTINGS],
  } as unknown as never);
  vi.mocked(api.protectedConfig).mockResolvedValue({
    service: "kryptkeeper",
    resource: "protected-config",
    auth_mode: "bootstrap",
    config: {
      oidc_enabled: false,
      discovery_enabled: false,
      jwt_mode_enabled: false,
    },
  } as unknown as never);
});

describe("Integrations page", () => {
  it("an admin can save a non-secret override", async () => {
    renderIntegrations();
    await screen.findByLabelText("SMTP host");
    const field = fieldContainer("SMTP host");

    const input = field.getByLabelText("SMTP host") as HTMLInputElement;
    await userEvent.clear(input);
    await userEvent.type(input, "smtp.new-host.example.com");
    await userEvent.click(field.getByRole("button", { name: /^save$/i }));

    await waitFor(() =>
      expect(api.setRuntimeConfig).toHaveBeenCalledWith(
        "notifications.smtp_host",
        "smtp.new-host.example.com",
      ),
    );
  });

  it("disables saving a blank secret field so it can't wipe a configured value", async () => {
    renderIntegrations();
    await screen.findByLabelText("PagerDuty routing key");
    const field = fieldContainer("PagerDuty routing key");

    expect(field.getByRole("button", { name: /^save$/i })).toBeDisabled();

    await userEvent.type(field.getByLabelText("PagerDuty routing key"), "R123");
    expect(field.getByRole("button", { name: /^save$/i })).toBeEnabled();
  });

  it("never renders a secret's plaintext even if the backend response includes one", async () => {
    vi.mocked(api.runtimeConfig).mockResolvedValue({
      data: [
        {
          key: "notifications.pagerduty_routing_key",
          category: "notifications",
          env_var: "PAGERDUTY_ROUTING_KEY",
          secret: true,
          source: "database",
          effective_source: "override",
          configured: true,
          // A backend bug/regression populating value on a secret must not
          // leak into the DOM -- the field renders blank regardless.
          value: "R-LEAKED-ROUTING-KEY",
        },
      ],
    } as unknown as never);

    renderIntegrations();
    const input = (await screen.findByLabelText(
      "PagerDuty routing key",
    )) as HTMLInputElement;

    expect(input).toHaveValue("");
    expect(screen.queryByText("R-LEAKED-ROUTING-KEY")).not.toBeInTheDocument();
    expect(
      screen.queryByDisplayValue("R-LEAKED-ROUTING-KEY"),
    ).not.toBeInTheDocument();
  });

  it("resets a database override back to the env default", async () => {
    renderIntegrations();
    await screen.findByLabelText("PagerDuty routing key");
    const field = fieldContainer("PagerDuty routing key");

    await userEvent.click(
      field.getByRole("button", { name: /reset to env default/i }),
    );

    await waitFor(() =>
      expect(api.resetRuntimeConfig).toHaveBeenCalledWith(
        "notifications.pagerduty_routing_key",
      ),
    );
  });

  it("disables writes for a non-admin role but still allows the channel test", async () => {
    vi.mocked(api.authzCheck).mockResolvedValue(
      operatorAuthz as unknown as never,
    );
    renderIntegrations();

    await screen.findByLabelText("SMTP host");
    const smtpField = fieldContainer("SMTP host");
    expect(smtpField.getByLabelText("SMTP host")).toBeDisabled();
    expect(screen.getByLabelText("SAML IdP SSO URL")).toBeDisabled();
    expect(smtpField.getByRole("button", { name: /^save$/i })).toBeDisabled();
    expect(
      smtpField.getByRole("button", { name: /reset to env default/i }),
    ).toBeDisabled();

    // The channel test is gated separately (canManageNotifications, which
    // pki-operator satisfies) -- disabled here only because no target has
    // been typed yet, not because of the role.
    const sendButton = screen.getByRole("button", { name: /send test$/i });
    expect(sendButton).toBeDisabled();
    await userEvent.type(
      screen.getByLabelText("Notification test target"),
      "ops@example.com",
    );
    expect(sendButton).not.toBeDisabled();
  });

  it("sends a notification channel test and shows the queued result", async () => {
    vi.mocked(api.testNotificationDelivery).mockResolvedValue({
      data: {
        resource: "notification-test-delivery",
        principal: "admin-1",
        delivery: {
          id: "d-1",
          channel: "email",
          target: "ops@example.com",
          status: "queued",
          queued_at: "2026-07-29T00:00:00Z",
        },
      },
    } as unknown as never);

    renderIntegrations();
    await userEvent.type(
      await screen.findByLabelText("Notification test target"),
      "ops@example.com",
    );
    await userEvent.click(screen.getByRole("button", { name: /send test$/i }));

    await waitFor(() =>
      expect(api.testNotificationDelivery).toHaveBeenCalledWith({
        channel: "email",
        target: "ops@example.com",
        message: "Test message from Kryptkeeper Integrations",
      }),
    );
    await screen.findByText(/queued: email → ops@example.com \(queued\)/i);
  });

  it("validates JWKS JSON locally without a network call", async () => {
    renderIntegrations();
    const jwks = await screen.findByLabelText("OIDC JWKS (static, JSON)");

    await userEvent.type(jwks, "not json");
    await screen.findByText("Not valid JSON.");

    // fireEvent bypasses user-event's keyboard parser, which otherwise
    // treats "{"/"}" as the start of a special key sequence (e.g.
    // "{enter}") and can't type literal JSON braces.
    fireEvent.change(jwks, { target: { value: '{"keys":[{"kid":"1"}]}' } });
    await screen.findByText(/Valid JWKS — 1 key\(s\)\./);

    expect(api.setRuntimeConfig).not.toHaveBeenCalled();
    expect(api.resetRuntimeConfig).not.toHaveBeenCalled();
  });

  it("shows the running server's SSO status with the W8-13 restart caveat", async () => {
    renderIntegrations();
    await screen.findByText("SSO status on the running server");
    await waitFor(() => expect(api.protectedConfig).toHaveBeenCalled());
    expect(screen.getByText("bootstrap")).toBeInTheDocument();
    expect(
      screen.getByText(/server restarts with SSO consumers rewired/i),
    ).toBeInTheDocument();
  });

  it("previews the role an IdP group would map to (W22-18)", async () => {
    vi.mocked(rolesApi.preview).mockResolvedValue({
      data: {
        groups: ["kk-ops"],
        mapped: true,
        role: "pki-operator",
        matched_claim_value: "kk-ops",
        unmapped_policy: "deny",
        effective_role: "pki-operator",
        would_login: true,
      },
    });
    renderIntegrations();
    await userEvent.type(await screen.findByLabelText(/idp groups/i), "kk-ops");
    await userEvent.click(screen.getByRole("button", { name: /^preview$/i }));
    await waitFor(() => expect(rolesApi.preview).toHaveBeenCalledWith(["kk-ops"]));
    await screen.findByText("pki-operator");
    expect(screen.getByText(/matched claim value: kk-ops/i)).toBeInTheDocument();
  });

  it("says an unmapped group would be denied (W22-18)", async () => {
    vi.mocked(rolesApi.preview).mockResolvedValue({
      data: {
        groups: ["nobody"],
        mapped: false,
        role: "",
        matched_claim_value: "",
        unmapped_policy: "deny",
        effective_role: "",
        would_login: false,
      },
    });
    renderIntegrations();
    await userEvent.type(await screen.findByLabelText(/idp groups/i), "nobody");
    await userEvent.click(screen.getByRole("button", { name: /^preview$/i }));
    await screen.findByText("Would be denied (403)");
    expect(screen.getByText("No mapping matches")).toBeInTheDocument();
  });
});

describe("SAML / SCIM / key backend panels (W33-05)", () => {
  it("shows SAML, SCIM and Key backend panels", async () => {
    renderIntegrations();
    await screen.findByLabelText("SAML IdP SSO URL");
    for (const title of ["SAML", "SCIM", "Key backend"]) {
      expect(screen.getByText(title, { exact: true })).toBeInTheDocument();
    }
    expect(screen.getByLabelText("SAML IdP issuer")).toBeInTheDocument();
    expect(screen.getByLabelText("SCIM bearer token")).toBeInTheDocument();
    expect(screen.getByLabelText("Key backend kind")).toBeInTheDocument();
  });

  it("saves a SAML override", async () => {
    renderIntegrations();
    await screen.findByLabelText("SAML IdP SSO URL");
    const field = fieldContainer("SAML IdP SSO URL");
    await userEvent.type(
      field.getByLabelText("SAML IdP SSO URL"),
      "https://idp.example/sso",
    );
    await userEvent.click(field.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(api.setRuntimeConfig).toHaveBeenCalledWith(
        "saml.idp_sso_url",
        "https://idp.example/sso",
      ),
    );
  });

  it("secret SCIM token never renders a stored value", async () => {
    renderIntegrations();
    const input = (await screen.findByLabelText(
      "SCIM bearer token",
    )) as HTMLInputElement;
    expect(screen.queryByDisplayValue("leak-me")).toBeNull();
    expect(screen.queryByText("leak-me")).toBeNull();
    expect(input.type).toBe("password");
    expect(input).toHaveValue("");
    const field = fieldContainer("SCIM bearer token");
    expect(field.getByRole("button", { name: /^save$/i })).toBeDisabled();
    await userEvent.type(input, "new-token");
    expect(field.getByRole("button", { name: /^save$/i })).toBeEnabled();
  });

  it("reset issues DELETE and badge flips to Env", async () => {
    renderIntegrations();
    await screen.findByLabelText("SAML IdP issuer");
    const field = fieldContainer("SAML IdP issuer");
    expect(field.getByText("Override")).toBeInTheDocument();

    vi.mocked(api.runtimeConfig).mockResolvedValue({
      data: [
        ...NOTIFICATION_SETTINGS,
        ...SSO_SETTINGS,
        ...NEW_SETTINGS.map((s) =>
          s.key === "saml.idp_issuer"
            ? { ...s, source: "env_default", effective_source: "env", updated_at: undefined }
            : s,
        ),
      ],
    } as unknown as never);
    await userEvent.click(
      field.getByRole("button", { name: /reset to env default/i }),
    );
    await waitFor(() =>
      expect(api.resetRuntimeConfig).toHaveBeenCalledWith("saml.idp_issuer"),
    );
    await waitFor(() =>
      expect(
        fieldContainer("SAML IdP issuer").getByText("Env"),
      ).toBeInTheDocument(),
    );
  });

  it("every config row has an Env or Override badge", async () => {
    renderIntegrations();
    await screen.findByLabelText("SAML IdP SSO URL");
    const all = [...NOTIFICATION_SETTINGS, ...SSO_SETTINGS, ...NEW_SETTINGS];
    const configured = all.filter((s) => s.configured).length;
    const badges = screen.getAllByText(/^(Env|Override)$/);
    expect(badges).toHaveLength(configured);
  });

  it("shows the agentless default privilege mode with its source badge (W34-14)", async () => {
    renderIntegrations();
    await screen.findByLabelText("Default sudo mode for SSH credentials");
    const field = fieldContainer("Default sudo mode for SSH credentials");
    expect(field.getByText("Env")).toBeInTheDocument();
    expect(field.getByDisplayValue("nopasswd")).toBeInTheDocument();
    expect(screen.getByText("Agentless privilege")).toBeInTheDocument();
  });

  it("key backend rows show the restart note", async () => {
    renderIntegrations();
    await screen.findByLabelText("Key backend kind");
    const field = fieldContainer("Key backend kind");
    expect(
      field.getByText("Takes effect after the hub restarts."),
    ).toBeInTheDocument();
  });

  it("shows the server message when a save is refused (409 lock-out guard)", async () => {
    vi.mocked(api.setRuntimeConfig).mockRejectedValue(
      new Error("would lock out all administrators"),
    );
    renderIntegrations();
    await screen.findByLabelText("SAML IdP SSO URL");
    const field = fieldContainer("SAML IdP SSO URL");
    await userEvent.type(
      field.getByLabelText("SAML IdP SSO URL"),
      "https://idp.example/sso",
    );
    await userEvent.click(field.getByRole("button", { name: /^save$/i }));
    await screen.findByText("would lock out all administrators");
  });
});
