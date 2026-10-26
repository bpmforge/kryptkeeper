import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  api: {
    createCredential: vi.fn(),
    createConnector: vi.fn(),
    testConnector: vi.fn(),
    createExternalCa: vi.fn(),
    deliveryPlugins: vi.fn(),
    credentials: vi.fn(),
  },
}));

import { AddIssuerWizard } from "./AddIssuerWizard";
import { api } from "../lib/api";
import { buildConfig, ISSUER_TYPES } from "../lib/issuerTypes";
import { ACME_PRESETS } from "../lib/acmePresets";

const next = () =>
  userEvent.click(screen.getByRole("button", { name: "Next" }));

describe("AddIssuerWizard", () => {
  const onClose = vi.fn();
  const onDone = vi.fn();
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(api.createCredential).mockResolvedValue({
      data: { id: "cred1" },
    } as never);
    vi.mocked(api.createConnector).mockResolvedValue({
      data: { id: "con1" },
    } as never);
    vi.mocked(api.testConnector).mockResolvedValue({ status: "healthy" });
    vi.mocked(api.createExternalCa).mockResolvedValue({ data: {} } as never);
  });

  it("runs Vault end to end, keeping the token out of config_json", async () => {
    render(<AddIssuerWizard open onClose={onClose} onDone={onDone} />);
    await userEvent.click(screen.getByLabelText(/HashiCorp Vault PKI/));
    await next();
    await userEvent.type(screen.getByLabelText("Issuer name"), "Prod Vault");
    await userEvent.type(
      screen.getByLabelText("Vault address"),
      "https://v:8200",
    );
    await userEvent.type(screen.getByLabelText("Role"), "web");
    await next();
    await userEvent.type(screen.getByLabelText("Vault token"), "s.secret");
    await next();
    await userEvent.click(
      screen.getByRole("button", { name: "Save and test" }),
    );
    await screen.findByText("healthy");

    expect(api.createCredential).toHaveBeenCalledWith({
      name: "Prod Vault credential",
      credential_type: "api_token",
      payload: { token: "s.secret" },
    });
    const body = vi.mocked(api.createConnector).mock.calls[0][0];
    expect(body.credential_ref).toBe("cred1");
    expect(JSON.parse(body.config_json)).toEqual({
      base_url: "https://v:8200",
      mount: "pki",
      role: "web",
    });
    expect(body.config_json).not.toContain("s.secret");

    await next();
    await userEvent.type(screen.getByLabelText(/CA name/), "Vault CA");
    await userEvent.type(
      screen.getByLabelText(/Trust PEM/),
      "-----BEGIN CERTIFICATE-----",
    );
    await userEvent.click(screen.getByRole("button", { name: "Finish" }));
    await waitFor(() =>
      expect(api.createExternalCa).toHaveBeenCalledWith({
        name: "Vault CA",
        connector_id: "con1",
        trust_pem: "-----BEGIN CERTIFICATE-----",
      }),
    );
    expect(onClose).toHaveBeenCalled();
  });

  it("blocks Next on a missing required setting", async () => {
    render(<AddIssuerWizard open onClose={onClose} onDone={onDone} />);
    await userEvent.click(screen.getByLabelText(/EJBCA/));
    await next();
    await next();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Issuer name is required.",
    );
  });

  it("skips the credential for ambient AWS and warns on a degraded test", async () => {
    vi.mocked(api.testConnector).mockResolvedValue({
      status: "degraded",
      detail: "no access",
    });
    render(<AddIssuerWizard open onClose={onClose} onDone={onDone} />);
    await userEvent.click(screen.getByLabelText(/AWS Private CA/));
    await next();
    await userEvent.type(screen.getByLabelText("Issuer name"), "PCA");
    await userEvent.type(screen.getByLabelText("CA ARN"), "arn:aws:acm-pca:x");
    await userEvent.type(screen.getByLabelText("Region"), "us-east-1");
    await userEvent.selectOptions(
      screen.getByLabelText(/^Authentication/),
      "ambient",
    );
    await next();
    expect(screen.getByText(/nothing to store/)).toBeInTheDocument();
    await next();
    await userEvent.click(
      screen.getByRole("button", { name: "Save and test" }),
    );
    expect(await screen.findByText(/did not pass cleanly/)).toBeInTheDocument();
    expect(api.createCredential).not.toHaveBeenCalled();
    // Degraded still lets the user continue.
    await next();
    expect(screen.getByLabelText(/CA name/)).toBeInTheDocument();
  });

  it("picks an enabled DNS-01 plugin and its credential for the ACME plugin provider", async () => {
    vi.mocked(api.deliveryPlugins).mockResolvedValue({
      data: [
        {
          id: "kryptkeeper.digitalocean-dns",
          enabled_version: "1.0.0",
          versions: [{ version: "1.0.0", kind: "dns01" }],
        },
        {
          id: "kryptkeeper.pagerduty",
          enabled_version: "1.0.0",
          versions: [{ version: "1.0.0", kind: "notify" }],
        },
        {
          id: "kryptkeeper.godaddy-dns",
          versions: [{ version: "1.0.0", kind: "dns01" }],
        },
      ],
    } as never);
    vi.mocked(api.credentials).mockResolvedValue({
      data: {
        items: [
          { id: "cred-do", name: "DO DNS", credential_type: "api_token" },
          { id: "cred-ssh", name: "A key", credential_type: "ssh_key" },
        ],
      },
    } as never);
    render(<AddIssuerWizard open onClose={onClose} onDone={onDone} />);
    await userEvent.click(screen.getByLabelText(/ACME CA/));
    await next();
    await userEvent.type(screen.getByLabelText("Issuer name"), "LE dns");
    await userEvent.type(screen.getByLabelText("Directory URL"), "https://acme.example/dir");
    expect(screen.queryByLabelText(/^DNS plugin/)).not.toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText(/^Challenge/), "dns-01");
    await userEvent.selectOptions(screen.getByLabelText(/^DNS provider/), "plugin");

    const plugin = await screen.findByLabelText(/^DNS plugin/);
    // Only the enabled dns01 plugin is offered: not a notify plugin, not a disabled one.
    await waitFor(() =>
      expect(screen.getByRole("option", { name: "kryptkeeper.digitalocean-dns" })).toBeInTheDocument(),
    );
    expect(screen.queryByRole("option", { name: "kryptkeeper.pagerduty" })).not.toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "kryptkeeper.godaddy-dns" })).not.toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /A key/ })).not.toBeInTheDocument();

    await next();
    expect(await screen.findByRole("alert")).toHaveTextContent("DNS plugin is required.");
    await userEvent.selectOptions(plugin, "kryptkeeper.digitalocean-dns");
    await userEvent.selectOptions(screen.getByLabelText(/^Plugin credential/), "cred-do");
    await next();
    // No DNS secret is collected: the plugin's credential is already stored.
    expect(screen.queryByLabelText(/Cloudflare API token/)).not.toBeInTheDocument();
    await next();
    await userEvent.click(screen.getByRole("button", { name: "Save and test" }));
    await screen.findByText("healthy");
    const body = vi.mocked(api.createConnector).mock.calls[0][0];
    expect(JSON.parse(body.config_json)).toMatchObject({
      challenge: "dns-01",
      dns_provider: "plugin",
      dns_plugin_id: "kryptkeeper.digitalocean-dns",
      dns_plugin_credential: "cred-do",
    });
  });

  it("fills the directory URL from an ACME preset", async () => {
    render(<AddIssuerWizard open onClose={onClose} onDone={onDone} />);
    await userEvent.click(screen.getByLabelText(/ACME CA/));
    await next();
    await userEvent.selectOptions(
      screen.getByLabelText("Preset (optional)"),
      "zerossl",
    );
    expect(screen.getByLabelText("Directory URL")).toHaveValue(
      "https://acme.zerossl.com/v2/DV90",
    );
    expect(screen.getByText(/Needs EAB credentials/)).toBeInTheDocument();
  });
});

describe("issuer schemas", () => {
  it("never puts a secret key in config", () => {
    const secretKeys = new Set([
      "token",
      "secret_id",
      "password",
      "api_key",
      "api_secret",
      "client_key_pem",
    ]);
    for (const t of ISSUER_TYPES) {
      for (const f of t.config) expect(secretKeys.has(f.key)).toBe(false);
    }
  });
  it("coerces number fields and drops empty ones", () => {
    const t = ISSUER_TYPES.find((x) => x.id === "sectigo")!;
    expect(
      buildConfig(t, {
        base_url: "u",
        customer_uri: "c",
        org_id: "12",
        cert_type: "1",
        term_days: "",
      }),
    ).toEqual({ base_url: "u", customer_uri: "c", org_id: 12, cert_type: "1" });
  });
  it("only presets https directories", () => {
    for (const p of ACME_PRESETS)
      expect(p.directoryUrl.startsWith("https://")).toBe(true);
  });
});
