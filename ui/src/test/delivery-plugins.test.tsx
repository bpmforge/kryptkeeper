import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";

vi.mock("../lib/api", () => ({
  api: {
    authzCheck: vi.fn(),
    deliveryPlugins: vi.fn(),
    installDeliveryPlugin: vi.fn(),
    pluginCatalogue: vi.fn(),
    installFromPluginCatalogue: vi.fn(),
    enableDeliveryPlugin: vi.fn(),
    disableDeliveryPlugin: vi.fn(),
    removeDeliveryPlugin: vi.fn(),
    pendingActions: vi.fn(),
    approvePendingAction: vi.fn(),
    rejectPendingAction: vi.fn(),
    approvePqcWaveExecute: vi.fn(),
  },
}));

import DeliveryPlugins from "../pages/DeliveryPlugins";
import PendingActions from "../pages/PendingActions";
import { api } from "../lib/api";
import {
  capabilityLines,
  capabilityTier,
  sha256Hex,
  type PluginManifest,
} from "../lib/plugins";

function renderPage(ui: ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const manifest: PluginManifest = {
  api_version: "kryptkeeper.delivery/v1",
  id: "kryptkeeper.example-device",
  name: "Example HTTPS device",
  version: "1.0.0",
  publisher: "Kryptkeeper Authors",
  artifact: { file: "plugin.wasm", sha256: "" },
  capabilities: {
    receive_private_key: true,
    network: { hosts_from_credential: "base_url" },
    tls_verify: true,
  },
  credential_schema: {
    base_url: { type: "url", required: true },
    token: { type: "string", required: true, secret: true },
  },
  target_schema: { listener: { type: "string", required: true } },
};

const plugin = {
  id: "kryptkeeper.example-device",
  enabled_version: "1.0.0",
  versions: [
    {
      plugin_id: "kryptkeeper.example-device",
      version: "1.0.0",
      sha256: "ab".repeat(32),
      trust_tier: "community",
      capability_tier: "critical",
      status: "enabled",
      manifest,
      installed_by: "admin",
      installed_at: "2026-10-08T12:00:00Z",
      approved_by: "second-admin",
      approved_at: "2026-10-08T12:05:00Z",
    },
  ],
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.authzCheck).mockResolvedValue({
    service: "kryptkeeper",
    authenticated: true,
    principal: "admin",
    role: "pki-admin",
  } as unknown as never);
});

describe("capability wording (W20-21)", () => {
  it("puts the most dangerous capability first, in fixed wording", () => {
    const lines = capabilityLines({
      tls_verify: true,
      network: {
        hosts_from_credential: "base_url",
        hosts: ["api.cdn.example"],
      },
      receive_private_key: true,
    });
    expect(lines.map((l) => l.tier)).toEqual([
      "critical",
      "high",
      "high",
      "standard",
    ]);
    expect(lines[0].text).toBe(
      "This plugin receives the private key of every certificate it delivers.",
    );
    expect(lines[1].text).toContain("api.cdn.example");
    expect(lines.every((l) => l.enforced)).toBe(true);
  });

  it("words provide_credentials as Critical, reserved for the credentials kind", () => {
    const lines = capabilityLines({ provide_credentials: true });
    expect(lines[0]).toMatchObject({
      key: "provide_credentials",
      tier: "critical",
    });
    expect(lines[0].text).toBe(
      "This plugin returns credentials the hub uses to log in to your systems.",
    );
    expect(capabilityTier({ provide_credentials: true })).toBe("critical");
  });

  it("matches the hub's tiers", () => {
    // SUP-A08-1: a credential-named host is network access, so High (was
    // "standard", which let one admin enable it without a second approver).
    expect(
      capabilityTier({ network: { hosts_from_credential: "base_url" } }),
    ).toBe("high");
    expect(capabilityTier({ tls_verify: true })).toBe("standard");
    expect(capabilityTier({ remote_exec: true })).toBe("high");
    expect(capabilityTier({ trust_store: true, remote_exec: true })).toBe(
      "critical",
    );
  });
});

describe("Delivery Plugins page", () => {
  it("shows each plugin's capabilities, tier and version, with admin actions", async () => {
    vi.mocked(api.deliveryPlugins).mockResolvedValue({
      data: [plugin],
    } as never);
    renderPage(<DeliveryPlugins />);
    expect(await screen.findByText("Enabled: 1.0.0")).toBeInTheDocument();
    expect(
      screen.getByText(
        "This plugin receives the private key of every certificate it delivers.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Critical capabilities")).toBeInTheDocument();
    expect(
      await screen.findByRole("button", { name: /disable/i }),
    ).toBeInTheDocument();
  });

  it("shows the plugin kind; a manifest without one is a delivery plugin", async () => {
    const notifyPlugin = {
      id: "kryptkeeper.pagerduty",
      versions: [
        {
          ...plugin.versions[0],
          plugin_id: "kryptkeeper.pagerduty",
          kind: "notify",
          capability_tier: "high",
          status: "installed",
          manifest: {
            ...manifest,
            id: "kryptkeeper.pagerduty",
            name: "PagerDuty alerts",
            kind: "notify",
            capabilities: { network: { hosts_from_credential: "api_base" } },
          },
        },
      ],
    };
    vi.mocked(api.deliveryPlugins).mockResolvedValue({
      data: [plugin, notifyPlugin],
    } as never);
    renderPage(<DeliveryPlugins />);
    expect(await screen.findByText("Notification plugin")).toBeInTheDocument();
    expect(screen.getByText("Delivery plugin")).toBeInTheDocument();
  });

  it("says plainly when plugins are turned off", async () => {
    vi.mocked(api.deliveryPlugins).mockRejectedValue(
      new Error(
        "delivery plugins are turned off (KRYPTKEEPER_DELIVERY_PLUGINS=off)",
      ),
    );
    renderPage(<DeliveryPlugins />);
    expect(
      await screen.findByText("Delivery plugins are turned off"),
    ).toBeInTheDocument();
  });

  it("refuses a module that does not match its manifest, and asks before a critical install", async () => {
    vi.mocked(api.deliveryPlugins).mockResolvedValue({ data: [] } as never);
    vi.mocked(api.installDeliveryPlugin).mockResolvedValue({
      data: { plugin_id: manifest.id, version: "1.0.0" },
    } as never);
    const user = userEvent.setup();
    renderPage(<DeliveryPlugins />);
    await user.click(
      await screen.findByRole("button", { name: /install plugin/i }),
    );

    const wasm = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
    const good = {
      ...manifest,
      artifact: { file: "plugin.wasm", sha256: await sha256Hex(wasm.buffer) },
    };
    const bad = {
      ...manifest,
      artifact: { file: "plugin.wasm", sha256: "00".repeat(32) },
    };
    const wasmFile = new File([wasm], "plugin.wasm", {
      type: "application/wasm",
    });

    await user.upload(
      screen.getByLabelText("manifest.json"),
      new File([JSON.stringify(bad)], "manifest.json", {
        type: "application/json",
      }),
    );
    await user.upload(screen.getByLabelText("Plugin module"), wasmFile);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /does not match/,
    );
    // Even acknowledged, a module that does not match its pin cannot be
    // installed.
    await user.click(screen.getByRole("checkbox"));
    const install = screen.getByRole("button", { name: /^install$/i });
    expect(install).toBeDisabled();
    await user.click(screen.getByRole("checkbox"));

    await user.upload(
      screen.getByLabelText("manifest.json"),
      new File([JSON.stringify(good)], "manifest.json", {
        type: "application/json",
      }),
    );
    expect(await screen.findByText(/matches the manifest/)).toBeInTheDocument();
    expect(
      screen.getAllByText(
        "This plugin receives the private key of every certificate it delivers.",
      ).length,
    ).toBeGreaterThan(0);
    expect(install).toBeDisabled();
    // A signature covers the manifest's exact bytes, so those are sent, not
    // a re-encoding of the parsed object.
    await user.upload(
      screen.getByLabelText("Signature"),
      new File(["MEUCIQ-test-signature\n"], "manifest.json.sig"),
    );
    expect(
      await screen.findByText("Trust: signed (checked by the hub on install)"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("checkbox"));
    await waitFor(() => expect(install).toBeEnabled());
    await user.click(install);
    await waitFor(() =>
      expect(api.installDeliveryPlugin).toHaveBeenCalledTimes(1),
    );
    expect(api.installDeliveryPlugin).toHaveBeenCalledWith(
      btoa(JSON.stringify(good)),
      expect.any(String),
      "MEUCIQ-test-signature",
    );
  });
});

describe("Pending Actions: plugin enable review", () => {
  it("shows the approver what the plugin version can do", async () => {
    vi.mocked(api.deliveryPlugins).mockResolvedValue({
      data: [
        {
          ...plugin,
          enabled_version: undefined,
          versions: [{ ...plugin.versions[0], status: "pending_approval" }],
        },
      ],
    } as never);
    vi.mocked(api.pendingActions).mockResolvedValue({
      data: [
        {
          id: "act-1",
          action_type: "delivery_plugin.enable",
          params: {
            plugin_id: plugin.id,
            version: "1.0.0",
            sha256: "ab".repeat(32),
          },
          proposed_by: "admin",
          status: "pending",
          created_at: "2026-10-08T12:00:00Z",
        },
      ],
    } as never);
    renderPage(<PendingActions />);
    expect(
      await screen.findByText(`Enable delivery plugin ${plugin.id} 1.0.0`),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(
        "This plugin receives the private key of every certificate it delivers.",
      ),
    ).toBeInTheDocument();
    // The proposer cannot approve their own request.
    expect(screen.getByRole("button", { name: /approve/i })).toBeDisabled();
  });
});

describe("Catalogue tab (W38-11)", () => {
  const entry = {
    id: "kryptkeeper.example-device",
    kind: "delivery",
    name: "Example HTTPS device",
    publisher: "Kryptkeeper Authors",
    version: "1.0.0",
    description: "d",
    sha256: "ab".repeat(32),
    capabilities: ["receive_private_key", "network"],
    status: "available",
    compatible: true,
  };

  it("does not touch the catalogue until the tab is opened, then installs", async () => {
    vi.mocked(api.deliveryPlugins).mockResolvedValue({ data: [] } as never);
    vi.mocked(api.pluginCatalogue).mockResolvedValue({
      data: { generated_at: "2026-10-25T00:00:00Z", entries: [entry] },
    } as never);
    vi.mocked(api.installFromPluginCatalogue).mockResolvedValue({
      data: {},
    } as never);
    renderPage(<DeliveryPlugins />);
    const tab = await screen.findByRole("tab", { name: "Catalogue" });
    expect(api.pluginCatalogue).not.toHaveBeenCalled();
    await userEvent.click(tab);
    await userEvent.click(
      await screen.findByRole("button", { name: "Install" }),
    );
    await waitFor(() =>
      expect(api.installFromPluginCatalogue).toHaveBeenCalledWith(
        "kryptkeeper.example-device",
        "1.0.0",
      ),
    );
  });

  it("says so when the hub has the catalogue turned off", async () => {
    vi.mocked(api.deliveryPlugins).mockResolvedValue({ data: [] } as never);
    vi.mocked(api.pluginCatalogue).mockRejectedValue(
      new Error("the plugin catalogue is turned off"),
    );
    renderPage(<DeliveryPlugins />);
    await userEvent.click(
      await screen.findByRole("tab", { name: "Catalogue" }),
    );
    expect(
      await screen.findByText("The catalogue is turned off"),
    ).toBeInTheDocument();
  });
});
