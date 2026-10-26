import { describe, expect, it } from "vitest";
import { buildConfig, dnsSecretFields, ISSUER_TYPES } from "./issuerTypes";

describe("dnsSecretFields", () => {
  it("nests every non-Cloudflare provider credential under dns", () => {
    for (const p of ["route53", "azure", "gcp", "rfc2136", "delegated"]) {
      const fields = dnsSecretFields(p);
      expect(fields.length).toBeGreaterThan(0);
      expect(fields.every((f) => f.nestUnder === "dns")).toBe(true);
    }
  });
  it("keeps the Cloudflare token at the top level", () => {
    const [f] = dnsSecretFields("cloudflare");
    expect(f.key).toBe("cloudflare_api_token");
    expect(f.nestUnder).toBeUndefined();
  });
  it("asks Route 53 for the access key pair", () => {
    const keys = dnsSecretFields("route53").filter((f) => f.required).map((f) => f.key);
    expect(keys).toEqual(["access_key_id", "secret_access_key"]);
  });
});

describe("the ACME plugin DNS provider", () => {
  const acme = ISSUER_TYPES.find((t) => t.id === "acme")!;
  it("collects no DNS secret", () => {
    expect(dnsSecretFields("plugin")).toEqual([]);
  });
  it("sends the plugin and credential names only for dns-01 with the plugin provider", () => {
    const base = { directory_url: "https://x/dir", dns_plugin_id: "a.b", dns_plugin_credential: "cred-1" };
    expect(buildConfig(acme, { ...base, challenge: "dns-01", dns_provider: "plugin" })).toMatchObject({
      dns_plugin_id: "a.b",
      dns_plugin_credential: "cred-1",
    });
    for (const values of [
      { ...base, challenge: "dns-01", dns_provider: "cloudflare" },
      { ...base, challenge: "http-01", dns_provider: "plugin" },
    ]) {
      const cfg = buildConfig(acme, values);
      expect(cfg).not.toHaveProperty("dns_plugin_id");
      expect(cfg).not.toHaveProperty("dns_plugin_credential");
    }
  });
});
