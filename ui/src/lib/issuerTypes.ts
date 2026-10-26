// Per-type settings and credential schemas for the add-issuer wizard (W36-13).
// Non-secret fields become config_json; secret fields go to the outbound
// credential store and only the returned id is kept as credential_ref.

type ShowCondition = { key: string; value: string };

export type IssuerField = {
  key: string;
  label: string;
  kind?: "text" | "number" | "select" | "textarea";
  required?: boolean;
  default?: string;
  options?: string[];
  help?: string;
  placeholder?: string;
  // Show only when another field has this value (or, as a list, all of them).
  showIf?: ShowCondition | ShowCondition[];
  // A select whose options come from the hub, not from this file: the enabled
  // DNS-01 plugins, or the api_token credentials a plugin can read.
  optionsFrom?: "dns01-plugins" | "plugin-credentials";
  // Secret fields only: store the value under this key of the credential
  // payload (the ACME dns-01 providers read a nested "dns" object).
  nestUnder?: string;
};

export type SecretMode = {
  id: string;
  label: string;
  fields: IssuerField[];
};

export type IssuerType = {
  id: string;
  label: string;
  description: string;
  config: IssuerField[];
  // Secret field groups; the user picks one when there is more than one.
  // An empty list means no credential is needed for these settings.
  secrets: (config: Record<string, string>) => SecretMode[];
  // credential_type sent to POST /credentials.
  credentialType: "api_token" | "cloud_iam";
};

const pem = (key: string, label: string): IssuerField => ({
  key,
  label,
  kind: "textarea",
  placeholder: "-----BEGIN CERTIFICATE-----",
});
const text = (
  key: string,
  label: string,
  required = false,
  extra: Partial<IssuerField> = {},
): IssuerField => ({ key, label, required, ...extra });
const num = (key: string, label: string, required = false): IssuerField => ({
  key,
  label,
  kind: "number",
  required,
});
const secret = (key: string, label: string, required = true): IssuerField => ({
  key,
  label,
  required,
});
// dns-01 credentials per provider; the backend reads them from the
// credential's nested "dns" object (internal/bootstrap/connector_acme_dns01_*.go).
const dnsField = (key: string, label: string, required = true, kind?: IssuerField["kind"]): IssuerField => ({
  key,
  label,
  required,
  nestUnder: "dns",
  ...(kind ? { kind } : {}),
});
export function dnsSecretFields(provider: string): IssuerField[] {
  switch (provider) {
    case "route53":
      return [
        dnsField("access_key_id", "AWS access key ID"),
        dnsField("secret_access_key", "AWS secret access key"),
        dnsField("session_token", "AWS session token", false),
        dnsField("hosted_zone_id", "Hosted zone ID", false),
      ];
    case "azure":
      return [
        dnsField("tenant_id", "Azure tenant ID"),
        dnsField("client_id", "Client ID"),
        dnsField("client_secret", "Client secret"),
        dnsField("subscription_id", "Subscription ID"),
        dnsField("resource_group", "Resource group"),
      ];
    case "gcp":
      return [
        dnsField("project_id", "Google Cloud project ID"),
        dnsField("service_account_json", "Service account key (JSON)", true, "textarea"),
      ];
    case "rfc2136":
      return [
        dnsField("nameserver", "Nameserver (host:port)"),
        dnsField("zone", "Zone"),
        dnsField("tsig_key_name", "TSIG key name"),
        dnsField("tsig_secret", "TSIG secret (base64)"),
        dnsField("tsig_algorithm", "TSIG algorithm (default hmac-sha256)", false),
      ];
    case "delegated":
      return [
        dnsField("base_url", "acme-dns server URL"),
        dnsField("accounts", "Accounts (JSON: domain to {username, password, subdomain, fulldomain})", true, "textarea"),
      ];
    case "plugin":
      // The plugin's credential is a separate stored credential chosen in the
      // settings step; nothing DNS-related goes in the ACME account credential.
      return [];
    default:
      return [secret("cloudflare_api_token", "Cloudflare API token", true)];
  }
}
const secretPem = (key: string, label: string): IssuerField => ({
  key,
  label,
  kind: "textarea",
  required: true,
});

const one = (fields: IssuerField[]) => (): SecretMode[] => [
  { id: "default", label: "Credentials", fields },
];

export const ISSUER_TYPES: IssuerType[] = [
  {
    id: "vault_pki",
    label: "HashiCorp Vault PKI",
    description: "Sign through a Vault PKI secrets engine role.",
    credentialType: "api_token",
    config: [
      text("base_url", "Vault address", true, {
        placeholder: "https://vault.example.com:8200",
      }),
      text("namespace", "Namespace"),
      text("mount", "PKI mount", true, { default: "pki" }),
      text("role", "Role", true),
      text("ttl", "Certificate TTL", false, { placeholder: "720h" }),
      text("approle_mount", "AppRole mount"),
      pem("ca_cert_pem", "Vault server CA certificate (PEM)"),
    ],
    secrets: () => [
      { id: "token", label: "Token", fields: [secret("token", "Vault token")] },
      {
        id: "approle",
        label: "AppRole",
        fields: [
          secret("role_id", "Role ID"),
          secret("secret_id", "Secret ID"),
        ],
      },
    ],
  },
  {
    id: "ejbca",
    label: "EJBCA",
    description: "Enroll through the EJBCA REST API with a client certificate.",
    credentialType: "api_token",
    config: [
      text("base_url", "EJBCA base URL", true, {
        placeholder: "https://ejbca.example.com:8443/ejbca",
      }),
      text("certificate_profile_name", "Certificate profile", true),
      text("end_entity_profile_name", "End entity profile", true),
      text("certificate_authority_name", "CA name", true),
      text("username_prefix", "End entity username prefix"),
      pem("ca_cert_pem", "EJBCA server CA certificate (PEM)"),
    ],
    secrets: one([
      secretPem("client_cert_pem", "Client certificate (PEM)"),
      secretPem("client_key_pem", "Client key (PEM)"),
    ]),
  },
  {
    id: "aws_pca",
    label: "AWS Private CA",
    description: "Issue from an AWS Private CA.",
    credentialType: "cloud_iam",
    config: [
      text("certificate_authority_arn", "CA ARN", true),
      text("region", "Region", true, { placeholder: "us-east-1" }),
      text("signing_algorithm", "Signing algorithm", false, {
        placeholder: "SHA256WITHRSA",
      }),
      num("validity_days", "Validity (days)"),
      text("template_arn", "Template ARN"),
      text("endpoint_url", "Endpoint URL"),
      {
        key: "auth",
        label: "Authentication",
        kind: "select",
        required: true,
        options: ["static", "ambient"],
        default: "static",
        help: "Ambient uses the hub's own AWS identity. Static stores an access key.",
      },
    ],
    secrets: (c) =>
      c.auth === "ambient"
        ? []
        : [
            {
              id: "default",
              label: "Access key",
              fields: [
                secret("access_key_id", "Access key ID"),
                secret("secret_access_key", "Secret access key"),
                secret("session_token", "Session token", false),
              ],
            },
          ],
  },
  {
    id: "gcp_cas",
    label: "Google CAS",
    description: "Issue from a Google Certificate Authority Service pool.",
    credentialType: "cloud_iam",
    config: [
      text("project", "Project", true),
      text("location", "Location", true, { placeholder: "us-central1" }),
      text("ca_pool", "CA pool", true),
      text("certificate_authority_id", "CA ID"),
      text("certificate_template", "Certificate template"),
      num("lifetime_days", "Lifetime (days)"),
      {
        key: "auth",
        label: "Authentication",
        kind: "select",
        required: true,
        options: ["service_account", "ambient"],
        default: "service_account",
        help: "Ambient uses the hub's own Google identity.",
      },
    ],
    secrets: (c) =>
      c.auth === "ambient"
        ? []
        : [
            {
              id: "default",
              label: "Service account",
              fields: [
                secretPem("service_account_json", "Service account JSON"),
              ],
            },
          ],
  },
  {
    id: "sectigo",
    label: "Sectigo",
    description: "Order certificates through Sectigo Certificate Manager.",
    credentialType: "api_token",
    config: [
      text("base_url", "SCM base URL", true, {
        placeholder: "https://cert-manager.com/api",
      }),
      text("customer_uri", "Customer URI", true),
      num("org_id", "Organization ID", true),
      text("cert_type", "Certificate type ID", true),
      num("term_days", "Term (days)", true),
    ],
    secrets: () => [
      {
        id: "password",
        label: "Login and password",
        fields: [secret("login", "Login"), secret("password", "Password")],
      },
      {
        id: "mtls",
        label: "Login and client certificate",
        fields: [
          secret("login", "Login"),
          secretPem("client_cert_pem", "Client certificate (PEM)"),
          secretPem("client_key_pem", "Client key (PEM)"),
        ],
      },
    ],
  },
  {
    id: "globalsign",
    label: "GlobalSign",
    description: "Issue through GlobalSign Atlas.",
    credentialType: "api_token",
    config: [
      text("base_url", "Atlas base URL", true),
      num("validity_days", "Validity (days)"),
      pem("ca_cert_pem", "CA certificate (PEM)"),
    ],
    secrets: one([
      secret("api_key", "API key"),
      secret("api_secret", "API secret"),
      secretPem("client_cert_pem", "Client certificate (PEM)"),
      secretPem("client_key_pem", "Client key (PEM)"),
    ]),
  },
  {
    id: "entrust",
    label: "Entrust",
    description: "Issue through Entrust Certificate Services.",
    credentialType: "api_token",
    config: [
      text("base_url", "API base URL", true),
      text("client_id", "Client ID", true),
      text("cert_type", "Certificate type", true),
      num("validity_days", "Validity (days)"),
      text("requester_name", "Requester name", true),
      text("requester_email", "Requester email", true),
      text("requester_phone", "Requester phone", true),
    ],
    secrets: one([
      secret("username", "Username"),
      secret("api_key", "API key"),
      secretPem("client_cert_pem", "Client certificate (PEM)"),
      secretPem("client_key_pem", "Client key (PEM)"),
    ]),
  },
  {
    id: "digicert",
    label: "DigiCert",
    description: "Order through DigiCert CertCentral.",
    credentialType: "api_token",
    config: [
      text("base_url", "Base URL"),
      text("organization_id", "Organization ID", true),
      text("product_name_id", "Product name ID"),
      num("validity_years", "Validity (years)"),
    ],
    secrets: one([secret("api_key", "API key")]),
  },
  {
    id: "acme",
    label: "ACME CA",
    description:
      "Let's Encrypt, ZeroSSL, Google, SSL.com, Buypass, Sectigo or any ACME directory.",
    credentialType: "api_token",
    config: [
      text("directory_url", "Directory URL", true, {
        placeholder: "https://example.com/directory",
      }),
      text("email", "Contact email"),
      {
        key: "challenge",
        label: "Challenge",
        kind: "select",
        required: true,
        options: ["http-01", "dns-01"],
        default: "http-01",
      },
      text("http01_listen", "HTTP-01 listen address", false, {
        placeholder: ":80",
        showIf: { key: "challenge", value: "http-01" },
      }),
      {
        key: "dns_provider",
        label: "DNS provider",
        kind: "select",
        required: true,
        options: ["cloudflare", "route53", "azure", "gcp", "rfc2136", "delegated", "plugin"],
        default: "cloudflare",
        showIf: { key: "challenge", value: "dns-01" },
        help: "rfc2136 covers BIND, PowerDNS, Infoblox and Windows DNS with a TSIG key; delegated is acme-dns style CNAME delegation; plugin uses a signed DNS plugin (DigitalOcean, GoDaddy, NS1, Akamai or your own).",
      },
      {
        key: "dns_plugin_id",
        label: "DNS plugin",
        kind: "select",
        required: true,
        optionsFrom: "dns01-plugins",
        showIf: [
          { key: "challenge", value: "dns-01" },
          { key: "dns_provider", value: "plugin" },
        ],
        help: "Only enabled DNS-01 plugins are listed. Install one on the Plugins page; a second person enables it.",
      },
      {
        key: "dns_plugin_credential",
        label: "Plugin credential",
        kind: "select",
        required: true,
        optionsFrom: "plugin-credentials",
        showIf: [
          { key: "challenge", value: "dns-01" },
          { key: "dns_provider", value: "plugin" },
        ],
        help: "An api_token credential whose secret is a JSON object of the plugin's credential fields (see the ACME upstream guide).",
      },
    ],
    secrets: (c) => [
      {
        id: "default",
        label: "Account and challenge credentials",
        fields: [
          secret("eab_kid", "EAB key ID", false),
          secret("eab_hmac_b64", "EAB HMAC key", false),
          ...(c.challenge === "dns-01" ? dnsSecretFields(c.dns_provider || "cloudflare") : []),
          {
            key: "account_key_pem",
            label: "Account key (PEM, optional)",
            kind: "textarea" as const,
          },
        ],
      },
    ],
  },
  {
    id: "est",
    label: "EST",
    description: "Enroll through an EST server (RFC 7030).",
    credentialType: "api_token",
    config: [
      text("base_url", "EST base URL", true),
      text("username", "Username", true),
    ],
    secrets: one([secret("password", "Password")]),
  },
];

const LABELS: Record<string, string> = Object.fromEntries(
  ISSUER_TYPES.map((t) => [t.id, t.label]),
);

export function issuerTypeLabel(type: string): string {
  if (type === "internal") return "Built-in";
  return LABELS[type] ?? type;
}

export function fieldVisible(
  f: IssuerField,
  values: Record<string, string>,
): boolean {
  if (!f.showIf) return true;
  const conds = Array.isArray(f.showIf) ? f.showIf : [f.showIf];
  return conds.every((c) => (values[c.key] ?? "") === c.value);
}

// Initial values from schema defaults.
export function configDefaults(t: IssuerType): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of t.config) if (f.default !== undefined) out[f.key] = f.default;
  return out;
}

// config_json object: hidden and empty fields are skipped; number fields
// become numbers.
export function buildConfig(
  t: IssuerType,
  values: Record<string, string>,
): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  for (const f of t.config) {
    if (!fieldVisible(f, values)) continue;
    const v = (values[f.key] ?? "").trim();
    if (v === "") continue;
    out[f.key] =
      f.kind === "number" && !Number.isNaN(Number(v)) ? Number(v) : v;
  }
  return out;
}

export function missingRequired(
  fields: IssuerField[],
  values: Record<string, string>,
): string | null {
  for (const f of fields) {
    if (
      f.required &&
      fieldVisible(f, values) &&
      (values[f.key] ?? "").trim() === ""
    ) {
      return `${f.label} is required.`;
    }
  }
  return null;
}
