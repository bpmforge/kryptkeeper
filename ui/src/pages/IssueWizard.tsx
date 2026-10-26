import { useState } from "react";
import { scrollableProps } from "../lib/scrollable";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { Button, Input, Panel, Select, Textarea } from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { StateMessage } from "../components/ops-ui";
import { Wizard, type WizardStepDef } from "../components/Wizard";
import { canManageCertificates, useAuthz } from "../lib/auth";
import { isRequesterOnly } from "../lib/nav";
import { useTeamAllowedOptions } from "../lib/myRequests";
import { extractList } from "../lib/models";
import { savePemFile } from "../lib/utils";
import { parsePolicyViolation } from "../lib/policiesApi";
import type {
  CaRecord,
  CertificateRecord,
  TemplateRecord,
} from "../lib/models";

type KeyMode = "existing" | "generate" | null;

type PendingApprovalResponse = {
  status: "pending_approval";
  approval_id: string;
  message: string;
};

type IssueResult =
  | { kind: "issued"; cert: CertificateRecord }
  | { kind: "pending"; approvalId: string; message: string; approvers: string[] };

function isPendingApproval(value: unknown): value is PendingApprovalResponse {
  return (
    !!value &&
    typeof value === "object" &&
    "approval_id" in (value as Record<string, unknown>)
  );
}

// The backend's CertificateIssueRequest only defines {ca_id, template_id,
// csr_pem, team_id} (see docs/openapi.yaml POST /certificates) -- there is
// no subject/SAN field to fill server-side. Common name and SANs are
// collected here purely to build the openssl hint below; they are never
// sent to the API, matching the pattern established in Onboarding.tsx.
function isIpAddress(s: string): boolean {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (v4) return v4.slice(1).every((o) => Number(o) <= 255);
  if (!s.includes(":") || !/^[0-9A-Fa-f:.]+$/.test(s)) return false;
  try {
    new URL("http://[" + s + "]");
    return true;
  } catch {
    return false;
  }
}

function isDnsName(s: string): boolean {
  const name = s.startsWith("*.") ? s.slice(2) : s;
  if (!name || name.length > 253) return false;
  return name
    .split(".")
    .every((l) => /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(l));
}

const SAN_LIMIT = 100;

// Returns the first SAN problem as a user-facing message, or null.
function validateSans(sans: string[], template: TemplateRecord | null) {
  if (sans.length > SAN_LIMIT) return `Too many SANs (limit ${SAN_LIMIT}).`;
  const np = template?.name_policy;
  const suffixes = np?.allowed_dns_suffixes ?? [];
  for (const san of sans) {
    const ip = isIpAddress(san);
    if (!ip && !isDnsName(san)) {
      return `"${san}" is not a valid DNS name or IP address. Use letters, digits and hyphens, for example api.example.com.`;
    }
    if (!np) continue;
    if (ip) {
      if (!np.allow_ip_sans) return "This template does not allow IP address SANs.";
    } else if (
      suffixes.length > 0 &&
      !(np.allowed_dns_names ?? []).includes(san) &&
      !suffixes.some((suf) => san.endsWith(suf))
    ) {
      return `"${san}" is outside this template's allowed domains (${suffixes.join(", ")}).`;
    }
  }
  return null;
}

function buildCsrHint(commonName: string, sans: string[]) {
  const subj = `/CN=${commonName.trim() || "example.com"}`;
  const sanExt = sans.length
    ? ` \\\n  -addext "subjectAltName=${sans.map((s) => `${isIpAddress(s) ? "IP" : "DNS"}:${s}`).join(",")}"`
    : "";
  return `openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \\
  -nodes -keyout issuance.key -out issuance.csr \\
  -subj "${subj}"${sanExt}`;
}

const emptyState = {
  caId: "",
  templateId: "",
  commonName: "",
  sansText: "",
  keyMode: null as KeyMode,
  csrPem: "",
};

export default function IssueWizard() {
  const navigate = useNavigate();
  const authz = useAuthz();
  // A requester files requests for its own team; the server confines it.
  const canManage =
    canManageCertificates(authz.data?.role, authz.data?.scopes) ||
    isRequesterOnly(authz.data?.role);
  const allowed = useTeamAllowedOptions();

  const [caId, setCaId] = useState(emptyState.caId);
  const [templateId, setTemplateId] = useState(emptyState.templateId);
  const [commonName, setCommonName] = useState(emptyState.commonName);
  const [sansText, setSansText] = useState(emptyState.sansText);
  const [keyMode, setKeyMode] = useState<KeyMode>(emptyState.keyMode);
  const [csrPem, setCsrPem] = useState(emptyState.csrPem);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [result, setResult] = useState<IssueResult | null>(null);

  const casQuery = useQuery({
    queryKey: ["cas", { limit: 50 }],
    queryFn: () => api.cas({ limit: 50 }),
  });
  const templatesQuery = useQuery({
    queryKey: ["templates", { limit: 50 }],
    queryFn: () => api.templates({ limit: 50 }),
  });

  const cas: CaRecord[] = allowed.filterCas(
    extractList<CaRecord>(casQuery.data?.data, ["items"]),
  );
  const allTemplates: TemplateRecord[] = extractList<TemplateRecord>(
    templatesQuery.data?.data,
    ["items"],
  );
  // Only templates the CA will actually accept. Offering an inactive one
  // walked a user through four steps to a "template policy violation" at
  // Finish — the wizard must not offer what the server will refuse.
  const templates = allowed
    .filterTemplates(allTemplates)
    .filter((t) => t.active !== false);
  const sans = sansText
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const selectedCa = cas.find((ca) => ca.id === caId) ?? null;
  const selectedTemplate = templates.find((t) => t.id === templateId) ?? null;
  const violation = issueError ? parseViolation(issueError) : null;

  // Engine-policy refusals carry policy/rule/observed; template refusals read
  // "policy violation [field]: detail" (handlers_certificates.go), where the
  // bracketed field is the rule name.
  function parseViolation(message: string) {
    const engine = parsePolicyViolation(message);
    if (engine) return engine;
    const m = /policy violation \[(\w+)\]: (.+)$/.exec(message);
    if (!m) return null;
    return {
      policy:
        selectedTemplate?.display_name || selectedTemplate?.name || "template",
      rule: m[1],
      detail: m[2],
    };
  }

  const issueMutation = useMutation({
    mutationFn: () =>
      api.issueCertificate({
        ca_id: caId,
        template_id: templateId,
        csr_pem: csrPem.trim(),
      }),
  });

  const reset = () => {
    setCaId(emptyState.caId);
    setTemplateId(emptyState.templateId);
    setCommonName(emptyState.commonName);
    setSansText(emptyState.sansText);
    setKeyMode(emptyState.keyMode);
    setCsrPem(emptyState.csrPem);
    setIssueError(null);
    setResult(null);
  };

  // Wizard.finish() awaits onComplete but has no catch -- a rejected
  // promise here would escape as an unhandled rejection, so failures are
  // caught and surfaced through issueError/summary instead of re-thrown.
  const submit = async () => {
    setIssueError(null);
    try {
      const res = await issueMutation.mutateAsync();
      const cert = res?.data;
      if (cert && cert.fingerprint_sha256) {
        setResult({ kind: "issued", cert });
      } else if (isPendingApproval(res)) {
        setResult({
          kind: "pending",
          approvalId: res.approval_id,
          message: res.message,
          approvers: selectedTemplate?.approval_roles?.length
            ? selectedTemplate.approval_roles
            : ["pki-admin"],
        });
      } else {
        setIssueError("Unexpected response from the issuance API.");
      }
    } catch (e) {
      setIssueError(
        e instanceof Error ? e.message : "Issuance failed. Try again.",
      );
    }
  };

  // S-69: the issue response's CertificateItem carries no PEM (the old
  // cert.cert_pem gate only ever matched MSW fixtures, so the download
  // button never rendered in production). Fetch the bytes from the download
  // endpoint instead.
  const downloadCert = async (cert: CertificateRecord) => {
    setDownloadError(null);
    try {
      const pem = await api.downloadCertificatePem(cert.fingerprint_sha256);
      savePemFile(`${cert.common_name || cert.fingerprint_sha256}.pem`, pem);
    } catch (e) {
      setDownloadError(
        e instanceof Error ? e.message : "Certificate download failed.",
      );
    }
  };

  const steps: WizardStepDef[] = [
    {
      id: "ca",
      title: "Certificate Authority",
      validate: () => (caId ? null : "Choose a CA to continue."),
      render: () => (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Pick the CA that will sign this certificate.
          </p>
          <label className="block space-y-1 text-sm text-foreground">
            <span>CA</span>
            <Select
              aria-label="Certificate authority"
              value={caId}
              onChange={(e) => setCaId(e.target.value)}
            >
              <option value="" disabled>
                — select a CA —
              </option>
              {cas.map((ca) => (
                <option key={ca.id} value={ca.id}>
                  {ca.display_name || ca.name || ca.id}
                  {ca.type === "external" ? " (external)" : ""}
                </option>
              ))}
            </Select>
          </label>
          {!casQuery.isLoading && cas.length === 0 ? (
            <p className="text-xs text-state-attn">
              No CAs exist yet. Create one on the{" "}
              <button
                type="button"
                className="underline"
                onClick={() => navigate("/cas")}
              >
                Certificate Authorities
              </button>{" "}
              page first.
            </p>
          ) : null}
        </div>
      ),
    },
    {
      id: "template",
      title: "Template",
      validate: () =>
        templateId ? null : "Choose a policy template to continue.",
      render: () => (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            The template governs key usage, algorithm allowlist, and validity
            window for this certificate.
          </p>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Template</span>
            <Select
              aria-label="Issuance template"
              value={templateId}
              onChange={(e) => setTemplateId(e.target.value)}
            >
              <option value="" disabled>
                — select a template —
              </option>
              {templates.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.display_name || t.name}
                </option>
              ))}
            </Select>
          </label>
          {!templatesQuery.isLoading && templates.length === 0 ? (
            <p className="text-xs text-state-attn">
              No templates exist yet. Create one on the{" "}
              <button
                type="button"
                className="underline"
                onClick={() => navigate("/templates")}
              >
                Templates
              </button>{" "}
              page first.
            </p>
          ) : null}
        </div>
      ),
    },
    {
      id: "subject",
      title: "Subject & SANs",
      validate: () =>
        commonName.trim()
          ? validateSans(sans, selectedTemplate)
          : "Enter a subject common name to continue.",
      render: () => (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            These describe the certificate you intend to request. They shape the
            CSR you'll provide in the next step — the hub only ever signs a CSR
            you already hold the private key for.
          </p>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Common name</span>
            <Input
              aria-label="Subject common name"
              value={commonName}
              onChange={(e) => setCommonName(e.target.value)}
              placeholder="api.example.com"
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>
              SANs <span className="text-muted-foreground">(comma-separated)</span>
            </span>
            <Input
              aria-label="Subject alternative names"
              value={sansText}
              onChange={(e) => setSansText(e.target.value)}
              placeholder="api.example.com, api-internal.example.com"
            />
          </label>
        </div>
      ),
    },
    {
      id: "key-or-csr",
      title: "Key or CSR",
      validate: () => {
        if (!keyMode) {
          return "Choose whether you already have a CSR or need to generate one.";
        }
        const trimmed = csrPem.trim();
        if (!trimmed) return "Paste the CSR PEM to continue.";
        if (!trimmed.includes("BEGIN CERTIFICATE REQUEST")) {
          return "That doesn't look like a PEM-encoded CSR.";
        }
        return null;
      },
      render: () => (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Private key material never leaves your machine — the hub only ever
            receives a certificate signing request.
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            <button
              type="button"
              aria-label="I already have a CSR"
              onClick={() => setKeyMode("existing")}
              className={`rounded-2xl border p-4 text-left transition ${
                keyMode === "existing"
                  ? "border-primary/50 bg-primary/10"
                  : "border-border bg-foreground/[0.02] hover:border-primary/40"
              }`}
            >
              <div className="font-semibold text-foreground">I have a CSR</div>
              <p className="mt-1 text-xs text-muted-foreground">
                Paste a CSR you already generated for this key.
              </p>
            </button>
            <button
              type="button"
              aria-label="Generate a new key"
              onClick={() => setKeyMode("generate")}
              className={`rounded-2xl border p-4 text-left transition ${
                keyMode === "generate"
                  ? "border-primary/50 bg-primary/10"
                  : "border-border bg-foreground/[0.02] hover:border-primary/40"
              }`}
            >
              <div className="font-semibold text-foreground">
                Generate a new key
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                Run a local command to create a key + CSR, then paste the CSR
                here.
              </p>
            </button>
          </div>
          {keyMode === "generate" ? (
            <pre className="overflow-x-auto rounded-xl bg-card p-3 text-xs text-foreground" {...scrollableProps}>
              {buildCsrHint(commonName, sans)}
            </pre>
          ) : null}
          {keyMode ? (
            <label className="block space-y-1 text-sm text-foreground">
              <span>CSR PEM</span>
              <Textarea
                aria-label="CSR PEM"
                value={csrPem}
                onChange={(e) => setCsrPem(e.target.value)}
                rows={6}
                placeholder="-----BEGIN CERTIFICATE REQUEST-----"
              />
            </label>
          ) : null}
        </div>
      ),
    },
  ];

  if (result) {
    return (
      <div className="p-6 space-y-6">
        <PageHeader
          eyebrow="Issuance"
          title={
            result.kind === "issued"
              ? "Certificate issued"
              : "Approval requested"
          }
          description={
            result.kind === "issued"
              ? "The certificate is in inventory and ready to download."
              : "Submitted for approval — it will be issued once approved."
          }
        />
        <Panel>
          {result.kind === "issued" ? (
            <div className="space-y-3 text-sm">
              <p className="text-foreground">
                {result.cert.common_name || result.cert.fingerprint_sha256} is
                now in inventory.
              </p>
              <p className="font-mono text-xs text-muted-foreground break-all">
                {result.cert.fingerprint_sha256}
              </p>
              <div className="flex flex-wrap gap-2 pt-2">
                <Button
                  tone="primary"
                  onClick={() => void downloadCert(result.cert)}
                >
                  Download certificate
                </Button>
                <Button
                  onClick={() =>
                    navigate(`/certificates/${result.cert.fingerprint_sha256}`)
                  }
                >
                  View in inventory
                </Button>
                <Button onClick={() => navigate("/targets/setup")}>
                  Deploy to a target
                </Button>
                <Button onClick={() => navigate("/targets/renewal-policy")}>
                  Set up renewal
                </Button>
                <Button onClick={reset}>Issue another</Button>
              </div>
              {downloadError ? (
                <p className="text-xs text-state-over">{downloadError}</p>
              ) : null}
            </div>
          ) : (
            <div className="space-y-3 text-sm">
              <p className="text-foreground">{result.message}</p>
              <p className="text-foreground">
                Waiting for approval from: {result.approvers.join(", ")}.
              </p>
              <p className="text-xs text-muted-foreground">
                You cannot approve your own request; another person with one of
                these roles must.
              </p>
              <p className="text-xs text-muted-foreground">
                Approval ID: {result.approvalId}
              </p>
              <div className="flex flex-wrap gap-2 pt-2">
                <Button tone="primary" onClick={() => navigate("/inbox")}>
                  View approvals
                </Button>
                <Button onClick={reset}>Issue another</Button>
              </div>
            </div>
          )}
        </Panel>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Issuance"
        title="Issue certificate"
        description="A guided, validated walk from CA to a downloadable certificate."
      />
      {!canManage ? (
        <StateMessage
          title="Read-only access"
          message="Your role can view certificates but not issue new ones."
        />
      ) : (
        <Panel>
          <Wizard
            steps={steps}
            onComplete={submit}
            onCancel={() =>
              navigate(isRequesterOnly(authz.data?.role) ? "/my-requests" : "/certificates")
            }
            summary={() => (
              <div className="space-y-3 text-sm">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <div className="text-muted-foreground">CA</div>
                    <div className="text-foreground">
                      {selectedCa?.display_name || selectedCa?.name || caId}
                    </div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Template</div>
                    <div className="text-foreground">
                      {selectedTemplate?.display_name ||
                        selectedTemplate?.name ||
                        templateId}
                    </div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Common name</div>
                    <div className="text-foreground">{commonName}</div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">SANs</div>
                    <div className="text-foreground">
                      {sans.length ? sans.join(", ") : "—"}
                    </div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Key source</div>
                    <div className="text-foreground">
                      {keyMode === "generate"
                        ? "Generated locally"
                        : "Existing CSR"}
                    </div>
                  </div>
                </div>
                {issueError ? (
                  <div role="alert" className="text-xs text-state-over">
                    {violation ? (
                      <dl className="space-y-0.5">
                        <div>
                          <dt className="inline font-semibold">Policy: </dt>
                          <dd className="inline">{violation.policy}</dd>
                        </div>
                        <div>
                          <dt className="inline font-semibold">Rule: </dt>
                          <dd className="inline">{violation.rule}</dd>
                        </div>
                        <div>
                          <dt className="inline font-semibold">Observed: </dt>
                          <dd className="inline">{violation.detail}</dd>
                        </div>
                      </dl>
                    ) : (
                      issueError
                    )}
                  </div>
                ) : null}
              </div>
            )}
          />
        </Panel>
      )}
    </div>
  );
}
