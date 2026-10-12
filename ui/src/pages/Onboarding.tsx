import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import type {
  CaRecord,
  CertificateRecord,
  TemplateRecord,
} from "../lib/models";
import { Button, Input, Panel, Select, Textarea } from "../components/ui";
import { savePemFile } from "../lib/utils";
import { Wizard, type WizardStepDef } from "../components/Wizard";

type Mode = "agent" | "agentless" | null;

// The wizard's algorithm choices mirror CAs.tsx's real create-CA dialog
// exactly, not the PQC-capable set ca.Engine itself supports -- the HTTP
// create-CA handler's parseAlgorithm only recognizes ECDSA/RSA strings
// today (verified by reading internal/bootstrap/ca_engine_provider.go
// before writing this), so offering an ML-DSA/hybrid option here would
// 400 on submit. Same limitation the existing CA page already has; not a
// regression introduced by this ticket.
const ALGORITHM_OPTIONS = [
  { value: "ECDSA-P256", label: "ECDSA P-256" },
  { value: "ECDSA-P384", label: "ECDSA P-384" },
  { value: "RSA-2048", label: "RSA 2048" },
  { value: "RSA-4096", label: "RSA 4096" },
];

const CSR_HINT = `openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \\
  -nodes -keyout onboarding.key -out onboarding.csr \\
  -subj "/CN=onboarding-test.example.com"`;

export default function Onboarding({ onComplete }: { onComplete: () => void }) {
  const navigate = useNavigate();

  const [caForm, setCaForm] = useState({
    subjectCn: "",
    subjectOrg: "",
    algorithm: "ECDSA-P256",
    validityStr: "10y",
  });
  const [createdCa, setCreatedCa] = useState<CaRecord | null>(null);
  const caMutation = useMutation({
    mutationFn: () =>
      api.createCa({
        type: "root",
        subject_cn: caForm.subjectCn.trim(),
        subject_org: caForm.subjectOrg.trim(),
        algorithm: caForm.algorithm,
        validity: caForm.validityStr.trim(),
      }),
    onSuccess: (res) => setCreatedCa(res.data),
  });

  const [templateForm, setTemplateForm] = useState({
    name: "",
    validityPeriod: "90d",
  });
  const [createdTemplate, setCreatedTemplate] = useState<TemplateRecord | null>(
    null,
  );
  const templateMutation = useMutation({
    mutationFn: () =>
      api.createTemplate({
        name: templateForm.name.trim(),
        display_name: templateForm.name.trim(),
        key_usage: ["digitalSignature", "keyEncipherment"],
        extended_key_usage: ["serverAuth"],
        allowed_algorithms: ["ECDSA", "RSA"],
        validity_period: templateForm.validityPeriod.trim(),
        auto_enroll: false,
        active: true,
      }),
    onSuccess: (res) => setCreatedTemplate(res.data),
  });

  const [csrPem, setCsrPem] = useState("");
  const [issuedCert, setIssuedCert] = useState<CertificateRecord | null>(null);
  const issueMutation = useMutation({
    mutationFn: () =>
      api.issueCertificate({
        ca_id: createdCa?.id,
        template_id: createdTemplate?.id,
        csr_pem: csrPem.trim(),
      }),
    onSuccess: (res) => setIssuedCert(res.data),
  });

  const [mode, setMode] = useState<Mode>(null);

  // S-69: the issue response carries no PEM field, so the old cert_pem gate
  // made this button a silent no-op outside MSW. Fetch from the download
  // endpoint instead.
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const downloadCert = async () => {
    if (!issuedCert) return;
    setDownloadError(null);
    try {
      const pem = await api.downloadCertificatePem(
        issuedCert.fingerprint_sha256,
      );
      savePemFile(
        `${issuedCert.common_name || issuedCert.fingerprint_sha256}.pem`,
        pem,
      );
    } catch (e) {
      setDownloadError(
        e instanceof Error ? e.message : "Certificate download failed.",
      );
    }
  };

  const steps: WizardStepDef[] = [
    {
      id: "ca",
      title: "Root CA",
      validate: () => (createdCa ? null : "Create the root CA to continue."),
      render: () => (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Every certificate this hub issues traces back to a trust anchor.
            Create your first root CA to get started.
          </p>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Subject common name</span>
            <Input
              value={caForm.subjectCn}
              onChange={(e) =>
                setCaForm((f) => ({ ...f, subjectCn: e.target.value }))
              }
              placeholder="Acme Corp Root CA"
              disabled={!!createdCa}
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Organization</span>
            <Input
              value={caForm.subjectOrg}
              onChange={(e) =>
                setCaForm((f) => ({ ...f, subjectOrg: e.target.value }))
              }
              placeholder="Acme Corp"
              disabled={!!createdCa}
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Algorithm</span>
            <Select
              value={caForm.algorithm}
              onChange={(e) =>
                setCaForm((f) => ({ ...f, algorithm: e.target.value }))
              }
              disabled={!!createdCa}
            >
              {ALGORITHM_OPTIONS.map((a) => (
                <option key={a.value} value={a.value}>
                  {a.label}
                </option>
              ))}
            </Select>
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Validity</span>
            <Input
              value={caForm.validityStr}
              onChange={(e) =>
                setCaForm((f) => ({ ...f, validityStr: e.target.value }))
              }
              placeholder="10y"
              disabled={!!createdCa}
            />
          </label>
          <Button
            tone="primary"
            onClick={() => caMutation.mutate()}
            disabled={
              caMutation.isPending || !!createdCa || !caForm.subjectCn.trim()
            }
          >
            {createdCa ? "Root CA created" : "Create root CA"}
          </Button>
          {caMutation.isError && (
            <p role="alert" className="text-xs text-state-over">
              {caMutation.error instanceof Error
                ? caMutation.error.message
                : "Failed to create the CA."}
            </p>
          )}
          {createdCa && (
            <p className="text-xs text-state-auto">
              Created {createdCa.display_name || createdCa.name || createdCa.id}
            </p>
          )}
        </div>
      ),
    },
    {
      id: "template",
      title: "Template",
      validate: () =>
        createdTemplate ? null : "Create a policy template to continue.",
      render: () => (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            A template is a reusable issuance policy — key usage, algorithm
            allowlist, and validity window applied to every certificate issued
            under it.
          </p>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Name</span>
            <Input
              value={templateForm.name}
              onChange={(e) =>
                setTemplateForm((f) => ({ ...f, name: e.target.value }))
              }
              placeholder="tls-server-default"
              disabled={!!createdTemplate}
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Validity period</span>
            <Input
              value={templateForm.validityPeriod}
              onChange={(e) =>
                setTemplateForm((f) => ({
                  ...f,
                  validityPeriod: e.target.value,
                }))
              }
              placeholder="90d"
              disabled={!!createdTemplate}
            />
          </label>
          <Button
            tone="primary"
            onClick={() => templateMutation.mutate()}
            disabled={
              templateMutation.isPending ||
              !!createdTemplate ||
              !templateForm.name.trim()
            }
          >
            {createdTemplate ? "Template created" : "Create template"}
          </Button>
          {templateMutation.isError && (
            <p role="alert" className="text-xs text-state-over">
              {templateMutation.error instanceof Error
                ? templateMutation.error.message
                : "Failed to create the template."}
            </p>
          )}
          {createdTemplate && (
            <p className="text-xs text-state-auto">
              Created {createdTemplate.display_name || createdTemplate.name}
            </p>
          )}
        </div>
      ),
    },
    {
      id: "issue",
      title: "First certificate",
      validate: () =>
        issuedCert ? null : "Issue your first certificate to continue.",
      render: () => (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Issuance signs a certificate signing request (CSR) you already hold
            the private key for — the hub never generates or sees your private
            key. If you don't have one handy, generate a throwaway one to try
            the flow:
          </p>
          <pre className="overflow-x-auto rounded-xl bg-card p-3 text-xs text-foreground">
            {CSR_HINT}
          </pre>
          <label className="block space-y-1 text-sm text-foreground">
            <span>CSR PEM</span>
            <Textarea
              value={csrPem}
              onChange={(e) => setCsrPem(e.target.value)}
              rows={6}
              placeholder="-----BEGIN CERTIFICATE REQUEST-----"
              disabled={!!issuedCert}
            />
          </label>
          <Button
            tone="primary"
            onClick={() => issueMutation.mutate()}
            disabled={issueMutation.isPending || !!issuedCert || !csrPem.trim()}
          >
            {issuedCert ? "Certificate issued" : "Issue certificate"}
          </Button>
          {issueMutation.isError && (
            <p role="alert" className="text-xs text-state-over">
              {issueMutation.error instanceof Error
                ? issueMutation.error.message
                : "Failed to issue the certificate."}
            </p>
          )}
          {issuedCert && (
            <div className="space-y-2 text-xs">
              <p className="text-state-auto">
                Issued {issuedCert.common_name || issuedCert.fingerprint_sha256}
              </p>
              <Button onClick={() => void downloadCert()}>
                Download certificate
              </Button>
              {downloadError ? (
                <p className="text-state-over">{downloadError}</p>
              ) : null}
            </div>
          )}
        </div>
      ),
    },
    {
      id: "mode",
      title: "Discovery & install",
      validate: () => (mode ? null : "Choose how this hub manages targets."),
      render: () => (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Choose how hosts get their certificates deployed and renewed. You
            can mix both modes across your fleet later.
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            <button
              type="button"
              aria-label="Choose agent mode"
              onClick={() => setMode("agent")}
              className={`rounded-2xl border p-4 text-left transition ${
                mode === "agent"
                  ? "border-primary/50 bg-primary/10"
                  : "border-border bg-foreground/[0.02] hover:border-primary/40"
              }`}
            >
              <div className="font-semibold text-foreground">Agent</div>
              <p className="mt-1 text-xs text-muted-foreground">
                A lightweight agent runs on the host, discovering and
                auto-renewing certificates with no inbound access required.
              </p>
            </button>
            <button
              type="button"
              aria-label="Choose agentless mode"
              onClick={() => setMode("agentless")}
              className={`rounded-2xl border p-4 text-left transition ${
                mode === "agentless"
                  ? "border-primary/50 bg-primary/10"
                  : "border-border bg-foreground/[0.02] hover:border-primary/40"
              }`}
            >
              <div className="font-semibold text-foreground">Agentless</div>
              <p className="mt-1 text-xs text-muted-foreground">
                Declare a target's host and how it should be discovered,
                renewed, and installed — no software runs on the target.
              </p>
            </button>
          </div>
          {mode === "agent" && (
            <p className="text-xs text-muted-foreground">
              On Finish, you'll land on the Agents page to install and pair your
              first agent.
            </p>
          )}
          {mode === "agentless" && (
            <p className="text-xs text-muted-foreground">
              On Finish, you'll land on Target Setup — a guided wizard that
              walks you through declaring your first agentless target
              (platform, connection mode, credentials).
            </p>
          )}
        </div>
      ),
    },
  ];

  const finish = () => {
    onComplete();
    // Each mode lands on its actual next step: agents installs a collector,
    // agentless declares a target in the Target Setup wizard.
    navigate(mode === "agentless" ? "/targets/setup" : "/agents");
  };

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-3xl font-semibold text-foreground">
          Welcome to Kryptkeeper
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Let's get your first certificate issued.
        </p>
      </div>
      <Panel>
        <Wizard steps={steps} onComplete={finish} />
      </Panel>
    </div>
  );
}
