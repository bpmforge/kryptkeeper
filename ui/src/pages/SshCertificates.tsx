import { useMemo, useState } from "react";
import { scrollableProps } from "../lib/scrollable";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api, fetchJSON } from "../lib/api";
import { extractList } from "../lib/models";
import type { SSHPolicy, TemplateRecord } from "../lib/models";
import {
  Badge,
  Button,
  Input,
  Panel,
  Select,
  StateMessage,
  Textarea,
  formatDateTime,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";

type CertType = "user" | "host";
type SshCa = { authority_line: string; authority_fingerprint: string };
type SshCertRecord = {
  serial: string;
  cert_type: CertType;
  key_id: string;
  principals: string[];
  valid_after: string;
  valid_before: string;
  subject_fingerprint: string;
  authority_fingerprint: string;
  certificate_line: string;
  tenant: string;
  created_at: string;
  template_id?: string;
};
type IssueBody = {
  template_id: string;
  public_key: string;
  cert_type: CertType;
  key_id: string;
  principals: string[];
  ttl_hours: number;
};
type IssueResponse =
  | { data: SshCertRecord }
  | { status: "pending_approval"; approval_id: string; message: string };
type PendingRow = { templateName: string; keyId: string; approvalId: string };

const PUBLIC_KEY_RE =
  /^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) \S+/;
const USER_CEILING_H = 24;
const HOST_CEILING_H = 720;

function globMatch(pattern: string, value: string): boolean {
  const re = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${re}$`).test(value);
}

function ttlCeiling(policy: SSHPolicy, certType: CertType): number {
  return Math.min(
    policy.max_ttl_hours,
    certType === "user" ? USER_CEILING_H : HOST_CEILING_H,
  );
}

function validateIssue(
  policy: SSHPolicy,
  certType: CertType,
  publicKey: string,
  principals: string[],
  ttl: number,
): string | null {
  if (!PUBLIC_KEY_RE.test(publicKey.trim())) {
    return "Public key must be an authorized_keys line such as ssh-ed25519 AAAA...";
  }
  if (principals.length === 0) return "Enter at least one principal.";
  if (certType === "user") {
    const allowed = policy.allowed_principals ?? [];
    const bad = principals.find((p) => !allowed.includes(p));
    if (bad !== undefined) {
      return `Principal "${bad}" is not allowed by this template.`;
    }
  } else {
    const patterns = policy.host_patterns ?? [];
    const bad = principals.find((p) => !patterns.some((g) => globMatch(g, p)));
    if (bad !== undefined) {
      return `Host "${bad}" does not match this template's host patterns.`;
    }
  }
  const ceiling = ttlCeiling(policy, certType);
  if (!(ttl > 0) || ttl > ceiling) {
    return `TTL must be greater than 0 and at most ${ceiling} hours.`;
  }
  return null;
}

function CaPanel() {
  const [copied, setCopied] = useState(false);
  const q = useQuery({
    queryKey: ["ssh-ca"],
    queryFn: () => fetchJSON<SshCa>("/ssh/ca"),
  });
  return (
    <Panel title="SSH CA" subtitle="Trust this public key in sshd (TrustedUserCAKeys / @cert-authority)">
      {q.isError ? (
        <StateMessage
          tone="error"
          title="SSH CA not available"
          message={q.error instanceof Error ? q.error.message : "Request failed."}
        />
      ) : !q.data ? (
        <StateMessage title="Loading" message="Fetching the SSH CA…" />
      ) : (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground">
            Fingerprint: <span className="font-mono">{q.data.authority_fingerprint}</span>
          </p>
          <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-lg bg-background/60 p-2 text-xs" {...scrollableProps}>
            {q.data.authority_line}
          </pre>
          <Button
            onClick={() => {
              void navigator.clipboard.writeText(q.data.authority_line).then(() => setCopied(true));
            }}
          >
            {copied ? "Copied" : "Copy CA public key"}
          </Button>
        </div>
      )}
    </Panel>
  );
}

function IssuePanel({
  templates,
  onPending,
}: {
  templates: TemplateRecord[];
  onPending: (row: PendingRow) => void;
}) {
  const qc = useQueryClient();
  const [templateId, setTemplateId] = useState(templates[0]?.id ?? "");
  const template = templates.find((t) => t.id === templateId) ?? templates[0];
  const policy = template?.ssh_policy;
  const [certType, setCertType] = useState<CertType | "">("");
  const effectiveType: CertType = (certType && policy?.cert_types.includes(certType)
    ? certType
    : policy?.cert_types[0]) ?? "user";
  const [keyId, setKeyId] = useState("");
  const [principalsText, setPrincipalsText] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [ttl, setTtl] = useState("1");
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<SshCertRecord | null>(null);
  const [pendingId, setPendingId] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const mutation = useMutation({
    mutationFn: (body: IssueBody) =>
      fetchJSON<IssueResponse>("/ssh/certificates", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: (res, body) => {
      setCopied(false);
      if ("status" in res && res.status === "pending_approval") {
        setIssued(null);
        setPendingId(res.approval_id);
        onPending({
          templateName: template?.display_name || template?.name || body.template_id,
          keyId: body.key_id,
          approvalId: res.approval_id,
        });
        return;
      }
      if ("data" in res) {
        setPendingId(null);
        setIssued(res.data);
        void qc.invalidateQueries({ queryKey: ["ssh-certs"] });
      }
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Issuance failed."),
  });

  if (!template || !policy) {
    return (
      <Panel title="Issue certificate">
        <StateMessage
          title="No SSH templates"
          message="Create an active template with an ssh_policy to issue SSH certificates."
        />
      </Panel>
    );
  }
  const ceiling = ttlCeiling(policy, effectiveType);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!template || !policy) return;
    const principals = principalsText.split(",").map((p) => p.trim()).filter(Boolean);
    const ttlHours = Number(ttl);
    const msg = validateIssue(policy, effectiveType, publicKey, principals, ttlHours);
    setError(msg);
    if (msg) return;
    mutation.mutate({
      template_id: template.id,
      public_key: publicKey.trim(),
      cert_type: effectiveType,
      key_id: keyId.trim(),
      principals,
      ttl_hours: ttlHours,
    });
  }

  return (
    <Panel title="Issue certificate" subtitle="Short-lived user or host certificate from a template">
      <form onSubmit={submit} className="space-y-3" noValidate>
        <div>
          <label htmlFor="ssh-template" className="text-xs text-muted-foreground">Template</label>
          <Select id="ssh-template" value={template.id} onChange={(e) => setTemplateId(e.target.value)}>
            {templates.map((t) => (
              <option key={t.id} value={t.id}>{t.display_name || t.name}</option>
            ))}
          </Select>
        </div>
        <fieldset>
          <legend className="text-xs text-muted-foreground">Certificate type</legend>
          <div className="flex gap-4">
            {policy.cert_types.map((t) => (
              <label key={t} className="flex items-center gap-1 text-sm">
                <input
                  type="radio"
                  name="ssh-cert-type"
                  value={t}
                  checked={effectiveType === t}
                  onChange={() => setCertType(t)}
                />
                {t}
              </label>
            ))}
          </div>
        </fieldset>
        <div>
          <label htmlFor="ssh-key-id" className="text-xs text-muted-foreground">Key ID</label>
          <Input id="ssh-key-id" value={keyId} onChange={(e) => setKeyId(e.target.value)} required />
        </div>
        <div>
          <label htmlFor="ssh-principals" className="text-xs text-muted-foreground">Principals (comma separated)</label>
          <Input id="ssh-principals" value={principalsText} onChange={(e) => setPrincipalsText(e.target.value)} />
        </div>
        <div>
          <label htmlFor="ssh-public-key" className="text-xs text-muted-foreground">Public key (authorized_keys line)</label>
          <Textarea id="ssh-public-key" rows={3} value={publicKey} onChange={(e) => setPublicKey(e.target.value)} />
        </div>
        <div>
          <label htmlFor="ssh-ttl" className="text-xs text-muted-foreground">TTL hours</label>
          <Input
            id="ssh-ttl"
            type="number"
            value={ttl}
            min={0}
            step="any"
            aria-describedby="ssh-ttl-help"
            onChange={(e) => setTtl(e.target.value)}
          />
          <p id="ssh-ttl-help" className="mt-1 text-xs text-muted-foreground">Maximum {ceiling} hours.</p>
        </div>
        {error ? <p role="alert" className="text-sm text-state-over">{error}</p> : null}
        <Button type="submit" tone="primary" disabled={mutation.isPending}>Issue certificate</Button>
      </form>

      {issued ? (
        <div className="mt-3 space-y-2">
          <p className="text-sm text-state-auto">Issued certificate serial {issued.serial}.</p>
          <Textarea aria-label="Issued certificate" readOnly rows={4} value={issued.certificate_line} />
          <Button
            onClick={() => {
              void navigator.clipboard.writeText(issued.certificate_line).then(() => setCopied(true));
            }}
          >
            {copied ? "Copied" : "Copy certificate"}
          </Button>
        </div>
      ) : null}
      {pendingId ? (
        <div className="mt-3 space-y-1">
          <Badge tone="warning">Pending approval</Badge>
          <p className="text-sm">Approval ID: <span className="font-mono">{pendingId}</span></p>
          <p className="text-sm">
            <Link className="underline" to="/inbox">Approvals inbox</Link>
          </p>
        </div>
      ) : null}
    </Panel>
  );
}

function IssuedList({ templateNames }: { templateNames: Record<string, string> }) {
  const [now] = useState(() => Date.now());
  const q = useQuery({
    queryKey: ["ssh-certs"],
    queryFn: () => fetchJSON<{ data: SshCertRecord[] }>("/ssh/certificates"),
  });
  const rows = useMemo(
    () => [...(q.data?.data ?? [])].sort((a, b) => b.created_at.localeCompare(a.created_at)),
    [q.data],
  );
  return (
    <Panel title="Issued certificates">
      {q.isError ? (
        <StateMessage tone="error" title="Could not load certificates" message={q.error instanceof Error ? q.error.message : "Request failed."} />
      ) : !q.data ? (
        <StateMessage title="Loading" message="Fetching issued certificates…" />
      ) : rows.length === 0 ? (
        <StateMessage title="No SSH certificates issued yet" message="Issued certificates appear here newest first." />
      ) : (
        <div className="overflow-x-auto" {...scrollableProps}>
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Issued SSH certificates</caption>
            <thead>
              <tr>
                {["Serial", "Type", "Key ID", "Principals", "Valid until", "Template", "Status"].map((h) => (
                  <th key={h} scope="col" className="px-2 py-1 text-xs text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.serial}>
                  <td className="px-2 py-1 font-mono">{c.serial}</td>
                  <td className="px-2 py-1">{c.cert_type}</td>
                  <td className="px-2 py-1">{c.key_id}</td>
                  <td className="px-2 py-1">{c.principals.join(", ")}</td>
                  <td className="px-2 py-1 whitespace-nowrap">{formatDateTime(c.valid_before)}</td>
                  <td className="px-2 py-1">
                    {c.template_id ? (
                      templateNames[c.template_id] ? (
                        templateNames[c.template_id]
                      ) : (
                        <span className="font-mono text-xs text-muted-foreground" title={c.template_id}>
                          {c.template_id}
                        </span>
                      )
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="px-2 py-1">
                    {new Date(c.valid_before).getTime() > now ? (
                      <Badge tone="success">Active</Badge>
                    ) : (
                      <Badge tone="danger">Expired</Badge>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

export default function SshCertificates() {
  const [pending, setPending] = useState<PendingRow[]>([]);
  const authz = useQuery({ queryKey: ["authz-check"], queryFn: () => api.authzCheck() });
  const tpls = useQuery({ queryKey: ["templates", "ssh"], queryFn: () => api.templates({ limit: 200 }) });
  const role = authz.data?.role;
  const readOnly = role === "viewer" || role === "mcp-agent";
  const sshTemplates = useMemo(
    () => extractList<TemplateRecord>(tpls.data?.data).filter((t) => t.active && t.ssh_policy),
    [tpls.data],
  );

  const templateNames = useMemo(
    () =>
      Object.fromEntries(
        extractList<TemplateRecord>(tpls.data?.data).map((t) => [t.id, t.name]),
      ),
    [tpls.data],
  );

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Estate"
        title="SSH certificates"
        description="Issue short-lived SSH user and host certificates from a template and trust the SSH CA."
      />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 [&>*]:min-w-0">
        <CaPanel />
        {readOnly ? (
          <Panel title="Issue certificate">
            <p className="text-sm text-muted-foreground">Your role is read-only and cannot issue SSH certificates.</p>
          </Panel>
        ) : tpls.data ? (
          <IssuePanel
            key={sshTemplates.map((t) => t.id).join(",")}
            templates={sshTemplates}
            onPending={(row) => setPending((p) => [row, ...p])}
          />
        ) : (
          <Panel title="Issue certificate"><StateMessage title="Loading" message="Fetching templates…" /></Panel>
        )}
      </div>
      {pending.length > 0 ? (
        <Panel title="Pending approval">
          <div className="overflow-x-auto" {...scrollableProps}>
            <table className="w-full text-left text-sm">
              <caption className="sr-only">SSH certificate requests pending approval</caption>
              <thead>
                <tr>
                  {["Template", "Key ID", "Approval ID"].map((h) => (
                    <th key={h} scope="col" className="px-2 py-1 text-xs text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {pending.map((p) => (
                  <tr key={p.approvalId}>
                    <td className="px-2 py-1">{p.templateName}</td>
                    <td className="px-2 py-1">{p.keyId}</td>
                    <td className="px-2 py-1 font-mono">{p.approvalId}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : null}
      <IssuedList templateNames={templateNames} />
    </div>
  );
}
