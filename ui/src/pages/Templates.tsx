import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import {
  Badge,
  Button,
  Dialog,
  Input,
  Panel,
  Select,
  StateMessage,
} from "../components/ops-ui";
import { EmptyState } from "../components/EmptyState";
import { PolicyDraftDialog } from "../components/PolicyDraftDialog";
import { PageHeader } from "../components/PageHeader";
import { extractList } from "../lib/models";
import { formatDateTime } from "../components/ui";
import { formatValidityPeriod } from "../lib/utils";
import type {
  NamePolicy,
  SSHPolicy,
  TemplateRecord,
  TemplateRevision,
} from "../lib/models";

const EKU_LABELS: Record<string, string> = {
  serverAuth: "Server auth",
  clientAuth: "Client auth",
  codeSigning: "Code signing",
  emailProtection: "Email protection",
  timeStamping: "Time stamping",
  ocspSigning: "OCSP signing",
  anyExtendedKeyUsage: "Any",
};

function ekuLabel(eku: string): string {
  return EKU_LABELS[eku] ?? eku;
}

const BUILT_IN_ROLES = [
  "pki-admin",
  "pki-operator",
  "approver",
  "viewer",
  "auditor",
  "service-account",
];

const showValue = (v: unknown) =>
  typeof v === "string" ? v : JSON.stringify(v);

type TemplateForm = {
  name: string;
  displayName: string;
  keyUsage: string;
  extendedKeyUsage: string;
  allowedAlgorithms: string;
  validityPeriod: string;
  autoEnroll: boolean;
  enrolleeType: "machine" | "user";
  active: boolean;
  requireApproval: boolean;
  enrollRoles: string;
  sshEnabled: boolean;
  sshUser: boolean;
  sshHost: boolean;
  sshPrincipals: string;
  sshHostPatterns: string;
  sshMaxTtlHours: string;
  nameEnabled: boolean;
  nameSuffixes: string;
  nameDnsNames: string;
  nameAllowIp: boolean;
  nameAllowUri: boolean;
  nameUriPrefixes: string;
  nameCnMustBeSan: boolean;
};

const splitList = (v: string) =>
  v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

// The SSH CA signs only what a template's policy lists (A01S-4), so the
// editor sends no policy unless the section is switched on.
function sshPolicyFromForm(f: TemplateForm): SSHPolicy | undefined {
  if (!f.sshEnabled) return undefined;
  const certTypes: SSHPolicy["cert_types"] = [];
  if (f.sshUser) certTypes.push("user");
  if (f.sshHost) certTypes.push("host");
  return {
    cert_types: certTypes,
    ...(f.sshUser ? { allowed_principals: splitList(f.sshPrincipals) } : {}),
    ...(f.sshHost ? { host_patterns: splitList(f.sshHostPatterns) } : {}),
    max_ttl_hours: Number(f.sshMaxTtlHours),
  };
}

// A template with no name policy lets a requester name any host (SUP-A04-3),
// so the editor sends one only when the section is switched on.
function namePolicyFromForm(f: TemplateForm): NamePolicy | undefined {
  if (!f.nameEnabled) return undefined;
  return {
    allowed_dns_suffixes: splitList(f.nameSuffixes),
    allowed_dns_names: splitList(f.nameDnsNames),
    allow_ip_sans: f.nameAllowIp,
    allow_uri_sans: f.nameAllowUri,
    ...(f.nameAllowUri
      ? { allowed_uri_prefixes: splitList(f.nameUriPrefixes) }
      : {}),
    cn_must_be_san: f.nameCnMustBeSan,
  };
}

const emptyForm: TemplateForm = {
  name: "",
  displayName: "",
  keyUsage: "digitalSignature,keyEncipherment",
  extendedKeyUsage: "serverAuth",
  allowedAlgorithms: "ECDSA",
  validityPeriod: "90d",
  autoEnroll: false,
  enrolleeType: "machine",
  active: true,
  requireApproval: false,
  enrollRoles: "",
  sshEnabled: false,
  sshUser: true,
  sshHost: false,
  sshPrincipals: "",
  sshHostPatterns: "",
  sshMaxTtlHours: "8",
  nameEnabled: false,
  nameSuffixes: "",
  nameDnsNames: "",
  nameAllowIp: false,
  nameAllowUri: false,
  nameUriPrefixes: "",
  nameCnMustBeSan: false,
};

function formToPayload(f: TemplateForm) {
  return {
    name: f.name.trim(),
    display_name: f.displayName.trim() || f.name.trim(),
    key_usage: f.keyUsage
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    extended_key_usage: f.extendedKeyUsage
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    allowed_algorithms: f.allowedAlgorithms
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    validity_period: f.validityPeriod.trim(),
    auto_enroll: f.autoEnroll,
    enrollee_type: f.enrolleeType,
    active: f.active,
    require_approval: f.requireApproval,
    // pki-admin is the server's default approver set; sending it explicitly
    // keeps the stored template self-describing.
    approval_roles: f.requireApproval ? ["pki-admin"] : [],
    // PUT replaces the template: always send it or any edit wipes the roles.
    enrollment_permissions: { enroll: splitList(f.enrollRoles) },
    ssh_policy: sshPolicyFromForm(f),
    name_policy: namePolicyFromForm(f),
  };
}

export default function Templates() {
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draftOpen, setDraftOpen] = useState(false);
  const [dialog, setDialog] = useState<"create" | "edit" | "delete" | null>(
    null,
  );
  const [form, setForm] = useState<TemplateForm>(emptyForm);
  const [statusMessage, setStatusMessage] = useState<{
    tone: "success" | "error";
    title: string;
    message: string;
  } | null>(null);

  const templatesQuery = useQuery({
    queryKey: ["templates"],
    queryFn: () => api.templates({ limit: 50 }),
  });

  const templates: TemplateRecord[] = extractList<TemplateRecord>(
    templatesQuery.data?.data,
    ["items"],
  );
  // Nothing explicitly chosen (first load, or after a delete): show the first
  // template so the detail pane is never an empty half-page.
  const selected =
    (selectedId ? templates.find((t) => t.id === selectedId) : undefined) ??
    templates[0] ??
    null;

  const revisionsQuery = useQuery({
    queryKey: ["template-revisions", selected?.id, selected?.revision],
    queryFn: () => api.templateRevisions(selected!.id),
    enabled: !!selected,
    retry: false,
  });
  const revisions: TemplateRevision[] = [
    ...(revisionsQuery.data?.data ?? []),
  ].sort((a, b) => b.revision - a.revision);

  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ["templates"] });

  const createMutation = useMutation({
    mutationFn: () => api.createTemplate(formToPayload(form)),
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "Template created",
        message: "The template is ready for issuance.",
      });
      setDialog(null);
      await refresh();
    },
    onError: (e) =>
      setStatusMessage({
        tone: "error",
        title: "Create failed",
        message: e instanceof Error ? e.message : "Try again.",
      }),
  });

  const updateMutation = useMutation({
    mutationFn: () => {
      if (!selected) throw new Error("No template selected");
      // PUT replaces the whole template: carry over what this form does not
      // edit, or saving would wipe the OID (dropping the template from
      // Windows autoenrollment), minimum key size and renewal overlap.
      return api.updateTemplate(
        selected.id,
        {
          ...formToPayload(form),
          oid: selected.oid,
          min_key_size: selected.min_key_size,
          renewal_overlap: selected.renewal_overlap,
          approval_roles: form.requireApproval
            ? selected.approval_roles?.length
              ? selected.approval_roles
              : ["pki-admin"]
            : [],
        },
        selected.revision,
      );
    },
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "Template updated",
        message: "Changes saved.",
      });
      setDialog(null);
      await refresh();
    },
    onError: (e) => {
      const msg = e instanceof Error ? e.message : "Try again.";
      if (/if-match|412|precondition/i.test(msg)) {
        setStatusMessage({
          tone: "error",
          title: "Update failed",
          message:
            "This template changed since you opened it. Reload and retry.",
        });
        void refresh();
        return;
      }
      setStatusMessage({ tone: "error", title: "Update failed", message: msg });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => {
      if (!selected) throw new Error("No template selected");
      return api.deleteTemplate(selected.id);
    },
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "Template deleted",
        message: "",
      });
      setDialog(null);
      setSelectedId(null);
      await refresh();
    },
    onError: (e) =>
      setStatusMessage({
        tone: "error",
        title: "Delete failed",
        message: e instanceof Error ? e.message : "Try again.",
      }),
  });

  function openCreate() {
    setForm(emptyForm);
    setDialog("create");
    setStatusMessage(null);
  }

  function openEdit() {
    if (!selected) return;
    setForm({
      name: selected.name,
      displayName: selected.display_name,
      keyUsage: (selected.key_usage ?? []).join(","),
      extendedKeyUsage: (selected.extended_key_usage ?? []).join(","),
      allowedAlgorithms: (selected.allowed_algorithms ?? []).join(","),
      validityPeriod: selected.validity_period,
      autoEnroll: selected.auto_enroll,
      enrolleeType: selected.enrollee_type === "user" ? "user" : "machine",
      active: selected.active,
      requireApproval: selected.require_approval ?? false,
      enrollRoles: (selected.enrollment_permissions?.enroll ?? []).join(","),
      sshEnabled: !!selected.ssh_policy,
      sshUser: selected.ssh_policy?.cert_types.includes("user") ?? true,
      sshHost: selected.ssh_policy?.cert_types.includes("host") ?? false,
      sshPrincipals: (selected.ssh_policy?.allowed_principals ?? []).join(","),
      sshHostPatterns: (selected.ssh_policy?.host_patterns ?? []).join(","),
      sshMaxTtlHours: String(selected.ssh_policy?.max_ttl_hours ?? 8),
      nameEnabled: !!selected.name_policy,
      nameSuffixes: (selected.name_policy?.allowed_dns_suffixes ?? []).join(
        ",",
      ),
      nameDnsNames: (selected.name_policy?.allowed_dns_names ?? []).join(","),
      nameAllowIp: selected.name_policy?.allow_ip_sans ?? false,
      nameAllowUri: selected.name_policy?.allow_uri_sans ?? false,
      nameUriPrefixes: (selected.name_policy?.allowed_uri_prefixes ?? []).join(
        ",",
      ),
      nameCnMustBeSan: selected.name_policy?.cn_must_be_san ?? false,
    });
    setDialog("edit");
    setStatusMessage(null);
  }

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Policy"
        title="Certificate Templates"
        description="Define issuance policy: key usage, algorithms, and validity constraints."
        actions={
          <div className="flex gap-2">
            <Button tone="secondary" onClick={() => setDraftOpen(true)}>
              Draft policy from text
            </Button>
            <Button tone="primary" onClick={openCreate}>
              New template
            </Button>
          </div>
        }
      />

      <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <Panel title="Templates" subtitle="Click a template to inspect or edit">
          {templatesQuery.isLoading ? (
            <StateMessage title="Loading" message="Fetching templates…" />
          ) : null}
          {templatesQuery.error ? (
            <StateMessage
              tone="error"
              title="Unavailable"
              message="Try again shortly."
            />
          ) : null}
          <div className="overflow-hidden rounded-xl border border-border">
            <table className="min-w-full divide-y divide-border">
              <thead className="bg-background/80">
                <tr>
                  <th
                    scope="col"
                    className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                  >
                    Name
                  </th>
                  <th
                    scope="col"
                    className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                  >
                    Validity
                  </th>
                  <th
                    scope="col"
                    className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                  >
                    EKU
                  </th>
                  <th
                    scope="col"
                    className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                  >
                    Status
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border bg-background/40">
                {templates.map((t) => (
                  <tr
                    key={t.id}
                    className={`cursor-pointer transition hover:bg-card/60 ${selectedId === t.id ? "bg-card/80" : ""}`}
                    onClick={() => setSelectedId(t.id)}
                  >
                    <td className="px-4 py-3 text-sm text-foreground">
                      {t.display_name || t.name}
                    </td>
                    <td className="px-4 py-3 text-sm text-foreground">
                      {formatValidityPeriod(t.validity_period)}
                    </td>
                    <td className="px-4 py-3 text-sm text-foreground">
                      {(t.extended_key_usage ?? []).map(ekuLabel).join(", ")}
                    </td>
                    <td className="px-4 py-3">
                      <Badge tone={t.active ? "neutral" : "warning"}>
                        {t.active ? "active" : "inactive"}
                      </Badge>
                    </td>
                  </tr>
                ))}
                {templates.length === 0 && !templatesQuery.isLoading ? (
                  <tr>
                    <td colSpan={4} className="px-4 py-8">
                      <EmptyState
                        title="No templates"
                        description="Create one to start issuing certificates."
                        actionLabel="Create your first template"
                        onAction={openCreate}
                      />
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel
          title="Template detail"
          subtitle="Policy constraints and metadata"
        >
          {selected ? (
            <div className="space-y-4">
              <div>
                <h2 className="text-lg font-semibold text-foreground">
                  {selected.display_name || selected.name}
                </h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  {selected.id}
                </p>
              </div>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <div className="text-muted-foreground">Validity</div>
                  <div className="text-foreground">
                    {formatValidityPeriod(selected.validity_period)}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Issued</div>
                  <div className="text-foreground">{selected.issued_count}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Key usage</div>
                  <div className="text-foreground">
                    {(selected.key_usage ?? []).join(", ")}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">EKU</div>
                  <div className="text-foreground">
                    {(selected.extended_key_usage ?? []).map(ekuLabel).join(", ")}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Algorithms</div>
                  <div className="text-foreground">
                    {(selected.allowed_algorithms ?? []).join(", ")}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Auto-enroll</div>
                  <div className="text-foreground">
                    {selected.auto_enroll ? "Yes" : "No"}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">SSH certificates</div>
                  <div className="text-foreground">
                    {selected.ssh_policy
                      ? `${selected.ssh_policy.cert_types.join(" + ")}, max ${selected.ssh_policy.max_ttl_hours}h`
                      : "Not enabled"}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Name policy</div>
                  <div className="text-foreground">
                    {selected.name_policy
                      ? "Names restricted"
                      : "None — any names"}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Enrollment roles</div>
                  <div className="text-foreground">
                    {selected.enrollment_permissions?.enroll?.length
                      ? selected.enrollment_permissions.enroll.join(", ")
                      : "Any role"}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Issued to</div>
                  <div className="text-foreground">
                    {selected.enrollee_type === "user" ? "Users" : "Machines"}
                  </div>
                </div>
              </div>
              <div className="flex gap-2">
                <Button tone="primary" onClick={openEdit}>
                  Edit
                </Button>
                <Button
                  tone="danger"
                  onClick={() => {
                    setDialog("delete");
                    setStatusMessage(null);
                  }}
                >
                  Delete
                </Button>
              </div>
            </div>
          ) : (
            <StateMessage
              title="No template selected"
              message="Click a row to inspect."
            />
          )}
        </Panel>
      </div>

      {selected ? (
        <Panel
          title="Revision history"
          subtitle={`Current revision ${selected.revision}`}
        >
          {revisionsQuery.isError &&
          (revisionsQuery.error as { status?: number }).status === 503 ? (
            // The file-backed template store (APP_TEMPLATE_FILE, the compose
            // default) has no history; that is a configuration, not a fault.
            <StateMessage
              title="No revision history"
              message="This hub's template store does not keep revisions."
            />
          ) : revisionsQuery.isError ? (
            <StateMessage
              tone="error"
              title="History unavailable"
              message={
                revisionsQuery.error instanceof Error
                  ? revisionsQuery.error.message
                  : "Try again."
              }
            />
          ) : revisionsQuery.isLoading ? (
            <p role="status" className="text-sm text-muted-foreground">
              Loading history...
            </p>
          ) : (
            <ol className="space-y-4">
              {revisions.map((r) => (
                <li key={r.revision} data-testid="revision-item">
                  <h4 className="text-sm font-semibold text-foreground">
                    Revision {r.revision}{" "}
                    <span className="font-normal text-muted-foreground">
                      {formatDateTime(r.changed_at)}
                    </span>
                  </h4>
                  {r.changes?.length ? (
                    <table className="mt-2 min-w-full text-sm">
                      <thead>
                        <tr className="text-left text-muted-foreground">
                          <th className="pr-4">Field</th>
                          <th className="pr-4">Old</th>
                          <th>New</th>
                        </tr>
                      </thead>
                      <tbody>
                        {r.changes.map((c) => (
                          <tr key={c.field} data-testid="rev-change-row">
                            <td className="pr-4 font-mono">{c.field}</td>
                            <td className="pr-4">{showValue(c.old)}</td>
                            <td>{showValue(c.new)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <p className="text-sm text-muted-foreground">
                      Initial revision
                    </p>
                  )}
                </li>
              ))}
            </ol>
          )}
        </Panel>
      ) : null}

      {statusMessage ? (
        <StateMessage
          tone={statusMessage.tone}
          title={statusMessage.title}
          message={statusMessage.message}
        />
      ) : null}

      {/* Create / Edit dialog */}
      <Dialog
        open={dialog === "create" || dialog === "edit"}
        title={dialog === "create" ? "New template" : "Edit template"}
        description="Define issuance policy constraints."
        onClose={() => setDialog(null)}
        footer={
          <>
            <Button
              tone="primary"
              type="submit"
              form="template-form"
              disabled={createMutation.isPending || updateMutation.isPending}
            >
              {dialog === "create" ? "Create" : "Save changes"}
            </Button>
            <Button onClick={() => setDialog(null)}>Cancel</Button>
          </>
        }
      >
        <form
          id="template-form"
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (dialog === "create") {
              void createMutation.mutateAsync().catch(() => {
                /* surfaced inline below */
              });
            } else {
              void updateMutation.mutateAsync().catch(() => {
                /* surfaced inline below */
              });
            }
          }}
        >
          {(dialog === "create" && createMutation.isError) ||
          (dialog === "edit" && updateMutation.isError) ? (
            <StateMessage
              tone="error"
              title={
                dialog === "create" ? "Template not created" : "Update failed"
              }
              message={
                (
                  (dialog === "create"
                    ? createMutation.error
                    : updateMutation.error) as Error
                )?.message ?? ""
              }
            />
          ) : null}
          {dialog === "create" ? (
            <label className="block space-y-1 text-sm text-foreground">
              <span>
                Name <span className="text-muted-foreground">(identifier)</span>
              </span>
              <Input
                value={form.name}
                onChange={(e) =>
                  setForm((f) => ({ ...f, name: e.target.value }))
                }
                placeholder="tpl-tls"
                required
              />
            </label>
          ) : null}
          <label className="block space-y-1 text-sm text-foreground">
            <span>Display name</span>
            <Input
              value={form.displayName}
              onChange={(e) =>
                setForm((f) => ({ ...f, displayName: e.target.value }))
              }
              placeholder="TLS Server"
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>
              Validity period{" "}
              <span className="text-muted-foreground">(e.g. 90d, 1y)</span>
            </span>
            <Input
              value={form.validityPeriod}
              onChange={(e) =>
                setForm((f) => ({ ...f, validityPeriod: e.target.value }))
              }
              placeholder="90d"
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>
              Extended key usage{" "}
              <span className="text-muted-foreground">(comma-separated)</span>
            </span>
            <Input
              value={form.extendedKeyUsage}
              onChange={(e) =>
                setForm((f) => ({ ...f, extendedKeyUsage: e.target.value }))
              }
              placeholder="serverAuth"
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>
              Allowed algorithms{" "}
              <span className="text-muted-foreground">(comma-separated)</span>
            </span>
            <Input
              value={form.allowedAlgorithms}
              onChange={(e) =>
                setForm((f) => ({ ...f, allowedAlgorithms: e.target.value }))
              }
              placeholder="ECDSA"
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>
              Issued to{" "}
              <span className="text-muted-foreground">
                — Windows autoenrollment offers a template only to this kind of
                account
              </span>
            </span>
            <Select
              value={form.enrolleeType}
              onChange={(e) =>
                setForm((f) => ({
                  ...f,
                  enrolleeType: e.target.value === "user" ? "user" : "machine",
                }))
              }
            >
              <option value="machine">Machines (computer accounts)</option>
              <option value="user">Users</option>
            </Select>
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Status</span>
            <Select
              value={form.active ? "active" : "inactive"}
              onChange={(e) =>
                setForm((f) => ({ ...f, active: e.target.value === "active" }))
              }
            >
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </Select>
          </label>
          <div className="space-y-1 text-sm text-foreground">
            <label className="block space-y-1">
              <span>Roles allowed to enroll</span>
              <Input
                value={form.enrollRoles}
                onChange={(e) =>
                  setForm((f) => ({ ...f, enrollRoles: e.target.value }))
                }
                placeholder="pki-admin,pki-operator"
              />
            </label>
            <p className="text-xs text-muted-foreground">
              Leave empty to allow every role that may issue certificates.
              The list also applies to Windows enrollment (XCEP/WSTEP): once it
              is set, only protocol:wstep or protocol:wstep:&lt;host fqdn&gt;
              lets Windows clients enroll.
            </p>
            <div className="flex flex-wrap gap-1">
              {BUILT_IN_ROLES.map((role) => (
                <Button
                  key={role}
                  type="button"
                  onClick={() =>
                    setForm((f) =>
                      splitList(f.enrollRoles).includes(role)
                        ? f
                        : {
                            ...f,
                            enrollRoles: [
                              ...splitList(f.enrollRoles),
                              role,
                            ].join(","),
                          },
                    )
                  }
                >
                  {role}
                </Button>
              ))}
            </div>
          </div>
          <label className="flex items-center gap-2 pt-1 text-sm text-foreground">
            <input
              type="checkbox"
              checked={form.requireApproval}
              onChange={(e) =>
                setForm((f) => ({ ...f, requireApproval: e.target.checked }))
              }
            />
            <span>
              Require approval{" "}
              <span className="text-muted-foreground">
                — issuance requests wait in Approvals until a second person
                (pki-admin) approves
              </span>
            </span>
          </label>
          <fieldset className="space-y-3 rounded-xl border border-border p-3">
            <legend className="px-1 text-sm font-medium text-foreground">
              SSH policy
            </legend>
            <label className="flex items-center gap-2 text-sm text-foreground">
              <input
                type="checkbox"
                checked={form.sshEnabled}
                onChange={(e) =>
                  setForm((f) => ({ ...f, sshEnabled: e.target.checked }))
                }
              />
              <span>
                Allow SSH certificates from this template{" "}
                <span className="text-muted-foreground">
                  — the SSH CA signs only the principals and hosts listed here
                </span>
              </span>
            </label>
            {form.sshEnabled ? (
              <>
                <div className="flex gap-4 text-sm text-foreground">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={form.sshUser}
                      onChange={(e) =>
                        setForm((f) => ({ ...f, sshUser: e.target.checked }))
                      }
                    />
                    <span>User certificates</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={form.sshHost}
                      onChange={(e) =>
                        setForm((f) => ({ ...f, sshHost: e.target.checked }))
                      }
                    />
                    <span>Host certificates</span>
                  </label>
                </div>
                {form.sshUser ? (
                  <label className="block space-y-1 text-sm text-foreground">
                    <span>
                      Allowed principals{" "}
                      <span className="text-muted-foreground">
                        (comma-separated login names, no wildcards)
                      </span>
                    </span>
                    <Input
                      value={form.sshPrincipals}
                      onChange={(e) =>
                        setForm((f) => ({
                          ...f,
                          sshPrincipals: e.target.value,
                        }))
                      }
                      placeholder="deploy,ops"
                    />
                  </label>
                ) : null}
                {form.sshHost ? (
                  <label className="block space-y-1 text-sm text-foreground">
                    <span>
                      Host patterns{" "}
                      <span className="text-muted-foreground">
                        (comma-separated; exact names or *.example.com)
                      </span>
                    </span>
                    <Input
                      value={form.sshHostPatterns}
                      onChange={(e) =>
                        setForm((f) => ({
                          ...f,
                          sshHostPatterns: e.target.value,
                        }))
                      }
                      placeholder="*.corp.example,build01.corp.example"
                    />
                  </label>
                ) : null}
                <label className="block space-y-1 text-sm text-foreground">
                  <span>
                    Max TTL (hours){" "}
                    <span className="text-muted-foreground">
                      (up to 24 for user, 720 for host; longer requests are
                      refused)
                    </span>
                  </span>
                  <Input
                    type="number"
                    min="0"
                    step="any"
                    value={form.sshMaxTtlHours}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        sshMaxTtlHours: e.target.value,
                      }))
                    }
                  />
                </label>
              </>
            ) : null}
          </fieldset>
          <fieldset className="space-y-3 rounded-xl border border-border p-3">
            <legend className="px-1 text-sm font-medium text-foreground">
              Name policy
            </legend>
            <label className="flex items-center gap-2 text-sm text-foreground">
              <input
                type="checkbox"
                checked={form.nameEnabled}
                onChange={(e) =>
                  setForm((f) => ({ ...f, nameEnabled: e.target.checked }))
                }
              />
              <span>
                Restrict the names this template may issue{" "}
                <span className="text-muted-foreground">
                  — without it a requester can name any host
                </span>
              </span>
            </label>
            {form.nameEnabled ? (
              <>
                <label className="block space-y-1 text-sm text-foreground">
                  <span>
                    Allowed DNS suffixes{" "}
                    <span className="text-muted-foreground">
                      (comma-separated; &quot;.corp.example&quot; matches
                      subdomains only, &quot;example.com&quot; the name and its
                      subdomains)
                    </span>
                  </span>
                  <Input
                    value={form.nameSuffixes}
                    onChange={(e) =>
                      setForm((f) => ({ ...f, nameSuffixes: e.target.value }))
                    }
                    placeholder=".corp.example,example.com"
                  />
                </label>
                <label className="block space-y-1 text-sm text-foreground">
                  <span>
                    Allowed exact DNS names{" "}
                    <span className="text-muted-foreground">
                      (comma-separated)
                    </span>
                  </span>
                  <Input
                    value={form.nameDnsNames}
                    onChange={(e) =>
                      setForm((f) => ({ ...f, nameDnsNames: e.target.value }))
                    }
                    placeholder="exact.example"
                  />
                </label>
                <div className="flex gap-4 text-sm text-foreground">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={form.nameAllowIp}
                      onChange={(e) =>
                        setForm((f) => ({
                          ...f,
                          nameAllowIp: e.target.checked,
                        }))
                      }
                    />
                    <span>Allow IP SANs</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={form.nameAllowUri}
                      onChange={(e) =>
                        setForm((f) => ({
                          ...f,
                          nameAllowUri: e.target.checked,
                        }))
                      }
                    />
                    <span>Allow URI SANs</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={form.nameCnMustBeSan}
                      onChange={(e) =>
                        setForm((f) => ({
                          ...f,
                          nameCnMustBeSan: e.target.checked,
                        }))
                      }
                    />
                    <span>CN must be a SAN</span>
                  </label>
                </div>
                {form.nameAllowUri ? (
                  <label className="block space-y-1 text-sm text-foreground">
                    <span>
                      Allowed URI prefixes{" "}
                      <span className="text-muted-foreground">
                        (comma-separated; empty allows any URI)
                      </span>
                    </span>
                    <Input
                      value={form.nameUriPrefixes}
                      onChange={(e) =>
                        setForm((f) => ({
                          ...f,
                          nameUriPrefixes: e.target.value,
                        }))
                      }
                      placeholder="spiffe://prod.example/"
                    />
                  </label>
                ) : null}
              </>
            ) : null}
          </fieldset>
        </form>
      </Dialog>

      {/* Delete confirm */}
      <Dialog
        open={dialog === "delete"}
        title="Delete template"
        description="This action cannot be undone."
        onClose={() => setDialog(null)}
      >
        <div className="space-y-4 text-sm text-foreground">
          <p>
            Delete <strong>{selected?.display_name || selected?.name}</strong>?
            Certificates already issued under this template are not affected.
          </p>
          <div className="flex gap-2">
            <Button
              tone="danger"
              onClick={() => void deleteMutation.mutateAsync()}
              disabled={deleteMutation.isPending}
            >
              Confirm delete
            </Button>
            <Button onClick={() => setDialog(null)}>Cancel</Button>
          </div>
        </div>
      </Dialog>
      <PolicyDraftDialog open={draftOpen} onClose={() => setDraftOpen(false)} />
    </div>
  );
}
