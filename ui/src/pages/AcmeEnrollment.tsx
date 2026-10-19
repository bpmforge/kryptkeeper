import { useState } from "react";
import { scrollableProps } from "../lib/scrollable";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { api } from "../lib/api";
import { extractList, type CaRecord, type TemplateRecord } from "../lib/models";
import { canManageUsers, useAuthz } from "../lib/auth";
import {
  acmeApi,
  validateAllowEntry,
  validateProvisionerName,
  type EabKey,
  type Provisioner,
} from "../lib/acmeApi";
import {
  Badge,
  Button,
  Dialog,
  Input,
  Panel,
  Select,
  StateMessage,
  Textarea,
  formatDateTime,
} from "../components/ui";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { CopyButton, SecretOnceDialog } from "../components/SecretOnceDialog";
import { PageHeader } from "../components/PageHeader";

type Secret = { kid: string; hmac_key: string };

function NewKeyDialog({
  open,
  provisioners,
  onClose,
  onCreated,
}: {
  open: boolean;
  provisioners: Provisioner[];
  onClose: () => void;
  onCreated: (s: Secret) => void;
}) {
  const [label, setLabel] = useState("");
  const [provisioner, setProvisioner] = useState("");
  const [templateId, setTemplateId] = useState("");
  const create = useMutation({
    mutationFn: () =>
      acmeApi.eabCreate({
        label: label.trim(),
        ...(provisioner ? { provisioner } : {}),
        ...(templateId.trim() ? { template_id: templateId.trim() } : {}),
      }),
    onSuccess: (res) => {
      // Hand the secret straight to the one-time dialog; do not keep it here.
      const { kid, hmac_key } = res.data;
      onCreated({ kid, hmac_key });
      setLabel("");
      setProvisioner("");
      setTemplateId("");
      create.reset();
    },
    onError: (e: Error) => toast.error(e.message),
  });
  return (
    <Dialog open={open} title="New EAB key" onClose={onClose} size="md">
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (label.trim()) create.mutate();
        }}
      >
        <label className="block space-y-1 text-sm text-foreground">
          <span>Label</span>
          <Input value={label} maxLength={200} onChange={(e) => setLabel(e.target.value)} />
        </label>
        <label className="block space-y-1 text-sm text-foreground">
          <span>Provisioner (optional)</span>
          <Select value={provisioner} onChange={(e) => setProvisioner(e.target.value)}>
            <option value="">Any</option>
            {provisioners.map((p) => (
              <option key={p.name} value={p.name}>
                {p.name}
              </option>
            ))}
          </Select>
        </label>
        <label className="block space-y-1 text-sm text-foreground">
          <span>Template id (optional)</span>
          <Input value={templateId} onChange={(e) => setTemplateId(e.target.value)} />
        </label>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" tone="primary" disabled={!label.trim() || create.isPending}>
            Create key
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function EabTab({ provisioners }: { provisioners: Provisioner[] }) {
  const qc = useQueryClient();
  const keys = useQuery({ queryKey: ["acme-eab"], queryFn: acmeApi.eabList });
  const [creating, setCreating] = useState(false);
  const [secret, setSecret] = useState<Secret | null>(null);
  const [revoking, setRevoking] = useState<EabKey | null>(null);

  const revoke = useMutation({
    mutationFn: (kid: string) => acmeApi.eabRevoke(kid),
    onSuccess: () => {
      toast.success("Key revoked");
      setRevoking(null);
      return qc.invalidateQueries({ queryKey: ["acme-eab"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const rows = keys.data?.data ?? [];
  return (
    <Panel
      title="EAB keys"
      subtitle="External account binding credentials for ACME clients (certbot, lego)."
    >
      <div className="mb-3 flex justify-end">
        <Button tone="primary" onClick={() => setCreating(true)}>
          <Plus className="h-4 w-4" />
          New key
        </Button>
      </div>
      {keys.isLoading ? (
        <StateMessage title="Loading" message="Fetching EAB keys…" />
      ) : keys.error ? (
        <StateMessage tone="error" title="Unavailable" message="Could not load EAB keys." />
      ) : rows.length === 0 ? (
        <StateMessage title="No EAB keys" message="Create a key to let an ACME client register." />
      ) : (
        <div className="overflow-x-auto" {...scrollableProps}>
          <table className="w-full text-left text-sm">
            <thead className="text-xs text-muted-foreground">
              <tr>
                <th className="pb-2 pr-3">Key id</th>
                <th className="pb-2 pr-3">Label</th>
                <th className="pb-2 pr-3">Provisioner</th>
                <th className="pb-2 pr-3">Status</th>
                <th className="pb-2 pr-3">Created</th>
                <th className="pb-2 pr-3">Last used</th>
                <th className="pb-2 pr-3">Uses</th>
                <th className="pb-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((k) => (
                <tr key={k.kid} className="border-t border-border align-top">
                  <td className="py-2 pr-3 font-mono text-xs">{k.kid}</td>
                  <td className="py-2 pr-3">{k.label}</td>
                  <td className="py-2 pr-3">{k.provisioner || "any"}</td>
                  <td className="py-2 pr-3">
                    {k.revoked_at ? <Badge tone="danger">revoked</Badge> : <Badge tone="success">active</Badge>}
                  </td>
                  <td className="py-2 pr-3">{formatDateTime(k.created_at)}</td>
                  <td className="py-2 pr-3">{k.last_used_at ? formatDateTime(k.last_used_at) : "never"}</td>
                  <td className="py-2 pr-3">{k.uses}</td>
                  <td className="py-2">
                    {k.revoked_at ? null : (
                      <Button tone="danger" aria-label={`Revoke ${k.kid}`} onClick={() => setRevoking(k)}>
                        Revoke
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <NewKeyDialog
        open={creating}
        provisioners={provisioners}
        onClose={() => setCreating(false)}
        onCreated={(s) => {
          setCreating(false);
          setSecret(s);
          void qc.invalidateQueries({ queryKey: ["acme-eab"] });
        }}
      />
      <SecretOnceDialog
        open={secret !== null}
        title="EAB key created"
        fields={
          secret
            ? [
                { label: "Key id (kid)", value: secret.kid },
                { label: "HMAC key", value: secret.hmac_key },
              ]
            : []
        }
        onDone={() => setSecret(null)}
      />
      <Dialog
        open={revoking !== null}
        title="Revoke EAB key"
        description="Clients using this key can no longer register accounts"
        onClose={() => setRevoking(null)}
        size="sm"
      >
        <div className="flex justify-end gap-2">
          <Button onClick={() => setRevoking(null)}>Cancel</Button>
          <Button
            tone="danger"
            disabled={revoke.isPending}
            onClick={() => revoking && revoke.mutate(revoking.kid)}
          >
            Revoke key
          </Button>
        </div>
      </Dialog>
    </Panel>
  );
}

function ProvisionerDialog({
  initial,
  onClose,
}: {
  initial: Provisioner | "new";
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = initial !== "new" ? initial : null;
  const cas = useQuery({ queryKey: ["cas", "acme"], queryFn: () => api.cas() });
  const templates = useQuery({ queryKey: ["templates", "acme"], queryFn: () => api.templates() });
  const [name, setName] = useState(editing?.name ?? "");
  const [caId, setCaId] = useState(editing?.ca_id ?? "");
  const [templateId, setTemplateId] = useState(editing?.template_id ?? "");
  const [allow, setAllow] = useState((editing?.allow_names ?? []).join("\n"));
  const [http01, setHttp01] = useState(!!editing?.challenges.includes("http-01"));
  const [dns01, setDns01] = useState(!!editing?.challenges.includes("dns-01"));

  const entries = allow.split("\n").map((l) => l.trim()).filter(Boolean);
  const entryErrors = entries
    .map((e) => ({ e, err: validateAllowEntry(e) }))
    .filter((x) => x.err !== null);
  const nameError = editing || name === "" ? null : validateProvisionerName(name);
  const canSave =
    (editing !== null || (name !== "" && !nameError)) &&
    caId !== "" &&
    entries.length > 0 &&
    entryErrors.length === 0;

  const save = useMutation({
    mutationFn: () => {
      const body = {
        name: editing?.name ?? name,
        ca_id: caId,
        ...(templateId ? { template_id: templateId } : {}),
        allow_names: entries.map((e) => e.toLowerCase()),
        challenges: [
          ...(http01 ? (["http-01"] as const) : []),
          ...(dns01 ? (["dns-01"] as const) : []),
        ],
      };
      return editing ? acmeApi.provUpdate(body) : acmeApi.provCreate(body);
    },
    onSuccess: () => {
      toast.success(editing ? "Provisioner updated" : "Provisioner created");
      onClose();
      return qc.invalidateQueries({ queryKey: ["acme-prov"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const allowErrId = "allow-names-error";
  return (
    <Dialog open title={editing ? `Edit ${editing.name}` : "New provisioner"} onClose={onClose} size="md">
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (canSave) save.mutate();
        }}
      >
        <label className="block space-y-1 text-sm text-foreground">
          <span>Name</span>
          <Input
            value={name}
            disabled={!!editing}
            aria-invalid={nameError ? true : undefined}
            onChange={(e) => setName(e.target.value)}
          />
          {nameError ? <span className="text-xs text-state-over">{nameError}</span> : null}
        </label>
        <label className="block space-y-1 text-sm text-foreground">
          <span>CA</span>
          <Select value={caId} onChange={(e) => setCaId(e.target.value)}>
            <option value="">Select a CA</option>
            {extractList<CaRecord>(cas.data?.data).map((c) => (
              <option key={c.id} value={c.id}>
                {c.display_name || c.name || c.id}
              </option>
            ))}
          </Select>
        </label>
        <label className="block space-y-1 text-sm text-foreground">
          <span>Template (optional)</span>
          <Select value={templateId} onChange={(e) => setTemplateId(e.target.value)}>
            <option value="">None</option>
            {extractList<TemplateRecord>(templates.data?.data).map((t) => (
              <option key={t.id} value={t.id}>
                {t.display_name || t.name || t.id}
              </option>
            ))}
          </Select>
        </label>
        <label className="block space-y-1 text-sm text-foreground">
          <span>Allowed names (one per line)</span>
          <Textarea
            rows={4}
            className="font-mono"
            value={allow}
            aria-invalid={entryErrors.length > 0 ? true : undefined}
            aria-describedby={entryErrors.length > 0 ? allowErrId : undefined}
            onChange={(e) => setAllow(e.target.value)}
          />
        </label>
        {entryErrors.length > 0 ? (
          <ul id={allowErrId} className="space-y-0.5 text-xs text-state-over">
            {entryErrors.map((x) => (
              <li key={x.e}>
                {x.e}: {x.err}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-muted-foreground">Exact names or *.suffix entries.</p>
        )}
        <fieldset className="space-y-1">
          <legend className="text-sm text-foreground">Challenge methods</legend>
          <label className="mr-4 inline-flex items-center gap-1.5 text-sm">
            <input type="checkbox" checked={http01} onChange={(e) => setHttp01(e.target.checked)} />
            http-01
          </label>
          <label className="inline-flex items-center gap-1.5 text-sm">
            <input type="checkbox" checked={dns01} onChange={(e) => setDns01(e.target.checked)} />
            dns-01
          </label>
          <p className="text-xs text-muted-foreground">None checked allows both.</p>
        </fieldset>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" tone="primary" disabled={!canSave || save.isPending}>
            Save
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function ProvisionersTab({
  provisioners,
  loading,
  failed,
}: {
  provisioners: Provisioner[];
  loading: boolean;
  failed: boolean;
}) {
  const qc = useQueryClient();
  const [dialog, setDialog] = useState<Provisioner | "new" | null>(null);
  const [deleting, setDeleting] = useState<Provisioner | null>(null);
  const remove = useMutation({
    mutationFn: (name: string) => acmeApi.provDelete(name),
    onSuccess: () => {
      toast.success("Provisioner deleted");
      setDeleting(null);
      return qc.invalidateQueries({ queryKey: ["acme-prov"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });
  return (
    <Panel title="Provisioners" subtitle="Each provisioner serves its own ACME directory bound to one CA.">
      <div className="mb-3 flex justify-end">
        <Button tone="primary" onClick={() => setDialog("new")}>
          <Plus className="h-4 w-4" />
          New provisioner
        </Button>
      </div>
      {loading ? (
        <StateMessage title="Loading" message="Fetching provisioners…" />
      ) : failed ? (
        <StateMessage tone="error" title="Unavailable" message="Could not load provisioners." />
      ) : provisioners.length === 0 ? (
        <StateMessage title="No provisioners" message="Create one to publish an ACME directory." />
      ) : (
        <div className="overflow-x-auto" {...scrollableProps}>
          <table className="w-full text-left text-sm">
            <thead className="text-xs text-muted-foreground">
              <tr>
                <th className="pb-2 pr-3">Name</th>
                <th className="pb-2 pr-3">Directory URL</th>
                <th className="pb-2 pr-3">CA</th>
                <th className="pb-2 pr-3">Template</th>
                <th className="pb-2 pr-3">Allowed names</th>
                <th className="pb-2 pr-3">Challenges</th>
                <th className="pb-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {provisioners.map((p) => (
                <tr key={p.name} className="border-t border-border align-top">
                  <td className="py-2 pr-3 font-medium">{p.name}</td>
                  <td className="py-2 pr-3">
                    <div className="flex items-center gap-2">
                      <span className="break-all font-mono text-xs">{p.directory_url}</span>
                      <CopyButton value={p.directory_url} label={`Copy directory URL for ${p.name}`} />
                    </div>
                  </td>
                  <td className="py-2 pr-3">{p.ca_id}</td>
                  <td className="py-2 pr-3">{p.template_id || "none"}</td>
                  <td className="py-2 pr-3">
                    <div className="flex flex-wrap gap-1">
                      {p.allow_names.map((n) => (
                        <Badge key={n}>{n}</Badge>
                      ))}
                    </div>
                  </td>
                  <td className="py-2 pr-3">{p.challenges.length ? p.challenges.join(", ") : "http-01, dns-01"}</td>
                  <td className="py-2">
                    <div className="flex gap-2">
                      <Button aria-label={`Edit ${p.name}`} onClick={() => setDialog(p)}>
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button tone="danger" aria-label={`Delete ${p.name}`} onClick={() => setDeleting(p)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {dialog ? <ProvisionerDialog initial={dialog} onClose={() => setDialog(null)} /> : null}
      <Dialog
        open={deleting !== null}
        title="Delete provisioner"
        description={deleting ? `Delete ${deleting.name}? Its ACME directory will stop answering.` : undefined}
        onClose={() => setDeleting(null)}
        size="sm"
      >
        <div className="flex justify-end gap-2">
          <Button onClick={() => setDeleting(null)}>Cancel</Button>
          <Button
            tone="danger"
            disabled={remove.isPending}
            onClick={() => deleting && remove.mutate(deleting.name)}
          >
            Delete provisioner
          </Button>
        </div>
      </Dialog>
    </Panel>
  );
}

export default function AcmeEnrollment() {
  const authz = useAuthz();
  const allowed = canManageUsers(authz.data?.role, authz.data?.scopes);
  const prov = useQuery({ queryKey: ["acme-prov"], queryFn: acmeApi.provList, enabled: allowed });

  if (authz.isLoading) return <StateMessage title="Loading" message="Checking permissions…" />;
  if (!allowed) {
    return (
      <div className="p-6">
        <StateMessage tone="error" title="Not permitted" message="pki-admin role required" />
      </div>
    );
  }
  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Administration"
        title="ACME"
        description="EAB credentials and provisioners for ACME clients."
      />
      <Tabs defaultValue="eab">
        <TabsList>
          <TabsTrigger value="eab">EAB keys</TabsTrigger>
          <TabsTrigger value="provisioners">Provisioners</TabsTrigger>
        </TabsList>
        <TabsContent value="eab">
          <EabTab provisioners={prov.data?.data ?? []} />
        </TabsContent>
        <TabsContent value="provisioners">
          <ProvisionersTab
            provisioners={prov.data?.data ?? []}
            loading={prov.isLoading}
            failed={!!prov.error}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}
