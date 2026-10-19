import { useState, type ReactNode } from "react";
import { scrollableProps } from "../lib/scrollable";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { toast } from "sonner";
import { canManageUsers, useAuthz } from "../lib/auth";
import {
  canManageEnrollment,
  enrollmentApi,
  parseLines,
  validateEstUsername,
  validateHostName,
  validateSuffix,
  type CmpCredential,
  type EstUser,
  type ScepChallenge,
} from "../lib/enrollmentApi";
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
import { SecretOnceDialog } from "../components/SecretOnceDialog";
import { PageHeader } from "../components/PageHeader";

type Shown = { title: string; fields: { label: string; value: string }[]; note?: string };

const errToast = (e: Error) => toast.error(e.message);

function Confirm({
  title,
  message,
  action,
  busy,
  onConfirm,
  onClose,
}: {
  title: string;
  message: string;
  action: string;
  busy: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Dialog open title={title} description={message} onClose={onClose} size="sm">
      <div className="flex justify-end gap-2">
        <Button onClick={onClose}>Cancel</Button>
        <Button tone="danger" disabled={busy} onClick={onConfirm}>
          {action}
        </Button>
      </div>
    </Dialog>
  );
}

function FieldErrors({ id, errors }: { id: string; errors: string[] }) {
  if (errors.length === 0) return null;
  return (
    <ul id={id} className="space-y-0.5 text-xs text-state-over">
      {errors.map((e) => (
        <li key={e}>{e}</li>
      ))}
    </ul>
  );
}

function ListState({
  isLoading,
  error,
  empty,
  emptyTitle,
  notEnabled,
  off,
  children,
}: {
  isLoading: boolean;
  error: unknown;
  empty: boolean;
  emptyTitle: string;
  /** Shown instead of the error state when the hub answers 404 (protocol disabled). */
  notEnabled: string;
  /** Known-disabled up front (feature probe), so the list was never requested. */
  off?: boolean;
  children: ReactNode;
}) {
  if (off) return <StateMessage title="Not enabled" message={notEnabled} />;
  if (isLoading) return <StateMessage title="Loading" message="Fetching…" />;
  if ((error as { status?: number } | null)?.status === 404) {
    return <StateMessage title="Not enabled" message={notEnabled} />;
  }
  if (error) return <StateMessage tone="error" title="Unavailable" message="Could not load this list." />;
  if (empty) return <StateMessage title={emptyTitle} />;
  return <div className="overflow-x-auto" {...scrollableProps}>{children}</div>;
}

const suffixErrors = (list: string[]) =>
  list.flatMap((s) => {
    const e = validateSuffix(s);
    return e ? [`${s}: ${e}`] : [];
  });

// ---------------------------------------------------------------- SCEP

function scepStatus(c: ScepChallenge): "used" | "expired" | "unused" {
  if (c.used_at) return "used";
  return new Date(c.expires_at).getTime() < Date.now() ? "expired" : "unused";
}

function ScepDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (s: Shown) => void }) {
  const [cn, setCn] = useState("");
  const [dns, setDns] = useState("");
  const [ttl, setTtl] = useState("1h");
  const names = parseLines(dns);
  const errors = [
    ...(cn.trim() && validateHostName(cn) ? [`Common name: ${validateHostName(cn)}`] : []),
    ...names.flatMap((n) => {
      const e = validateHostName(n);
      return e ? [`${n}: ${e}`] : [];
    }),
    ...(names.length > 20 ? ["At most 20 DNS names"] : []),
  ];
  const canSave = cn.trim() !== "" && errors.length === 0;
  const create = useMutation({
    mutationFn: () =>
      enrollmentApi.scepCreate({ common_name: cn.trim(), dns_names: names, ttl }),
    onSuccess: (res) => {
      onCreated({
        title: "SCEP challenge created",
        fields: [
          { label: "Challenge", value: res.data.challenge },
          { label: "SCEP URL", value: `${window.location.origin}/scep` },
        ],
      });
      create.reset();
    },
    onError: errToast,
  });
  return (
    <Dialog open title="New SCEP challenge" onClose={onClose} size="md">
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (canSave) create.mutate();
        }}
      >
        <label className="block space-y-1 text-sm text-foreground">
          <span>Common name</span>
          <Input value={cn} onChange={(e) => setCn(e.target.value)} />
        </label>
        <label className="block space-y-1 text-sm text-foreground">
          <span>DNS names (one per line)</span>
          <Textarea
            rows={3}
            className="font-mono"
            value={dns}
            aria-invalid={errors.length > 0 ? true : undefined}
            aria-describedby={errors.length > 0 ? "scep-errors" : undefined}
            onChange={(e) => setDns(e.target.value)}
          />
        </label>
        <FieldErrors id="scep-errors" errors={errors} />
        <label className="block space-y-1 text-sm text-foreground">
          <span>Valid for</span>
          <Select value={ttl} onChange={(e) => setTtl(e.target.value)}>
            {["30m", "1h", "4h", "24h"].map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </Select>
        </label>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" tone="primary" disabled={!canSave || create.isPending}>
            Create challenge
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function ScepTab() {
  const qc = useQueryClient();
  const flag = useQuery({ queryKey: ["scep-enabled"], queryFn: enrollmentApi.scepEnabled, retry: false });
  // A failed probe falls through to the list call, whose 404 is still handled.
  const scepOff = flag.data?.data.scep_enabled === false;
  const list = useQuery({
    queryKey: ["scep-challenges"],
    queryFn: enrollmentApi.scepList,
    enabled: !flag.isLoading && !scepOff,
  });
  const [creating, setCreating] = useState(false);
  const [shown, setShown] = useState<Shown | null>(null);
  const [revoking, setRevoking] = useState<ScepChallenge | null>(null);
  const revoke = useMutation({
    mutationFn: (id: string) => enrollmentApi.scepRevoke(id),
    onSuccess: () => {
      toast.success("Challenge revoked");
      setRevoking(null);
      return qc.invalidateQueries({ queryKey: ["scep-challenges"] });
    },
    onError: errToast,
  });
  const rows = list.data?.data ?? [];
  return (
    <Panel title="SCEP challenges" subtitle="One-time challenge passwords bound to a device's names.">
      <div className="mb-3 flex justify-end">
        <Button tone="primary" disabled={scepOff} onClick={() => setCreating(true)}>
          <Plus className="h-4 w-4" />
          New challenge
        </Button>
      </div>
      <ListState isLoading={flag.isLoading || list.isLoading} off={scepOff} error={list.error} empty={rows.length === 0} emptyTitle="No SCEP challenges"
        notEnabled={
          flag.data?.data.scep_off_reason
            ? `SCEP is not running on this hub: ${flag.data.data.scep_off_reason}`
            : "SCEP is not enabled on this hub. Set KRYPTKEEPER_SCEP_ENABLED=true to issue one-time challenges."
        }>
        <table className="w-full text-left text-sm">
          <thead className="text-xs text-muted-foreground">
            <tr>
              <th className="pb-2 pr-3">Common name</th>
              <th className="pb-2 pr-3">DNS names</th>
              <th className="pb-2 pr-3">Expires</th>
              <th className="pb-2 pr-3">Status</th>
              <th className="pb-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => {
              const st = scepStatus(c);
              return (
                <tr key={c.id} className="border-t border-border align-top">
                  <td className="py-2 pr-3 font-medium">{c.common_name}</td>
                  <td className="py-2 pr-3">{(c.dns_names ?? []).join(", ") || "none"}</td>
                  <td className="py-2 pr-3">{formatDateTime(c.expires_at)}</td>
                  <td className="py-2 pr-3">
                    <Badge tone={st === "unused" ? "success" : "neutral"}>{st}</Badge>
                  </td>
                  <td className="py-2">
                    {st === "unused" ? (
                      <Button tone="danger" aria-label={`Revoke challenge for ${c.common_name}`} onClick={() => setRevoking(c)}>
                        Revoke
                      </Button>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </ListState>
      {creating ? (
        <ScepDialog
          onClose={() => setCreating(false)}
          onCreated={(s) => {
            setCreating(false);
            setShown(s);
            void qc.invalidateQueries({ queryKey: ["scep-challenges"] });
          }}
        />
      ) : null}
      <SecretOnceDialog open={shown !== null} title={shown?.title ?? ""} fields={shown?.fields ?? []} onDone={() => setShown(null)} />
      {revoking ? (
        <Confirm
          title="Revoke SCEP challenge"
          message={`Withdraw the unused challenge for ${revoking.common_name}?`}
          action="Revoke challenge"
          busy={revoke.isPending}
          onConfirm={() => revoke.mutate(revoking.id)}
          onClose={() => setRevoking(null)}
        />
      ) : null}
    </Panel>
  );
}

// ---------------------------------------------------------------- EST

function EstDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (s: Shown) => void }) {
  const [username, setUsername] = useState("");
  const [suffixes, setSuffixes] = useState("");
  const list = parseLines(suffixes);
  const userError = username === "" ? null : validateEstUsername(username);
  const errors = suffixErrors(list);
  const canSave = username !== "" && !userError && list.length > 0 && errors.length === 0;
  const create = useMutation({
    mutationFn: () => enrollmentApi.estCreate({ username, allowed_dns_suffixes: list }),
    onSuccess: (res) => {
      onCreated({
        title: "EST user created",
        fields: [
          { label: "Username", value: res.data.username },
          { label: "Password", value: res.data.password },
        ],
      });
      create.reset();
    },
    onError: errToast,
  });
  return (
    <Dialog open title="New EST user" onClose={onClose} size="md">
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (canSave) create.mutate();
        }}
      >
        <label className="block space-y-1 text-sm text-foreground">
          <span>Username</span>
          <Input
            value={username}
            aria-invalid={userError ? true : undefined}
            aria-describedby={userError ? "est-user-error" : undefined}
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>
        {userError ? <FieldErrors id="est-user-error" errors={[userError]} /> : null}
        <label className="block space-y-1 text-sm text-foreground">
          <span>Allowed DNS suffixes (one per line)</span>
          <Textarea
            rows={3}
            className="font-mono"
            placeholder=".devices.example.com"
            value={suffixes}
            aria-invalid={errors.length > 0 ? true : undefined}
            aria-describedby={errors.length > 0 ? "est-suffix-errors" : undefined}
            onChange={(e) => setSuffixes(e.target.value)}
          />
        </label>
        <FieldErrors id="est-suffix-errors" errors={errors} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" tone="primary" disabled={!canSave || create.isPending}>
            Create user
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

type EstAction = { kind: "rotate" | "disable" | "delete"; user: EstUser };

function EstTab() {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["est-users"], queryFn: enrollmentApi.estList });
  const [creating, setCreating] = useState(false);
  const [shown, setShown] = useState<Shown | null>(null);
  const [pending, setPending] = useState<EstAction | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["est-users"] });

  const rotate = useMutation({
    mutationFn: (u: string) => enrollmentApi.estRotate(u),
    onSuccess: (res) => {
      setPending(null);
      setShown({
        title: "EST password rotated",
        fields: [
          { label: "Username", value: res.data.username },
          { label: "Password", value: res.data.password },
        ],
      });
      rotate.reset();
      return refresh();
    },
    onError: errToast,
  });
  const patch = useMutation({
    mutationFn: (v: { u: string; disabled: boolean }) => enrollmentApi.estPatch(v.u, { disabled: v.disabled }),
    onSuccess: () => {
      setPending(null);
      return refresh();
    },
    onError: errToast,
  });
  const remove = useMutation({
    mutationFn: (u: string) => enrollmentApi.estDelete(u),
    onSuccess: () => {
      toast.success("User deleted");
      setPending(null);
      return refresh();
    },
    onError: errToast,
  });

  const rows = list.data?.data ?? [];
  const busy = rotate.isPending || patch.isPending || remove.isPending;
  return (
    <Panel title="EST users" subtitle="HTTP Basic users for EST enrollment. Passwords are generated and shown once.">
      <div className="mb-3 flex justify-end">
        <Button tone="primary" onClick={() => setCreating(true)}>
          <Plus className="h-4 w-4" />
          New user
        </Button>
      </div>
      <ListState isLoading={list.isLoading} error={list.error} empty={rows.length === 0} emptyTitle="No EST users"
        notEnabled="EST is not enabled on this hub.">
        <table className="w-full text-left text-sm">
          <thead className="text-xs text-muted-foreground">
            <tr>
              <th className="pb-2 pr-3">Username</th>
              <th className="pb-2 pr-3">DNS suffixes</th>
              <th className="pb-2 pr-3">Status</th>
              <th className="pb-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((u) => (
              <tr key={u.username} className="border-t border-border align-top">
                <td className="py-2 pr-3 font-medium">{u.username}</td>
                <td className="py-2 pr-3">{(u.allowed_dns_suffixes ?? []).join(", ")}</td>
                <td className="py-2 pr-3">
                  <div className="flex flex-wrap gap-1">
                    <Badge tone={u.disabled ? "warning" : "success"}>{u.disabled ? "disabled" : "active"}</Badge>
                    {u.shadowed_by_file ? (
                      <span title="defined in the users file; the file wins">
                        <Badge tone="info">file</Badge>
                      </span>
                    ) : null}
                  </div>
                </td>
                <td className="py-2">
                  <div className="flex flex-wrap gap-2">
                    <Button aria-label={`Rotate password for ${u.username}`} onClick={() => setPending({ kind: "rotate", user: u })}>
                      Rotate
                    </Button>
                    {u.disabled ? (
                      <Button aria-label={`Enable ${u.username}`} onClick={() => patch.mutate({ u: u.username, disabled: false })}>
                        Enable
                      </Button>
                    ) : (
                      <Button aria-label={`Disable ${u.username}`} onClick={() => setPending({ kind: "disable", user: u })}>
                        Disable
                      </Button>
                    )}
                    <Button tone="danger" aria-label={`Delete ${u.username}`} onClick={() => setPending({ kind: "delete", user: u })}>
                      Delete
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </ListState>
      {creating ? (
        <EstDialog
          onClose={() => setCreating(false)}
          onCreated={(s) => {
            setCreating(false);
            setShown(s);
            void refresh();
          }}
        />
      ) : null}
      <SecretOnceDialog open={shown !== null} title={shown?.title ?? ""} fields={shown?.fields ?? []} onDone={() => setShown(null)} />
      {pending?.kind === "rotate" ? (
        <Confirm
          title="Rotate EST password"
          message={`Replace the password for ${pending.user.username}? The old one stops working immediately.`}
          action="Rotate password"
          busy={busy}
          onConfirm={() => rotate.mutate(pending.user.username)}
          onClose={() => setPending(null)}
        />
      ) : null}
      {pending?.kind === "disable" ? (
        <Confirm
          title="Disable EST user"
          message={`Disable ${pending.user.username}? It can no longer enroll until enabled again.`}
          action="Disable user"
          busy={busy}
          onConfirm={() => patch.mutate({ u: pending.user.username, disabled: true })}
          onClose={() => setPending(null)}
        />
      ) : null}
      {pending?.kind === "delete" ? (
        <Confirm
          title="Delete EST user"
          message={`Delete ${pending.user.username}?`}
          action="Delete user"
          busy={busy}
          onConfirm={() => remove.mutate(pending.user.username)}
          onClose={() => setPending(null)}
        />
      ) : null}
    </Panel>
  );
}

// ---------------------------------------------------------------- CMP

function PbmDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (s: Shown) => void }) {
  const [label, setLabel] = useState("");
  const [suffixes, setSuffixes] = useState("");
  const list = parseLines(suffixes);
  const errors = suffixErrors(list);
  const canSave = label.trim() !== "" && errors.length === 0;
  const create = useMutation({
    mutationFn: () => enrollmentApi.cmpCreatePbm({ label: label.trim(), allowed_dns_suffixes: list }),
    onSuccess: (res) => {
      onCreated(pbmShown("CMP secret created", res.data.reference ?? "", res.data.secret));
      create.reset();
    },
    onError: errToast,
  });
  return (
    <Dialog open title="New PBM secret" onClose={onClose} size="md">
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (canSave) create.mutate();
        }}
      >
        <label className="block space-y-1 text-sm text-foreground">
          <span>Label</span>
          <Input value={label} maxLength={200} onChange={(e) => setLabel(e.target.value)} />
        </label>
        <label className="block space-y-1 text-sm text-foreground">
          <span>Allowed DNS suffixes (optional, one per line)</span>
          <Textarea
            rows={3}
            className="font-mono"
            placeholder=".devices.example.com"
            value={suffixes}
            aria-invalid={errors.length > 0 ? true : undefined}
            aria-describedby={errors.length > 0 ? "cmp-suffix-errors" : undefined}
            onChange={(e) => setSuffixes(e.target.value)}
          />
        </label>
        <FieldErrors id="cmp-suffix-errors" errors={errors} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" tone="primary" disabled={!canSave || create.isPending}>
            Create secret
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function pbmShown(title: string, reference: string, secret: string): Shown {
  return {
    title,
    fields: [
      { label: "Reference", value: reference },
      { label: "Secret", value: secret },
    ],
    note: `openssl cmp -cmd ir -ref ${reference} -secret pass:${secret} ...`,
  };
}

function AnchorDialog({ onClose, onRegistered }: { onClose: () => void; onRegistered: () => void }) {
  const [label, setLabel] = useState("");
  const [pem, setPem] = useState("");
  const pemOk = pem.includes("BEGIN CERTIFICATE");
  const register = useMutation({
    mutationFn: () => enrollmentApi.cmpRegisterAnchor({ label: label.trim(), certificate_pem: pem.trim() }),
    onSuccess: () => {
      toast.success("Trust anchor registered");
      onRegistered();
    },
    onError: errToast,
  });
  return (
    <Dialog open title="Register trust anchor" onClose={onClose} size="md">
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (label.trim() && pemOk) register.mutate();
        }}
      >
        <label className="block space-y-1 text-sm text-foreground">
          <span>Label</span>
          <Input value={label} maxLength={200} onChange={(e) => setLabel(e.target.value)} />
        </label>
        <label className="block space-y-1 text-sm text-foreground">
          <span>Certificate (PEM)</span>
          <Textarea
            rows={6}
            className="font-mono"
            value={pem}
            aria-invalid={pem !== "" && !pemOk ? true : undefined}
            aria-describedby={pem !== "" && !pemOk ? "cmp-pem-error" : undefined}
            onChange={(e) => setPem(e.target.value)}
          />
        </label>
        {pem !== "" && !pemOk ? <FieldErrors id="cmp-pem-error" errors={["Paste one PEM CERTIFICATE block"]} /> : null}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" tone="primary" disabled={!label.trim() || !pemOk || register.isPending}>
            Register anchor
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function cmpStatus(c: CmpCredential): string {
  return c.revoked_at ? "revoked" : "active";
}

function CmpTab() {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["cmp-credentials"], queryFn: enrollmentApi.cmpList });
  const [dialog, setDialog] = useState<"pbm" | "anchor" | null>(null);
  const [shown, setShown] = useState<Shown | null>(null);
  const [anchorNote, setAnchorNote] = useState(false);
  const [revoking, setRevoking] = useState<CmpCredential | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["cmp-credentials"] });

  const rotate = useMutation({
    mutationFn: (id: string) => enrollmentApi.cmpRotate(id),
    onSuccess: (res) => {
      setShown(pbmShown("CMP secret rotated", res.data.reference, res.data.secret));
      rotate.reset();
      return refresh();
    },
    onError: errToast,
  });
  const revoke = useMutation({
    mutationFn: (id: string) => enrollmentApi.cmpRevoke(id),
    onSuccess: () => {
      toast.success("Credential revoked");
      setRevoking(null);
      return refresh();
    },
    onError: errToast,
  });

  const rows = list.data?.data ?? [];
  return (
    <Panel title="CMP credentials" subtitle="PBM shared secrets and trust anchors for CMP enrollment.">
      <div className="mb-3 flex flex-wrap justify-end gap-2">
        <Button onClick={() => setDialog("anchor")}>Register trust anchor</Button>
        <Button tone="primary" onClick={() => setDialog("pbm")}>
          <Plus className="h-4 w-4" />
          New PBM secret
        </Button>
      </div>
      {anchorNote ? (
        <div className="mb-3">
          <StateMessage
            title="Trust anchor registered"
            message="Registered anchors are stored but signature verification is not enforced yet"
          />
        </div>
      ) : null}
      <ListState isLoading={list.isLoading} error={list.error} empty={rows.length === 0} emptyTitle="No CMP credentials"
        notEnabled="CMP is not enabled on this hub.">
        <table className="w-full text-left text-sm">
          <thead className="text-xs text-muted-foreground">
            <tr>
              <th className="pb-2 pr-3">Kind</th>
              <th className="pb-2 pr-3">Label</th>
              <th className="pb-2 pr-3">Reference</th>
              <th className="pb-2 pr-3">DNS suffixes</th>
              <th className="pb-2 pr-3">Status</th>
              <th className="pb-2 pr-3">Last used</th>
              <th className="pb-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.id} className="border-t border-border align-top">
                <td className="py-2 pr-3">
                  <Badge>{c.kind === "pbm" ? "PBM" : "trust anchor"}</Badge>
                </td>
                <td className="py-2 pr-3">{c.label}</td>
                <td className="py-2 pr-3 font-mono text-xs">{c.reference ?? (c.cert_sha256 ? c.cert_sha256.slice(0, 16) : "")}</td>
                <td className="py-2 pr-3">{(c.allowed_dns_suffixes ?? []).join(", ") || "server default"}</td>
                <td className="py-2 pr-3">
                  <Badge tone={c.revoked_at ? "danger" : "success"}>{cmpStatus(c)}</Badge>
                </td>
                <td className="py-2 pr-3">{c.last_used_at ? formatDateTime(c.last_used_at) : "never"}</td>
                <td className="py-2">
                  {c.revoked_at ? null : (
                    <div className="flex flex-wrap gap-2">
                      {c.kind === "pbm" ? (
                        <Button aria-label={`Rotate ${c.label || c.id}`} disabled={rotate.isPending} onClick={() => rotate.mutate(c.id)}>
                          Rotate
                        </Button>
                      ) : null}
                      <Button tone="danger" aria-label={`Revoke ${c.label || c.id}`} onClick={() => setRevoking(c)}>
                        Revoke
                      </Button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </ListState>
      {dialog === "pbm" ? (
        <PbmDialog
          onClose={() => setDialog(null)}
          onCreated={(s) => {
            setDialog(null);
            setShown(s);
            void refresh();
          }}
        />
      ) : null}
      {dialog === "anchor" ? (
        <AnchorDialog
          onClose={() => setDialog(null)}
          onRegistered={() => {
            setDialog(null);
            setAnchorNote(true);
            void refresh();
          }}
        />
      ) : null}
      <SecretOnceDialog open={shown !== null} title={shown?.title ?? ""} fields={shown?.fields ?? []} onDone={() => setShown(null)}>
        {shown?.note ? (
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">Sample client command</p>
            <pre className="overflow-x-auto rounded-xl bg-[var(--surface-0)] p-2 font-mono text-xs" {...scrollableProps}>{shown.note}</pre>
          </div>
        ) : null}
      </SecretOnceDialog>
      {revoking ? (
        <Confirm
          title="Revoke CMP credential"
          message={`Revoke ${revoking.label || revoking.id}? Messages protected by it will be refused.`}
          action="Revoke credential"
          busy={revoke.isPending}
          onConfirm={() => revoke.mutate(revoking.id)}
          onClose={() => setRevoking(null)}
        />
      ) : null}
    </Panel>
  );
}

// ---------------------------------------------------------------- page

export default function EnrollmentProtocols() {
  const authz = useAuthz();
  const role = authz.data?.role;
  const scopes = authz.data?.scopes;
  if (authz.isLoading) return <StateMessage title="Loading" message="Checking permissions…" />;
  if (!canManageEnrollment(role, scopes)) {
    return (
      <div className="p-6">
        <StateMessage tone="error" title="Not permitted" message="pki-admin or pki-operator role required" />
      </div>
    );
  }
  const isAdmin = canManageUsers(role, scopes);
  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Administration"
        title="Enrollment Protocols"
        description="Credentials for SCEP, EST and CMP enrollment."
      />
      <Tabs defaultValue="scep">
        <TabsList className="group-data-horizontal/tabs:h-9">
          <TabsTrigger value="scep" className="h-full flex-none px-3 py-1">SCEP</TabsTrigger>
          {isAdmin ? <TabsTrigger value="est" className="h-full flex-none px-3 py-1">EST</TabsTrigger> : null}
          {isAdmin ? <TabsTrigger value="cmp" className="h-full flex-none px-3 py-1">CMP</TabsTrigger> : null}
        </TabsList>
        <TabsContent value="scep">
          <ScepTab />
        </TabsContent>
        {isAdmin ? (
          <TabsContent value="est">
            <EstTab />
          </TabsContent>
        ) : null}
        {isAdmin ? (
          <TabsContent value="cmp">
            <CmpTab />
          </TabsContent>
        ) : null}
      </Tabs>
    </div>
  );
}
