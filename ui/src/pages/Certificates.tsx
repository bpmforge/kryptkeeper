import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
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
import { PageHeader } from "../components/PageHeader";
import { canManageCertificates, useAuthz } from "../lib/auth";
import { extractList } from "../lib/models";
import { useCaNames } from "../lib/useResourceNames";
import { savePemFile } from "../lib/utils";
import type { CaRecord, CertificateRecord } from "../lib/models";

type CertFilters = {
  q: string;
  ca_id: string;
  team_id: string;
  status: string;
  grade: string;
  order: string;
  origin: string;
  management_state: string;
};

const initialFilters: CertFilters = {
  q: "",
  ca_id: "",
  team_id: "",
  status: "",
  grade: "",
  origin: "",
  management_state: "",
  order: "desc",
};

// reissue_required is set by the CA-key-compromise flow; show it as words.
function formatStatus(status: string | undefined): string {
  return status ? status.replace(/_/g, " ") : "—";
}

function csvEscape(value: string) {
  const escaped = String(value ?? "").replace(/"/g, '""');
  return `"${escaped}"`;
}

// OwnershipEditor renders the ownership fields for a certificate and, for users
// who can manage certificates, an inline edit form wired to the ownership API.
export function OwnershipEditor({
  cert,
  canEdit,
}: {
  cert: CertificateRecord;
  canEdit: boolean;
}) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [ownerEmail, setOwnerEmail] = useState("");
  const [ownerTeam, setOwnerTeam] = useState("");
  const [serviceName, setServiceName] = useState("");
  const [labels, setLabels] = useState("");
  const [saved, setSaved] = useState(false);

  function beginEdit() {
    setOwnerEmail(cert.owner_email ?? "");
    setOwnerTeam(cert.owner_team ?? cert.team_id ?? "");
    setServiceName(cert.service_name ?? "");
    setLabels((cert.labels ?? []).join(", "));
    setSaved(false);
    setEditing(true);
  }

  const mutation = useMutation({
    mutationFn: () =>
      api.updateCertOwnership(cert.fingerprint_sha256, {
        owner_email: ownerEmail.trim(),
        owner_team: ownerTeam.trim(),
        service_name: serviceName.trim(),
        labels: labels
          .split(",")
          .map((l) => l.trim())
          .filter(Boolean),
      }),
    onSuccess: async () => {
      setEditing(false);
      setSaved(true);
      await queryClient.invalidateQueries({ queryKey: ["certificates"] });
    },
  });

  const currentLabels = cert.labels ?? [];

  return (
    <div className="rounded-xl border border-border bg-card/40 p-3 text-sm">
      <div className="flex items-center justify-between">
        <div className="font-medium text-foreground">Ownership</div>
        {canEdit && !editing ? (
          <Button tone="secondary" onClick={beginEdit}>
            Edit
          </Button>
        ) : null}
      </div>

      {!editing ? (
        <div className="mt-2 grid grid-cols-2 gap-3">
          <div>
            <div className="text-muted-foreground">Owner email</div>
            <div className="text-foreground">{cert.owner_email || "—"}</div>
          </div>
          <div>
            <div className="text-muted-foreground">Owner team</div>
            <div className="text-foreground">
              {cert.owner_team || cert.team_id || "—"}
            </div>
          </div>
          <div>
            <div className="text-muted-foreground">Service</div>
            <div className="text-foreground">{cert.service_name || "—"}</div>
          </div>
          <div>
            <div className="text-muted-foreground">Labels</div>
            <div className="text-foreground">
              {currentLabels.length ? currentLabels.join(", ") : "—"}
            </div>
          </div>
          {saved ? (
            <div className="col-span-full text-xs text-state-auto">
              Ownership updated.
            </div>
          ) : null}
        </div>
      ) : (
        <form
          className="mt-3 space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          <div>
            <label className="text-xs text-muted-foreground">Owner email</label>
            <Input
              type="email"
              value={ownerEmail}
              onChange={(e) => setOwnerEmail(e.target.value)}
              placeholder="owner@example.com"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Owner team</label>
            <Input
              value={ownerTeam}
              onChange={(e) => setOwnerTeam(e.target.value)}
              placeholder="platform"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">
              Service name
            </label>
            <Input
              value={serviceName}
              onChange={(e) => setServiceName(e.target.value)}
              placeholder="checkout-api"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground">
              Labels (comma-separated)
            </label>
            <Input
              value={labels}
              onChange={(e) => setLabels(e.target.value)}
              placeholder="prod, pci, tier-1"
            />
          </div>
          {mutation.isError ? (
            <p className="text-xs text-state-over">
              {mutation.error instanceof Error
                ? mutation.error.message
                : "Update failed."}
            </p>
          ) : null}
          <div className="flex gap-2">
            <Button type="submit" tone="primary" disabled={mutation.isPending}>
              {mutation.isPending ? "Saving…" : "Save ownership"}
            </Button>
            <Button
              type="button"
              tone="secondary"
              onClick={() => setEditing(false)}
            >
              Cancel
            </Button>
          </div>
        </form>
      )}
    </div>
  );
}

// TakeoverDialog fronts POST /estate/takeover (W11-06): assign an owner,
// choose the renewal path, and the certificate becomes managed — the found
// -> takeover -> managed funnel's last step.
export function TakeoverDialog({
  open,
  cert,
  onClose,
}: {
  open: boolean;
  cert: CertificateRecord | null;
  onClose: () => void;
}) {
  const connectorsQuery = useQuery({
    queryKey: ["connectors"],
    queryFn: api.connectors,
    enabled: open,
  });
  const connectorList = connectorsQuery.data?.data ?? [];

  if (!cert) return null;
  return (
    <Dialog
      open={open}
      title="Take certificate under management"
      description={`${cert.common_name || cert.fingerprint_sha256} — assign an owner and choose how it renews from now on.`}
      onClose={onClose}
    >
      <TakeoverForm
        key={cert.fingerprint_sha256 + String(open)}
        cert={cert}
        connectorList={connectorList}
        onClose={onClose}
      />
    </Dialog>
  );
}

function TakeoverForm({
  cert,
  connectorList,
  onClose,
}: {
  cert: CertificateRecord;
  connectorList: {
    id: string;
    name: string;
    type: string;
    health?: { status: string };
  }[];
  onClose: () => void;
}) {
  const [ownerEmail, setOwnerEmail] = useState(cert.owner_email ?? "");
  const [ownerTeam, setOwnerTeam] = useState(
    cert.owner_team ?? cert.team_id ?? "",
  );
  const [mode, setMode] = useState("internal");
  const [connectorId, setConnectorId] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () =>
      api.estateTakeover({
        fingerprint: cert.fingerprint_sha256,
        owner_email: ownerEmail.trim(),
        owner_team: ownerTeam.trim(),
        renewal_path: {
          mode,
          ...(mode === "connector" ? { connector_id: connectorId } : {}),
        },
      }),
    onSuccess: () => {
      setDone(true);
      setError(null);
    },
    onError: (e) =>
      setError(e instanceof Error ? e.message : "Takeover failed."),
  });

  return (
    <>
      {done ? (
        <div className="space-y-3 text-sm">
          <p className="text-state-auto">
            Now managed. Its renewal path is recorded as{" "}
            {mode === "internal"
              ? "an internal CA"
              : "the selected upstream connector"}{" "}
            — to renew automatically, also declare the serving host as a managed
            target with auto-renew in Target Setup.
          </p>
          <Button tone="primary" onClick={onClose}>
            Done
          </Button>
        </div>
      ) : (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          <label className="block space-y-1 text-sm text-foreground">
            <span>Owner email</span>
            <Input
              aria-label="Takeover owner email"
              type="email"
              value={ownerEmail}
              onChange={(e) => setOwnerEmail(e.target.value)}
              placeholder="owner@example.com"
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Owner team</span>
            <Input
              aria-label="Takeover owner team"
              value={ownerTeam}
              onChange={(e) => setOwnerTeam(e.target.value)}
              placeholder="platform"
            />
          </label>
          <fieldset className="space-y-2 text-sm text-foreground">
            <legend>Renewal path</legend>
            <label className="flex items-center gap-2">
              <input
                type="radio"
                name="renewal-path"
                value="internal"
                checked={mode === "internal"}
                onChange={() => setMode("internal")}
              />
              <span>Renew from an internal CA (migrate it to Kryptkeeper)</span>
            </label>
            <label className="flex items-center gap-2">
              <input
                type="radio"
                name="renewal-path"
                value="connector"
                checked={mode === "connector"}
                onChange={() => setMode("connector")}
              />
              <span>Renew at its original CA via a connector</span>
            </label>
            {mode === "connector" ? (
              <Select
                aria-label="Takeover connector"
                value={connectorId}
                onChange={(e) => setConnectorId(e.target.value)}
              >
                <option value="" disabled>
                  — select a connector —
                </option>
                {connectorList.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} ({c.type}
                    {c.health?.status ? ` · ${c.health.status}` : ""})
                  </option>
                ))}
              </Select>
            ) : null}
          </fieldset>
          {error ? <p className="text-xs text-state-over">{error}</p> : null}
          <Button
            type="submit"
            tone="primary"
            disabled={
              mutation.isPending || (mode === "connector" && !connectorId)
            }
          >
            {mutation.isPending ? "Taking over…" : "Take over"}
          </Button>
        </form>
      )}
    </>
  );
}

// BulkImportDialog fronts POST /certificates/bulk-import (W11-08): paste or
// pick a file, choose the format, get the imported/skipped/failed report.
export function BulkImportDialog({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const [format, setFormat] = useState("pem");
  const [bundle, setBundle] = useState("");
  const [result, setResult] = useState<{
    imported: number;
    skipped_duplicates: number;
    failed: { index: number; reason: string }[];
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () => api.bulkImportCertificates({ format, bundle }),
    onSuccess: (res) => {
      setResult(res.data);
      setError(null);
    },
    onError: (e) =>
      setError(e instanceof Error ? e.message : "Bulk import failed."),
  });

  const reset = () => {
    setBundle("");
    setResult(null);
    setError(null);
  };

  return (
    <Dialog
      open={open}
      title="Bulk import certificates"
      description="Bring the certificates other CAs issued into the estate. They land as unmanaged — take them over when you are ready."
      onClose={() => {
        reset();
        onClose();
      }}
    >
      {result ? (
        <div className="space-y-3 text-sm">
          <p className="text-state-auto">
            Imported {result.imported} · skipped {result.skipped_duplicates}{" "}
            duplicates
            {result.failed.length ? ` · ${result.failed.length} failed` : ""}
          </p>
          {result.failed.slice(0, 5).map((f) => (
            <p key={f.index} className="text-xs text-state-over">
              #{f.index}: {f.reason}
            </p>
          ))}
          <div className="flex gap-2">
            <Button tone="secondary" onClick={reset}>
              Import more
            </Button>
            <Button
              tone="primary"
              onClick={() => {
                reset();
                onClose();
              }}
            >
              Done
            </Button>
          </div>
        </div>
      ) : (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          <label className="block space-y-1 text-sm text-foreground">
            <span>Format</span>
            <Select
              aria-label="Bulk import format"
              value={format}
              onChange={(e) => setFormat(e.target.value)}
            >
              <option value="pem">PEM bundle (concatenated)</option>
              <option value="der_b64">Base64 DER list</option>
              <option value="csv">
                CSV (cert_b64, owner_email, owner_team, service_name)
              </option>
            </Select>
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>File</span>
            <input
              type="file"
              aria-label="Bulk import file"
              accept=".pem,.crt,.cer,.txt,.csv"
              className="block w-full text-sm text-muted-foreground"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (!file) return;
                const reader = new FileReader();
                reader.onload = () => setBundle(String(reader.result ?? ""));
                reader.readAsText(file);
              }}
            />
          </label>
          <label className="block space-y-1 text-sm text-foreground">
            <span>Or paste the bundle</span>
            <textarea
              aria-label="Bulk import bundle"
              className="h-32 w-full rounded-xl border border-border bg-background p-3 font-mono text-xs text-foreground"
              placeholder="-----BEGIN CERTIFICATE-----"
              value={bundle}
              onChange={(e) => setBundle(e.target.value)}
            />
          </label>
          {error ? <p className="text-xs text-state-over">{error}</p> : null}
          <Button
            type="submit"
            tone="primary"
            disabled={mutation.isPending || !bundle.trim()}
          >
            {mutation.isPending ? "Importing…" : "Import"}
          </Button>
        </form>
      )}
    </Dialog>
  );
}

export default function Certificates() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { fingerprint } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const authz = useAuthz();

  const [filters, setFilters] = useState<CertFilters>(() => ({
    q: searchParams.get("q") ?? "",
    ca_id: searchParams.get("ca_id") ?? "",
    team_id: searchParams.get("team_id") ?? "",
    status: searchParams.get("status") ?? "",
    grade: searchParams.get("grade") ?? "",
    order: searchParams.get("order") ?? "desc",
    origin: searchParams.get("origin") ?? "",
    management_state: searchParams.get("management_state") ?? "",
  }));
  const [cursor, setCursor] = useState<string | null>(
    searchParams.get("cursor") ?? null,
  );

  const updateFilter = (patch: Partial<CertFilters>) => {
    setCursor(null);
    setFilters((curr) => ({ ...curr, ...patch }));
  };

  useEffect(() => {
    const next = new URLSearchParams();
    Object.entries(filters).forEach(([k, v]) => {
      if (v && !(k === "order" && v === "desc")) next.set(k, v);
    });
    if (cursor) next.set("cursor", cursor);
    setSearchParams(next, { replace: true });
  }, [filters, cursor]); // eslint-disable-line react-hooks/exhaustive-deps

  const [selectedFingerprint, setSelectedFingerprint] = useState<string | null>(
    null,
  );
  const [bulkImportOpen, setBulkImportOpen] = useState(false);
  const [takeoverOpen, setTakeoverOpen] = useState(
    searchParams.get("takeover") === "1",
  );
  const [selectedFingerprints, setSelectedFingerprints] = useState<string[]>(
    [],
  );
  const [action, setAction] = useState<
    "renew" | "revoke" | "import" | "bulk-renew" | "bulk-revoke" | null
  >(null);
  const [revokeConfirm, setRevokeConfirm] = useState("");
  const [bulkProgress, setBulkProgress] = useState<{
    done: number;
    total: number;
    errors: string[];
  } | null>(null);
  const [form, setForm] = useState({
    csrPem: "",
    reasonCode: "0",
    reasonText: "",
    certificatePem: "",
    teamId: "",
    notes: "",
  });
  const [statusMessage, setStatusMessage] = useState<{
    tone: "success" | "error";
    title: string;
    message: string;
  } | null>(null);

  const queryParams = useMemo(
    () => ({
      q: filters.q,
      ca_id: filters.ca_id,
      team_id: filters.team_id,
      status: filters.status,
      grade: filters.grade,
      order: filters.order,
      origin: filters.origin,
      management_state: filters.management_state,
      limit: 50,
      ...(cursor ? { cursor } : {}),
    }),
    [filters, cursor],
  );

  const certsQuery = useQuery({
    queryKey: ["certificates", queryParams],
    queryFn: () => api.certificates(queryParams),
  });

  const { names: caNames } = useCaNames();
  const casQuery = useQuery({
    queryKey: ["cas", { limit: 200 }],
    queryFn: () => api.cas({ limit: 200 }),
  });

  const certs: CertificateRecord[] = extractList<CertificateRecord>(
    certsQuery.data?.data,
    ["items"],
  );
  const cas: CaRecord[] = extractList<CaRecord>(casQuery.data?.data, ["items"]);

  const meta = certsQuery.data?.meta;
  const selectedKey = fingerprint ?? selectedFingerprint ?? null;
  const pageHit = selectedKey
    ? (certs.find((cert) => cert.fingerprint_sha256 === selectedKey) ?? null)
    : null;
  // A deep link (/certificates/:fingerprint — e.g. IssueWizard's "View in
  // inventory", Discovery's mapped certs) can point outside the loaded
  // page; GET /certificates/{fingerprint} has existed all along.
  const certById = useQuery({
    queryKey: ["certificate-by-id", selectedKey],
    enabled: Boolean(selectedKey) && !pageHit && !certsQuery.isLoading,
    staleTime: 30_000,
    queryFn: async () => {
      try {
        const res = await api.certificate(selectedKey!);
        return (res.data ?? null) as CertificateRecord | null;
      } catch {
        return null;
      }
    },
  });
  const selectedCert =
    pageHit ?? certById.data ?? (selectedKey ? null : (certs[0] ?? null));
  const canManage = canManageCertificates(authz.data?.role, authz.data?.scopes);
  const allVisibleSelected =
    certs.length > 0 &&
    certs.every((cert) =>
      selectedFingerprints.includes(cert.fingerprint_sha256),
    );
  const selectedCount = selectedFingerprints.length;

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ["certificates"] });
  };

  const renewMutation = useMutation({
    mutationFn: async () => {
      if (!selectedCert) throw new Error("No certificate selected");
      return api.renewCertificate(selectedCert.fingerprint_sha256, {
        csr_pem: form.csrPem,
      });
    },
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "Certificate renewed",
        message: "A new certificate was issued.",
      });
      setAction(null);
      await refresh();
    },
    onError: (e) =>
      setStatusMessage({
        tone: "error",
        title: "Renewal failed",
        message:
          e instanceof Error ? e.message : "Check the CSR and try again.",
      }),
  });

  const revokeMutation = useMutation({
    mutationFn: async () => {
      if (!selectedCert) throw new Error("No certificate selected");
      return api.revokeCertificate(selectedCert.fingerprint_sha256, {
        reason_code: Number(form.reasonCode),
        reason_text: form.reasonText,
      });
    },
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "Certificate revoked",
        message: "The certificate is now marked revoked.",
      });
      setAction(null);
      await refresh();
    },
    onError: (e) =>
      setStatusMessage({
        tone: "error",
        title: "Revocation failed",
        message:
          e instanceof Error
            ? e.message
            : "Check the reason code and try again.",
      }),
  });

  const importMutation = useMutation({
    mutationFn: async () =>
      api.importCertificate({
        certificate_pem: form.certificatePem,
        team_id: form.teamId,
        notes: form.notes,
      }),
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "Certificate imported",
        message: "The inventory now includes the imported cert.",
      });
      setAction(null);
      await refresh();
    },
    onError: (e) =>
      setStatusMessage({
        tone: "error",
        title: "Import failed",
        message:
          e instanceof Error ? e.message : "Verify the PEM and try again.",
      }),
  });

  const bulkRenewMutation = useMutation({
    mutationFn: async () => {
      const fps = [...selectedFingerprints];
      setBulkProgress({ done: 0, total: fps.length, errors: [] });
      const errors: string[] = [];
      for (let i = 0; i < fps.length; i++) {
        try {
          await api.renewCertificate(fps[i], { csr_pem: form.csrPem });
        } catch (err) {
          errors.push(
            `${fps[i].slice(0, 12)}… — ${err instanceof Error ? err.message : String(err)}`,
          );
        }
        setBulkProgress({
          done: i + 1,
          total: fps.length,
          errors: [...errors],
        });
      }
      return errors;
    },
    onSuccess: async (errors) => {
      const total = selectedFingerprints.length;
      setStatusMessage({
        tone: errors.length > 0 ? "error" : "success",
        title:
          errors.length > 0
            ? `${errors.length} renewals failed`
            : "Bulk renewal complete",
        message:
          errors.length > 0
            ? `${total - errors.length} of ${total} renewed successfully.`
            : `${total} certificates renewed.`,
      });
      setAction(null);
      setBulkProgress(null);
      setSelectedFingerprints([]);
      await refresh();
    },
    onError: (e) => {
      setStatusMessage({
        tone: "error",
        title: "Bulk renewal failed",
        message: e instanceof Error ? e.message : "Try again.",
      });
      setBulkProgress(null);
    },
  });

  const bulkRevokeMutation = useMutation({
    mutationFn: async () => {
      const fps = [...selectedFingerprints];
      setBulkProgress({ done: 0, total: fps.length, errors: [] });
      const errors: string[] = [];
      for (let i = 0; i < fps.length; i++) {
        try {
          await api.revokeCertificate(fps[i], {
            reason_code: Number(form.reasonCode),
            reason_text: form.reasonText,
          });
        } catch (err) {
          errors.push(
            `${fps[i].slice(0, 12)}… — ${err instanceof Error ? err.message : String(err)}`,
          );
        }
        setBulkProgress({
          done: i + 1,
          total: fps.length,
          errors: [...errors],
        });
      }
      return errors;
    },
    onSuccess: async (errors) => {
      const total = selectedFingerprints.length;
      setStatusMessage({
        tone: errors.length > 0 ? "error" : "success",
        title:
          errors.length > 0
            ? `${errors.length} revocations failed`
            : "Bulk revocation complete",
        message:
          errors.length > 0
            ? `${total - errors.length} of ${total} revoked successfully.`
            : `${total} certificates revoked.`,
      });
      setAction(null);
      setBulkProgress(null);
      setSelectedFingerprints([]);
      await refresh();
    },
    onError: (e) => {
      setStatusMessage({
        tone: "error",
        title: "Bulk revocation failed",
        message: e instanceof Error ? e.message : "Try again.",
      });
      setBulkProgress(null);
    },
  });

  const openAction = (
    next: "renew" | "revoke" | "import" | "bulk-renew" | "bulk-revoke",
  ) => {
    setRevokeConfirm("");
    setAction(next);
    setStatusMessage(null);
    setBulkProgress(null);
    if (next !== "bulk-renew" && next !== "bulk-revoke") {
      setForm((curr) => ({
        ...curr,
        teamId: selectedCert?.team_id || curr.teamId,
      }));
    }
  };

  const toggleCertificate = (fp: string) => {
    setSelectedFingerprints((curr) =>
      curr.includes(fp) ? curr.filter((f) => f !== fp) : [...curr, fp],
    );
  };

  const toggleAllVisible = () => {
    setSelectedFingerprints(
      allVisibleSelected ? [] : certs.map((cert) => cert.fingerprint_sha256),
    );
  };

  const exportSelectedCsv = () => {
    const rows = certs.filter((cert) =>
      selectedFingerprints.includes(cert.fingerprint_sha256),
    );
    const header = [
      "fingerprint_sha256",
      "common_name",
      "issuer",
      "valid_until",
      "grade",
      "risk_score",
      "status",
    ];
    const csv = [
      header.join(","),
      ...rows.map((cert) =>
        [
          cert.fingerprint_sha256,
          cert.common_name || cert.subject_dn || "",
          cert.issuer_cn || cert.issuer_dn || "",
          cert.valid_until || "",
          cert.grade || "",
          cert.risk_score != null ? String(cert.risk_score) : "",
          cert.status || "",
        ]
          .map(csvEscape)
          .join(","),
      ),
    ].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "certificates-selected.csv";
    link.click();
    URL.revokeObjectURL(url);
  };

  // S-69: fetch the PEM from the download endpoint on demand — the list/get
  // responses carry no PEM field (the old cert_pem gate only ever matched
  // MSW fixtures, so no download existed in production).
  const [pemDownloadError, setPemDownloadError] = useState<string | null>(null);
  const downloadPem = async (cert: CertificateRecord) => {
    setPemDownloadError(null);
    try {
      const pem = await api.downloadCertificatePem(cert.fingerprint_sha256);
      savePemFile(`${cert.common_name || cert.fingerprint_sha256}.pem`, pem);
    } catch (e) {
      setPemDownloadError(
        e instanceof Error ? e.message : "Certificate download failed.",
      );
    }
  };

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Inventory"
        title="Certificates"
        description="Search, filter, inspect, and act on certificate inventory."
        actions={
          canManage ? (
            <div className="flex gap-2">
              <Button tone="secondary" onClick={() => setBulkImportOpen(true)}>
                Bulk import
              </Button>
              <Button
                tone="primary"
                onClick={() => navigate("/certificates/issue")}
              >
                Issue certificate
              </Button>
            </div>
          ) : undefined
        }
      />

      <BulkImportDialog
        open={bulkImportOpen}
        onClose={() => {
          setBulkImportOpen(false);
          void queryClient.invalidateQueries({ queryKey: ["certificates"] });
        }}
      />

      <TakeoverDialog
        open={takeoverOpen && !!selectedCert}
        cert={selectedCert}
        onClose={() => {
          setTakeoverOpen(false);
          void queryClient.invalidateQueries({ queryKey: ["certificates"] });
        }}
      />

      <Panel
        title="Filters"
        subtitle="Narrow the inventory before you inspect a record"
      >
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-6">
          <label className="space-y-2 text-sm text-foreground">
            <span>Search</span>
            <Input
              aria-label="Search certificates"
              placeholder="CN, issuer, fingerprint"
              value={filters.q}
              onChange={(e) => updateFilter({ q: e.target.value })}
            />
          </label>
          <label className="space-y-2 text-sm text-foreground">
            <span>CA</span>
            <Select
              aria-label="Filter by CA"
              value={filters.ca_id}
              onChange={(e) => updateFilter({ ca_id: e.target.value })}
            >
              <option value="">All CAs</option>
              {cas.map((ca) => (
                <option key={ca.id} value={ca.id}>
                  {ca.display_name || ca.name || ca.id}
                </option>
              ))}
            </Select>
          </label>
          <label className="space-y-2 text-sm text-foreground">
            <span>Team ID</span>
            <Input
              aria-label="Filter by team ID"
              placeholder="Team ID"
              value={filters.team_id}
              onChange={(e) => updateFilter({ team_id: e.target.value })}
            />
          </label>
          <label className="space-y-2 text-sm text-foreground">
            <span>Status</span>
            <Select
              aria-label="Filter by certificate status"
              value={filters.status}
              onChange={(e) => updateFilter({ status: e.target.value })}
            >
              <option value="">All statuses</option>
              <option value="active">Active</option>
              <option value="expired">Expired</option>
              <option value="revoked">Revoked</option>
              <option value="pending">Pending</option>
              <option value="reissue_required">Reissue required</option>
            </Select>
          </label>
          <label className="space-y-2 text-sm text-foreground">
            <span>Grade</span>
            <Select
              aria-label="Filter by grade"
              value={filters.grade}
              onChange={(e) => updateFilter({ grade: e.target.value })}
            >
              <option value="">All grades</option>
              <option value="A+">A+</option>
              <option value="A">A</option>
              <option value="A-">A-</option>
              <option value="B">B</option>
              <option value="C">C</option>
              <option value="D">D</option>
              <option value="F">F</option>
            </Select>
          </label>
          <label className="space-y-2 text-sm text-foreground">
            <span>Estate</span>
            <Select
              aria-label="Filter by management state"
              value={filters.management_state}
              onChange={(e) =>
                updateFilter({ management_state: e.target.value })
              }
            >
              <option value="">All states</option>
              <option value="managed">Managed</option>
              <option value="external">Externally managed</option>
              <option value="unmanaged">Unmanaged</option>
            </Select>
          </label>
          <label className="space-y-2 text-sm text-foreground">
            <span>Origin</span>
            <Select
              aria-label="Filter by origin"
              value={filters.origin}
              onChange={(e) => updateFilter({ origin: e.target.value })}
            >
              <option value="">All origins</option>
              <option value="internal">Internal CA</option>
              <option value="imported">Imported</option>
              <option value="discovered">Discovered</option>
              <option value="synced">Synced from CA</option>
            </Select>
          </label>
          <label className="space-y-2 text-sm text-foreground">
            <span>Sort order</span>
            <Select
              aria-label="Sort certificates"
              value={filters.order}
              onChange={(e) => updateFilter({ order: e.target.value })}
            >
              <option value="desc">Newest first</option>
              <option value="asc">Oldest first</option>
            </Select>
          </label>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <Button tone="primary" onClick={() => certsQuery.refetch()}>
            Apply filters
          </Button>
          <Button
            onClick={() => {
              setCursor(null);
              setFilters(initialFilters);
            }}
          >
            Reset
          </Button>
        </div>
      </Panel>

      {certsQuery.isLoading ? (
        <StateMessage
          title="Loading certificates"
          message="Fetching inventory..."
        />
      ) : null}
      {certsQuery.error ? (
        <StateMessage
          tone="error"
          title="Certificates unavailable"
          message="Try again in a moment."
        />
      ) : null}
      {statusMessage ? (
        <StateMessage
          tone={statusMessage.tone}
          title={statusMessage.title}
          message={statusMessage.message}
        />
      ) : null}

      <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <Panel
          title={`Certificate inventory${meta ? ` · ${meta.total ?? 0} total` : ""}`}
          subtitle="Click a row to inspect details"
        >
          <div className="mb-3 flex flex-wrap items-center gap-2 text-sm text-foreground">
            <Button onClick={toggleAllVisible}>
              {allVisibleSelected ? "Clear selection" : "Select all visible"}
            </Button>
            <Button
              tone="primary"
              onClick={exportSelectedCsv}
              disabled={selectedCount === 0}
            >
              Export CSV
            </Button>
            {canManage ? (
              <>
                <Button
                  onClick={() => openAction("bulk-renew")}
                  disabled={selectedCount === 0}
                >
                  Bulk renew
                </Button>
                <Button
                  tone="danger"
                  onClick={() => openAction("bulk-revoke")}
                  disabled={selectedCount === 0}
                >
                  Bulk revoke
                </Button>
              </>
            ) : null}
            <span className="text-muted-foreground">
              {selectedCount} selected
            </span>
          </div>
          <div className="overflow-hidden rounded-xl border border-border">
            <table className="min-w-full divide-y divide-border">
              <thead className="bg-background/80">
                <tr>
                  <th
                    scope="col"
                    className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                  >
                    Select
                  </th>
                  <th
                    scope="col"
                    className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                  >
                    Common Name
                  </th>
                  <th
                    scope="col"
                    className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                  >
                    Issuer
                  </th>
                  <th
                    scope="col"
                    className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                  >
                    Valid Until
                  </th>
                  <th
                    scope="col"
                    className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                  >
                    Grade
                  </th>
                  <th
                    scope="col"
                    className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                  >
                    Risk
                  </th>
                  <th
                    scope="col"
                    className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                  >
                    Estate
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
                {certs.map((cert) => (
                  <tr
                    key={cert.fingerprint_sha256}
                    className={
                      selectedCert?.fingerprint_sha256 ===
                      cert.fingerprint_sha256
                        ? "bg-card/80"
                        : ""
                    }
                  >
                    <td className="px-4 py-3 text-sm text-foreground">
                      <input
                        type="checkbox"
                        aria-label={`Select ${cert.common_name || cert.subject_dn || cert.fingerprint_sha256}`}
                        checked={selectedFingerprints.includes(
                          cert.fingerprint_sha256,
                        )}
                        onChange={() =>
                          toggleCertificate(cert.fingerprint_sha256)
                        }
                        className="h-4 w-4 rounded border-border bg-background text-primary focus:ring-ring"
                      />
                    </td>
                    <td className="px-4 py-3 text-sm text-foreground">
                      <button
                        type="button"
                        className="text-left font-medium hover:text-primary"
                        onClick={() => {
                          setSelectedFingerprint(cert.fingerprint_sha256);
                          navigate(`/certificates/${cert.fingerprint_sha256}`);
                        }}
                      >
                        {cert.common_name ||
                          cert.subject_dn ||
                          cert.fingerprint_sha256}
                      </button>
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">
                      {cert.issuer_cn || cert.issuer_dn || "—"}
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">
                      {cert.valid_until?.slice?.(0, 10) ||
                        cert.valid_until ||
                        "—"}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <Badge
                        tone={
                          String(cert.grade ?? "").startsWith("A")
                            ? "success"
                            : String(cert.grade ?? "").startsWith("B")
                              ? "warning"
                              : "neutral"
                        }
                      >
                        {cert.grade || "—"}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {cert.risk_score != null ? (
                        <span
                          className={
                            cert.risk_score >= 70
                              ? "font-semibold text-state-over"
                              : cert.risk_score >= 40
                                ? "font-semibold text-state-attn"
                                : "text-state-auto"
                          }
                        >
                          {cert.risk_score}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <Badge
                        tone={
                          cert.management_state === "managed"
                            ? "success"
                            : cert.management_state === "external"
                              ? "neutral"
                              : "warning"
                        }
                      >
                        {cert.management_state || "unmanaged"}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <Badge
                        tone={
                          String(cert.renewal_status ?? "").includes("expir") ||
                          cert.status === "expired"
                            ? "danger"
                            : cert.status === "revoked" ||
                                cert.renewal_status === "reissue_required"
                              ? "warning"
                              : "info"
                        }
                      >
                        {formatStatus(cert.renewal_status || cert.status)}
                      </Badge>
                    </td>
                  </tr>
                ))}
                {certs.length === 0 &&
                (filters.q ||
                  filters.ca_id ||
                  filters.team_id ||
                  filters.status ||
                  filters.grade ||
                  filters.origin ||
                  filters.management_state) ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-10">
                      <EmptyState
                        title="No certificates match these filters"
                        description="Try broadening the search."
                        actionLabel="Reset filters"
                        onAction={() => {
                          setCursor(null);
                          setFilters(initialFilters);
                        }}
                      />
                    </td>
                  </tr>
                ) : null}
                {certs.length === 0 &&
                !(
                  filters.q ||
                  filters.ca_id ||
                  filters.team_id ||
                  filters.status ||
                  filters.grade ||
                  filters.origin ||
                  filters.management_state
                ) ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-10">
                      <EmptyState
                        title="No certificates issued yet"
                        description="The inventory tracks every certificate in your estate — issue one from an internal CA, or import the ones other CAs issued."
                        actionLabel={
                          canManage ? "Issue your first certificate" : undefined
                        }
                        onAction={
                          canManage
                            ? () => navigate("/certificates/issue")
                            : undefined
                        }
                      />
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
          <div className="mt-4 flex items-center justify-between text-sm text-muted-foreground">
            <span>
              {meta?.total != null
                ? `${meta.total} total · page size ${meta.limit ?? 50}`
                : "Loading…"}
            </span>
            <div className="flex gap-2">
              <Button
                disabled={!meta?.prev_cursor}
                onClick={() => setCursor(meta?.prev_cursor ?? null)}
              >
                ← Previous
              </Button>
              <Button
                disabled={!meta?.next_cursor}
                onClick={() => setCursor(meta?.next_cursor ?? null)}
              >
                Next →
              </Button>
            </div>
          </div>
        </Panel>

        <Panel title="Certificate detail" subtitle="Inspect before you act">
          {selectedCert ? (
            <div className="space-y-4">
              {selectedKey ? (
                <div className="flex justify-between gap-3">
                  <div />
                  <Button onClick={() => navigate("/certificates")}>
                    Back to list
                  </Button>
                </div>
              ) : null}
              <div>
                <h3 className="text-lg font-semibold text-foreground">
                  {selectedCert.common_name ||
                    selectedCert.subject_dn ||
                    selectedCert.fingerprint_sha256}
                </h3>
                <p className="mt-1 font-mono text-xs text-muted-foreground break-all">
                  {selectedCert.fingerprint_sha256}
                </p>
              </div>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <div className="text-muted-foreground">Issuer</div>
                  <div className="text-foreground">
                    {selectedCert.issuer_cn || selectedCert.issuer_dn || "—"}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Valid until</div>
                  <div className="text-foreground">
                    {selectedCert.valid_until || "—"}
                  </div>
                </div>
                {selectedCert.valid_from ? (
                  <div>
                    <div className="text-muted-foreground">Valid from</div>
                    <div className="text-foreground">
                      {selectedCert.valid_from}
                    </div>
                  </div>
                ) : null}
                {selectedCert.serial_number ? (
                  <div>
                    <div className="text-muted-foreground">Serial</div>
                    <div className="font-mono text-xs text-foreground break-all">
                      {selectedCert.serial_number}
                    </div>
                  </div>
                ) : null}
                {selectedCert.public_key_algorithm ? (
                  <div>
                    <div className="text-muted-foreground">Key algorithm</div>
                    <div className="text-foreground">
                      {selectedCert.key_algorithm_display ||
                        selectedCert.public_key_algorithm}
                      {selectedCert.key_size_bits
                        ? ` ${selectedCert.key_size_bits}-bit`
                        : ""}
                    </div>
                  </div>
                ) : null}
                <div>
                  <div className="text-muted-foreground">Origin</div>
                  <div className="text-foreground">
                    {selectedCert.origin || "internal"}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Team</div>
                  <div className="text-foreground">
                    {selectedCert.team_id || "—"}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">CA</div>
                  <div className="text-foreground">
                    {selectedCert.ca_id ? (
                      <span title={selectedCert.ca_id}>
                        {caNames.get(selectedCert.ca_id) ?? selectedCert.ca_id}
                      </span>
                    ) : (
                      "—"
                    )}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Grade</div>
                  <div className="text-foreground">
                    {selectedCert.grade || "—"}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Risk score</div>
                  <div
                    className={
                      selectedCert.risk_score != null
                        ? selectedCert.risk_score >= 70
                          ? "font-semibold text-state-over"
                          : selectedCert.risk_score >= 40
                            ? "font-semibold text-state-attn"
                            : "font-semibold text-state-auto"
                        : "text-foreground"
                    }
                  >
                    {selectedCert.risk_score != null
                      ? `${selectedCert.risk_score} / 100`
                      : "—"}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Status</div>
                  <div className="text-foreground">
                    {formatStatus(
                      selectedCert.renewal_status || selectedCert.status,
                    )}
                  </div>
                </div>
                <div className="col-span-full">
                  <div className="text-muted-foreground">
                    Fingerprint (SHA-256)
                  </div>
                  <div className="font-mono text-xs text-foreground break-all">
                    {selectedCert.fingerprint_sha256}
                  </div>
                </div>
              </div>
              {selectedCert.revoked_at ? (
                <div className="rounded-xl border border-state-over/50 bg-state-over/10 p-3 text-sm">
                  <div className="font-medium text-state-over">Revoked</div>
                  <div className="mt-1 text-state-over/70">
                    {selectedCert.revoked_at}
                    {selectedCert.revocation_reason
                      ? ` — ${selectedCert.revocation_reason}`
                      : ""}
                  </div>
                </div>
              ) : null}
              {(selectedCert.subject_alt_names ?? []).length > 0 ? (
                <div className="text-sm">
                  <div className="text-muted-foreground">SANs</div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {(selectedCert.subject_alt_names ?? []).map((san) => (
                      <span
                        key={san}
                        className="rounded-lg bg-muted px-2 py-0.5 font-mono text-xs text-foreground"
                      >
                        {san}
                      </span>
                    ))}
                  </div>
                </div>
              ) : null}
              {(selectedCert.uri_sans ?? []).length > 0 ? (
                <div className="text-sm">
                  <div className="text-muted-foreground">URI SANs (SPIFFE)</div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {(selectedCert.uri_sans ?? []).map((uri) => (
                      <span
                        key={uri}
                        className="rounded-lg bg-primary/15 px-2 py-0.5 font-mono text-xs text-primary"
                      >
                        {uri}
                      </span>
                    ))}
                  </div>
                </div>
              ) : null}
              <OwnershipEditor cert={selectedCert} canEdit={canManage} />
              {selectedCert.ca_id && cas.length > 0
                ? (() => {
                    const chain: CaRecord[] = [];
                    let cur = cas.find((c) => c.id === selectedCert.ca_id);
                    const visited = new Set<string>();
                    while (cur && !visited.has(cur.id)) {
                      visited.add(cur.id);
                      chain.push(cur);
                      cur = cur.parent_ca_id
                        ? cas.find((c) => c.id === cur!.parent_ca_id)
                        : undefined;
                    }
                    if (chain.length === 0) return null;
                    return (
                      <div className="text-sm">
                        <div className="text-muted-foreground">CA chain</div>
                        <ol className="mt-2 flex flex-wrap items-center gap-1 font-mono text-xs">
                          {chain.map((ca, i) => (
                            <li key={ca.id} className="flex items-center gap-1">
                              {i > 0 && (
                                <span className="text-muted-foreground">→</span>
                              )}
                              <span
                                className={`rounded px-2 py-0.5 ${ca.type === "root" ? "bg-primary/10 text-primary" : "bg-muted text-foreground"}`}
                                title={
                                  ca.type === "root"
                                    ? "Root CA"
                                    : "Intermediate CA"
                                }
                              >
                                {ca.name || ca.id}
                              </span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    );
                  })()
                : null}
              {(selectedCert.extended_key_usage ?? []).length > 0 ? (
                <div className="text-sm">
                  <div className="text-muted-foreground">
                    Extended key usage
                  </div>
                  <div className="mt-1 text-foreground">
                    {(selectedCert.extended_key_usage ?? []).join(", ")}
                  </div>
                </div>
              ) : null}
              {selectedCert.management_state !== "managed" && canManage ? (
                <div className="rounded-xl border border-state-attn/30 bg-state-attn/5 p-3 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-state-attn">
                      Nobody manages this certificate yet.
                    </div>
                    <Button
                      tone="primary"
                      onClick={() => setTakeoverOpen(true)}
                    >
                      Take over
                    </Button>
                  </div>
                </div>
              ) : null}
              <div className="text-sm">
                <div className="flex items-center justify-between">
                  <div className="text-muted-foreground">Certificate PEM</div>
                  <Button onClick={() => void downloadPem(selectedCert)}>
                    Download PEM
                  </Button>
                </div>
                {pemDownloadError ? (
                  <p className="mt-1 text-xs text-state-over">
                    {pemDownloadError}
                  </p>
                ) : null}
              </div>
              <div className="rounded-xl border border-border bg-background/60 p-4 text-sm text-muted-foreground">
                <div className="font-medium text-foreground">Next actions</div>
                {canManage ? (
                  <div className="mt-2 flex flex-wrap gap-2">
                    <Button tone="primary" onClick={() => openAction("renew")}>
                      Renew
                    </Button>
                    <Button tone="danger" onClick={() => openAction("revoke")}>
                      Revoke
                    </Button>
                    <Button onClick={() => openAction("import")}>Import</Button>
                  </div>
                ) : (
                  <StateMessage
                    title="Read-only access"
                    message="Your role can inspect certificates but not change them."
                  />
                )}
              </div>
            </div>
          ) : (
            <StateMessage
              title="No certificate selected"
              message="Pick a row to inspect details."
            />
          )}
        </Panel>
      </div>

      <Dialog
        open={action === "renew"}
        title="Renew certificate"
        description="Issue a successor certificate for the selected record."
        onClose={() => setAction(null)}
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void renewMutation.mutateAsync();
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>CSR PEM</span>
            <textarea
              value={form.csrPem}
              onChange={(e) =>
                setForm((curr) => ({ ...curr, csrPem: e.target.value }))
              }
              rows={6}
              className="w-full rounded-xl border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              placeholder="-----BEGIN CERTIFICATE REQUEST-----"
            />
          </label>
          <div className="flex gap-2">
            <Button
              tone="primary"
              type="submit"
              disabled={renewMutation.isPending}
            >
              Confirm renew
            </Button>
            <Button onClick={() => setAction(null)}>Cancel</Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={action === "revoke"}
        title="Revoke certificate"
        description="Mark this certificate revoked for the provided reason."
        onClose={() => setAction(null)}
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void revokeMutation.mutateAsync();
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>Reason code</span>
            <Select
              value={form.reasonCode}
              onChange={(e) =>
                setForm((curr) => ({ ...curr, reasonCode: e.target.value }))
              }
            >
              <option value="0">0 — Unspecified</option>
              <option value="1">1 — Key compromise</option>
              <option value="2">2 — CA compromise</option>
              <option value="3">3 — Affiliation changed</option>
              <option value="4">4 — Superseded</option>
              <option value="5">5 — Cessation of operation</option>
              <option value="6">6 — Certificate hold</option>
              <option value="9">9 — Privilege withdrawn</option>
            </Select>
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>Reason text</span>
            <Input
              value={form.reasonText}
              onChange={(e) =>
                setForm((curr) => ({ ...curr, reasonText: e.target.value }))
              }
              placeholder="Optional explanation"
            />
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>
              Type <strong>REVOKE</strong> to confirm
            </span>
            <Input
              value={revokeConfirm}
              onChange={(e) => setRevokeConfirm(e.target.value)}
              placeholder="REVOKE"
            />
          </label>
          <div className="flex gap-2">
            <Button
              tone="danger"
              type="submit"
              disabled={revokeMutation.isPending || revokeConfirm !== "REVOKE"}
            >
              Confirm revoke
            </Button>
            <Button onClick={() => setAction(null)}>Cancel</Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={action === "import"}
        title="Import certificate"
        description="Bring an external certificate into inventory."
        onClose={() => setAction(null)}
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void importMutation.mutateAsync();
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>Certificate PEM</span>
            <textarea
              value={form.certificatePem}
              onChange={(e) =>
                setForm((curr) => ({ ...curr, certificatePem: e.target.value }))
              }
              rows={6}
              className="w-full rounded-xl border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              placeholder="-----BEGIN CERTIFICATE-----"
            />
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>Team ID</span>
            <Input
              value={form.teamId}
              onChange={(e) =>
                setForm((curr) => ({ ...curr, teamId: e.target.value }))
              }
              placeholder="team-1"
            />
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>Notes</span>
            <Input
              value={form.notes}
              onChange={(e) =>
                setForm((curr) => ({ ...curr, notes: e.target.value }))
              }
              placeholder="Optional notes"
            />
          </label>
          <div className="flex gap-2">
            <Button
              tone="primary"
              type="submit"
              disabled={importMutation.isPending}
            >
              Confirm import
            </Button>
            <Button onClick={() => setAction(null)}>Cancel</Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={action === "bulk-renew"}
        title={`Bulk renew ${selectedCount} certificate${selectedCount !== 1 ? "s" : ""}`}
        description="A new certificate will be issued for each selected record using the provided CSR."
        onClose={() => {
          setAction(null);
          setBulkProgress(null);
        }}
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void bulkRenewMutation.mutateAsync();
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>
              CSR PEM{" "}
              <span className="text-muted-foreground">
                (applied to all selected — every renewed certificate will share
                this CSR&apos;s subject and public key)
              </span>
            </span>
            <textarea
              value={form.csrPem}
              onChange={(e) =>
                setForm((curr) => ({ ...curr, csrPem: e.target.value }))
              }
              rows={5}
              className="w-full rounded-xl border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              placeholder="-----BEGIN CERTIFICATE REQUEST-----"
            />
          </label>
          {bulkProgress ? (
            <div className="rounded-xl border border-border bg-background/60 p-3 text-sm text-foreground">
              <div className="mb-1 font-medium">
                Progress: {bulkProgress.done} / {bulkProgress.total}
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-2 rounded-full bg-primary transition-all"
                  style={{
                    width: `${Math.round((bulkProgress.done / bulkProgress.total) * 100)}%`,
                  }}
                />
              </div>
              {bulkProgress.errors.length > 0 ? (
                <div className="mt-2 text-state-over">
                  {bulkProgress.errors.length} failed so far
                </div>
              ) : null}
            </div>
          ) : null}
          <div className="flex gap-2">
            <Button
              tone="primary"
              type="submit"
              disabled={bulkRenewMutation.isPending}
            >
              {bulkRenewMutation.isPending
                ? "Renewing…"
                : `Renew ${selectedCount}`}
            </Button>
            <Button
              onClick={() => {
                setAction(null);
                setBulkProgress(null);
              }}
            >
              Cancel
            </Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={action === "bulk-revoke"}
        title={`Bulk revoke ${selectedCount} certificate${selectedCount !== 1 ? "s" : ""}`}
        description="All selected certificates will be marked revoked with the reason below."
        onClose={() => {
          setAction(null);
          setBulkProgress(null);
        }}
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void bulkRevokeMutation.mutateAsync();
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>Reason code</span>
            <Select
              value={form.reasonCode}
              onChange={(e) =>
                setForm((curr) => ({ ...curr, reasonCode: e.target.value }))
              }
            >
              <option value="0">0 — Unspecified</option>
              <option value="1">1 — Key compromise</option>
              <option value="2">2 — CA compromise</option>
              <option value="3">3 — Affiliation changed</option>
              <option value="4">4 — Superseded</option>
              <option value="5">5 — Cessation of operation</option>
              <option value="9">9 — Privilege withdrawn</option>
            </Select>
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>
              Reason text{" "}
              <span className="text-muted-foreground">(optional)</span>
            </span>
            <Input
              value={form.reasonText}
              onChange={(e) =>
                setForm((curr) => ({ ...curr, reasonText: e.target.value }))
              }
              placeholder="Reason for bulk revocation"
            />
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>
              Type <strong>REVOKE</strong> to confirm
            </span>
            <Input
              value={revokeConfirm}
              onChange={(e) => setRevokeConfirm(e.target.value)}
              placeholder="REVOKE"
            />
          </label>
          {bulkProgress ? (
            <div className="rounded-xl border border-border bg-background/60 p-3 text-sm text-foreground">
              <div className="mb-1 font-medium">
                Progress: {bulkProgress.done} / {bulkProgress.total}
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-2 rounded-full bg-state-over transition-all"
                  style={{
                    width: `${Math.round((bulkProgress.done / bulkProgress.total) * 100)}%`,
                  }}
                />
              </div>
              {bulkProgress.errors.length > 0 ? (
                <div className="mt-2 text-state-over">
                  {bulkProgress.errors.length} failed so far
                </div>
              ) : null}
            </div>
          ) : null}
          <div className="flex gap-2">
            <Button
              tone="danger"
              type="submit"
              disabled={
                bulkRevokeMutation.isPending || revokeConfirm !== "REVOKE"
              }
            >
              {bulkRevokeMutation.isPending
                ? "Revoking…"
                : `Revoke ${selectedCount}`}
            </Button>
            <Button
              onClick={() => {
                setAction(null);
                setBulkProgress(null);
              }}
            >
              Cancel
            </Button>
          </div>
        </form>
      </Dialog>
    </div>
  );
}
