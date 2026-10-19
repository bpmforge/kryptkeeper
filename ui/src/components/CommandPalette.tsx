import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Command } from "cmdk";
import {
  LayoutDashboard,
  ShieldCheck,
  Building2,
  KeyRound,
  FileCheck2,
  Radar,
  Search,
  BarChart2,
  Bell,
  BookOpen,
  Users,
  Plug,
  Cpu,
  TrendingUp,
  Calendar,
  RotateCcw,
  ClipboardList,
  Gavel,
  AlertTriangle,
  Stamp,
  X,
  ChevronLeft,
  PlusCircle,
  Ban,
} from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api } from "../lib/api";
import { Button, Input, Select, Textarea } from "./ui";
import { EmptyState } from "./EmptyState";
import { canManageCertificates, useAuthz } from "../lib/auth";
import { extractList } from "../lib/models";
import type { CaRecord, SearchResult, TemplateRecord } from "../lib/models";

type NavItem = {
  label: string;
  to: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  section: string;
};

const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", to: "/", icon: LayoutDashboard, section: "Pages" },
  {
    label: "Certificates",
    to: "/certificates",
    icon: ShieldCheck,
    section: "Pages",
  },
  {
    label: "Certificate Authorities",
    to: "/cas",
    icon: Building2,
    section: "Pages",
  },
  { label: "Keys", to: "/keys", icon: KeyRound, section: "Pages" },
  { label: "Templates", to: "/templates", icon: FileCheck2, section: "Pages" },
  { label: "Approvals inbox", to: "/inbox", icon: Stamp, section: "Pages" },
  { label: "Discovery", to: "/discovery", icon: Radar, section: "Pages" },
  { label: "Search", to: "/search", icon: Search, section: "Pages" },
  {
    label: "Crypto Posture",
    to: "/crypto-posture",
    icon: BarChart2,
    section: "Reports",
  },
  {
    label: "CA Health",
    to: "/reports/ca-health",
    icon: Building2,
    section: "Reports",
  },
  {
    label: "Expiry Timeline",
    to: "/reports/expiry-timeline",
    icon: Calendar,
    section: "Reports",
  },
  {
    label: "Revocation Activity",
    to: "/reports/revocation-activity",
    icon: RotateCcw,
    section: "Reports",
  },
  {
    label: "Issuance Velocity",
    to: "/reports/issuance-velocity",
    icon: TrendingUp,
    section: "Reports",
  },
  {
    label: "Change Audit",
    to: "/reports/change-audit",
    icon: ClipboardList,
    section: "Reports",
  },
  {
    label: "Compliance Evidence",
    to: "/reports/compliance-evidence",
    icon: Gavel,
    section: "Reports",
  },
  {
    label: "Algorithm Sunset",
    to: "/reports/algorithm-sunset",
    icon: AlertTriangle,
    section: "Reports",
  },
  { label: "Alerts", to: "/alerts", icon: Bell, section: "System" },
  { label: "Audit Log", to: "/audit", icon: BookOpen, section: "System" },
  { label: "Users", to: "/users", icon: Users, section: "System" },
  { label: "ACME", to: "/acme", icon: Plug, section: "System" },
  {
    label: "Enrollment Protocols",
    to: "/enrollment",
    icon: Plug,
    section: "System",
  },
  { label: "Agents", to: "/agents", icon: Cpu, section: "System" },
];

type ActionKind = "issue" | "renew" | "revoke";

const ACTIONS: {
  id: ActionKind;
  label: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
}[] = [
  { id: "issue", label: "Issue certificate…", icon: PlusCircle },
  { id: "renew", label: "Renew certificate…", icon: RotateCcw },
  { id: "revoke", label: "Revoke certificate…", icon: Ban },
];

function actionTitle(action: ActionKind): string {
  if (action === "issue") return "Issue certificate";
  if (action === "renew") return "Renew certificate";
  return "Revoke certificate";
}

type Target = { fingerprint: string; label: string };

type View =
  | { kind: "browse" }
  | { kind: "target"; action: ActionKind }
  | { kind: "form"; action: ActionKind; target?: Target };

const REASON_CODES = [
  { value: "0", label: "0 — Unspecified" },
  { value: "1", label: "1 — Key compromise" },
  { value: "2", label: "2 — CA compromise" },
  { value: "3", label: "3 — Affiliation changed" },
  { value: "4", label: "4 — Superseded" },
  { value: "5", label: "5 — Cessation of operation" },
  { value: "6", label: "6 — Certificate hold" },
  { value: "9", label: "9 — Privilege withdrawn" },
];

const emptyIssueForm = { templateId: "", caId: "", csrPem: "" };
const emptyRenewForm = { csrPem: "" };
const emptyRevokeForm = { reasonCode: "0", reasonText: "" };

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [view, setView] = useState<View>({ kind: "browse" });
  const focusOnMount = useCallback((el: HTMLInputElement | null) => {
    el?.focus();
  }, []);
  const [issueForm, setIssueForm] = useState(emptyIssueForm);
  const [renewForm, setRenewForm] = useState(emptyRenewForm);
  const [revokeForm, setRevokeForm] = useState(emptyRevokeForm);
  const [revokeConfirm, setRevokeConfirm] = useState("");
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const authz = useAuthz();
  const canManage = canManageCertificates(authz.data?.role, authz.data?.scopes);

  const reset = useCallback(() => {
    setQuery("");
    setView({ kind: "browse" });
    setIssueForm(emptyIssueForm);
    setRenewForm(emptyRenewForm);
    setRevokeForm(emptyRevokeForm);
    setRevokeConfirm("");
  }, []);

  const close = useCallback(() => {
    setOpen(false);
    reset();
  }, [reset]);

  // Keyboard shortcut: Cmd+K / Ctrl+K
  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((o) => !o);
      }
      if (e.key === "Escape") close();
    };
    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, [close]);

  // Live search via API
  const searchQ = useQuery({
    queryKey: ["cmd-search", query],
    queryFn: () => api.search(query),
    enabled: query.length >= 2,
    staleTime: 10_000,
  });
  const results = (searchQ.data?.data ?? []) as SearchResult[];
  const certResults = results.filter((r) => r.kind === "certificate");

  const templatesQ = useQuery({
    queryKey: ["cmd-templates"],
    queryFn: () => api.templates(),
    enabled: view.kind === "form" && view.action === "issue",
  });
  const casQ = useQuery({
    queryKey: ["cmd-cas"],
    queryFn: () => api.cas(),
    enabled: view.kind === "form" && view.action === "issue",
  });
  const templates = extractList<TemplateRecord>(templatesQ.data?.data, [
    "items",
  ]);
  const cas = extractList<CaRecord>(casQ.data?.data, ["items"]);

  const actionMutation = useMutation({
    mutationFn: async () => {
      if (view.kind !== "form") throw new Error("No pending action");
      if (view.action === "issue") {
        return api.issueCertificate({
          template_id: issueForm.templateId,
          ca_id: issueForm.caId,
          csr_pem: issueForm.csrPem,
        });
      }
      if (!view.target) throw new Error("No certificate selected");
      if (view.action === "renew") {
        return api.renewCertificate(view.target.fingerprint, {
          csr_pem: renewForm.csrPem,
        });
      }
      return api.revokeCertificate(view.target.fingerprint, {
        reason_code: Number(revokeForm.reasonCode),
        reason_text: revokeForm.reasonText,
      });
    },
    onSuccess: async (res) => {
      await queryClient.invalidateQueries({ queryKey: ["certificates"] });
      const pendingApproval =
        !!res &&
        typeof res === "object" &&
        (res as { status?: string }).status === "pending_approval";
      const action = view.kind === "form" ? view.action : "issue";
      const verb =
        action === "issue"
          ? "Certificate issuance"
          : action === "renew"
            ? "Certificate renewal"
            : "Certificate revocation";
      const inventoryOnly =
        action === "revoke" &&
        (res as { data?: { revocation_scope?: string } } | undefined)?.data
          ?.revocation_scope === "inventory_only";
      const headline = pendingApproval
        ? `${verb} submitted for approval`
        : `${verb} complete`;
      if (inventoryOnly) {
        toast.success(headline, {
          description:
            "Marked revoked in inventory — revoke at the issuing CA.",
        });
      } else {
        toast.success(headline);
      }
      close();
    },
    onError: (e) => {
      toast.error(
        e instanceof Error
          ? e.message
          : "The action failed. Check the form and try again.",
      );
    },
  });

  const go = useCallback(
    (to: string) => {
      close();
      navigate(to);
    },
    [navigate, close],
  );

  const startAction = (action: ActionKind) => {
    setQuery("");
    setView(
      action === "issue"
        ? { kind: "form", action }
        : { kind: "target", action },
    );
  };

  const selectTarget = (action: ActionKind, result: SearchResult) => {
    setQuery("");
    setView({
      kind: "form",
      action,
      target: { fingerprint: result.id, label: result.label },
    });
  };

  const handleBack = () => {
    if (view.kind === "form" && view.action !== "issue") {
      setView({ kind: "target", action: view.action });
    } else {
      setView({ kind: "browse" });
    }
    setQuery("");
  };

  if (!open) return null;

  return (
    <div
      role="presentation"
      className="fixed inset-0 z-[100] flex items-start justify-center pt-[15vh]"
      onClick={close}
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" />

      {/* Palette */}
      <div
        role="presentation"
        className="relative w-full max-w-xl mx-4 rounded-2xl border border-border bg-[var(--surface-1)] shadow-2xl shadow-black/60 overflow-hidden animate-in fade-in-0 zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        <Command shouldFilter={false} className="flex flex-col">
          {/* Header */}
          <div className="flex items-center gap-3 border-b border-border px-4 py-3.5">
            {view.kind !== "browse" && (
              <button
                type="button"
                onClick={handleBack}
                aria-label="Back"
                className="text-muted-foreground hover:text-foreground transition shrink-0"
              >
                <ChevronLeft size={16} />
              </button>
            )}
            {view.kind === "form" ? (
              <span className="flex-1 text-sm font-medium text-foreground">
                {actionTitle(view.action)}
                {view.target ? ` · ${view.target.label}` : ""}
              </span>
            ) : (
              <>
                <Search size={16} className="text-muted-foreground shrink-0" />
                <Command.Input
                  value={query}
                  onValueChange={setQuery}
                  placeholder={
                    view.kind === "target"
                      ? `Search certificates to ${view.action}…`
                      : "Search pages, certificates, CAs…"
                  }
                  className="flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground outline-none"
                  ref={focusOnMount}
                />
                {query && (
                  <button
                    type="button"
                    aria-label="Clear search"
                    onClick={() => setQuery("")}
                    className="text-muted-foreground hover:text-foreground transition"
                  >
                    <X size={14} />
                  </button>
                )}
              </>
            )}
            <kbd className="hidden sm:inline-flex items-center rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
              ESC
            </kbd>
          </div>

          {view.kind === "form" ? (
            <div className="max-h-[60vh] overflow-y-auto px-4 py-4">
              {view.action === "issue" && (
                <form
                  className="space-y-3"
                  onSubmit={(e) => {
                    e.preventDefault();
                    actionMutation.mutate();
                  }}
                >
                  <label className="block space-y-1 text-sm text-foreground">
                    <span>Template</span>
                    <Select
                      value={issueForm.templateId}
                      onChange={(e) =>
                        setIssueForm((f) => ({
                          ...f,
                          templateId: e.target.value,
                        }))
                      }
                      required
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
                  <label className="block space-y-1 text-sm text-foreground">
                    <span>CA</span>
                    <Select
                      value={issueForm.caId}
                      onChange={(e) =>
                        setIssueForm((f) => ({ ...f, caId: e.target.value }))
                      }
                      required
                    >
                      <option value="" disabled>
                        — select a CA —
                      </option>
                      {cas.map((ca) => (
                        <option key={ca.id} value={ca.id}>
                          {ca.display_name || ca.name || ca.id}
                        </option>
                      ))}
                    </Select>
                  </label>
                  <label className="block space-y-2 text-sm text-foreground">
                    <span>CSR PEM</span>
                    <Textarea
                      value={issueForm.csrPem}
                      onChange={(e) =>
                        setIssueForm((f) => ({ ...f, csrPem: e.target.value }))
                      }
                      rows={5}
                      placeholder="-----BEGIN CERTIFICATE REQUEST-----"
                      required
                    />
                  </label>
                  <div className="flex gap-2 pt-1">
                    <Button
                      tone="primary"
                      type="submit"
                      disabled={actionMutation.isPending}
                    >
                      Issue
                    </Button>
                    <Button onClick={handleBack}>Cancel</Button>
                  </div>
                </form>
              )}

              {view.action === "renew" && view.target && (
                <form
                  className="space-y-3"
                  onSubmit={(e) => {
                    e.preventDefault();
                    actionMutation.mutate();
                  }}
                >
                  <label className="block space-y-2 text-sm text-foreground">
                    <span>CSR PEM</span>
                    <Textarea
                      value={renewForm.csrPem}
                      onChange={(e) =>
                        setRenewForm((f) => ({ ...f, csrPem: e.target.value }))
                      }
                      rows={5}
                      placeholder="-----BEGIN CERTIFICATE REQUEST-----"
                      required
                    />
                  </label>
                  <div className="flex gap-2 pt-1">
                    <Button
                      tone="primary"
                      type="submit"
                      disabled={actionMutation.isPending}
                    >
                      Confirm renew
                    </Button>
                    <Button onClick={handleBack}>Cancel</Button>
                  </div>
                </form>
              )}

              {view.action === "revoke" && view.target && (
                <form
                  className="space-y-3"
                  onSubmit={(e) => {
                    e.preventDefault();
                    actionMutation.mutate();
                  }}
                >
                  <label className="block space-y-1 text-sm text-foreground">
                    <span>Reason code</span>
                    <Select
                      value={revokeForm.reasonCode}
                      onChange={(e) =>
                        setRevokeForm((f) => ({
                          ...f,
                          reasonCode: e.target.value,
                        }))
                      }
                    >
                      {REASON_CODES.map((r) => (
                        <option key={r.value} value={r.value}>
                          {r.label}
                        </option>
                      ))}
                    </Select>
                  </label>
                  <label className="block space-y-1 text-sm text-foreground">
                    <span>Reason text</span>
                    <Input
                      value={revokeForm.reasonText}
                      onChange={(e) =>
                        setRevokeForm((f) => ({
                          ...f,
                          reasonText: e.target.value,
                        }))
                      }
                      placeholder="Optional explanation"
                    />
                  </label>
                  <label className="block space-y-1 text-sm text-foreground">
                    <span>
                      Type <strong>REVOKE</strong> to confirm
                    </span>
                    <Input
                      value={revokeConfirm}
                      onChange={(e) => setRevokeConfirm(e.target.value)}
                      placeholder="REVOKE"
                    />
                  </label>
                  <div className="flex gap-2 pt-1">
                    <Button
                      tone="danger"
                      type="submit"
                      disabled={
                        actionMutation.isPending || revokeConfirm !== "REVOKE"
                      }
                    >
                      Confirm revoke
                    </Button>
                    <Button onClick={handleBack}>Cancel</Button>
                  </div>
                </form>
              )}
            </div>
          ) : (
            <Command.List className="max-h-[60vh] overflow-y-auto py-2">
              {view.kind === "target" ? (
                <>
                  <Command.Empty className="px-4 py-6">
                    <EmptyState
                      title={
                        query.length < 2
                          ? "Start typing to search"
                          : `No certificates match "${query}"`
                      }
                      description={`Search by common name or fingerprint to ${view.action} a certificate.`}
                    />
                  </Command.Empty>
                  {certResults.length > 0 && (
                    <Command.Group
                      heading={`Select a certificate to ${view.action}`}
                      className="[&_[cmdk-group-heading]]:px-4 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-widest [&_[cmdk-group-heading]]:text-muted-foreground"
                    >
                      {certResults.map((r) => (
                        <PaletteItem
                          key={r.id}
                          label={r.label}
                          hint={r.description}
                          icon={ShieldCheck}
                          onSelect={() => selectTarget(view.action, r)}
                        />
                      ))}
                    </Command.Group>
                  )}
                </>
              ) : (
                <>
                  <Command.Empty className="px-4 py-6">
                    <EmptyState
                      title={`No results for "${query}"`}
                      description="Try a different search term, or use an action below."
                    />
                  </Command.Empty>

                  {/* API search results */}
                  {results.length > 0 && (
                    <Command.Group
                      heading="Results"
                      className="[&_[cmdk-group-heading]]:px-4 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-widest [&_[cmdk-group-heading]]:text-muted-foreground"
                    >
                      {results.map((r) => (
                        <PaletteItem
                          key={r.id}
                          label={r.label}
                          hint={r.kind}
                          icon={
                            r.kind === "ca"
                              ? Building2
                              : r.kind === "template"
                                ? FileCheck2
                                : ShieldCheck
                          }
                          onSelect={() => go(r.url)}
                        />
                      ))}
                    </Command.Group>
                  )}

                  {/* Actions */}
                  {canManage &&
                    (() => {
                      const items = ACTIONS.filter(
                        (a) =>
                          !query ||
                          a.label.toLowerCase().includes(query.toLowerCase()),
                      );
                      if (items.length === 0) return null;
                      return (
                        <Command.Group
                          heading="Actions"
                          className="[&_[cmdk-group-heading]]:px-4 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-widest [&_[cmdk-group-heading]]:text-muted-foreground"
                        >
                          {items.map((a) => (
                            <PaletteItem
                              key={a.id}
                              label={a.label}
                              icon={a.icon}
                              onSelect={() => startAction(a.id)}
                            />
                          ))}
                        </Command.Group>
                      );
                    })()}

                  {/* Nav sections grouped */}
                  {(["Pages", "Reports", "System"] as const).map((section) => {
                    const items = NAV_ITEMS.filter((n) => {
                      if (n.section !== section) return false;
                      if (!query) return true;
                      return n.label
                        .toLowerCase()
                        .includes(query.toLowerCase());
                    });
                    if (items.length === 0) return null;
                    return (
                      <Command.Group
                        key={section}
                        heading={section}
                        className="[&_[cmdk-group-heading]]:px-4 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-widest [&_[cmdk-group-heading]]:text-muted-foreground"
                      >
                        {items.map((item) => (
                          <PaletteItem
                            key={item.to}
                            label={item.label}
                            icon={item.icon}
                            onSelect={() => go(item.to)}
                          />
                        ))}
                      </Command.Group>
                    );
                  })}
                </>
              )}
            </Command.List>
          )}

          {/* Footer hint */}
          <div className="border-t border-border px-4 py-2 flex items-center gap-3 text-[10px] text-muted-foreground">
            <span>
              <kbd className="font-mono">↑↓</kbd> navigate
            </span>
            <span>
              <kbd className="font-mono">↵</kbd>{" "}
              {view.kind === "form" ? "submit" : "open"}
            </span>
            <span>
              <kbd className="font-mono">⌘K</kbd> toggle
            </span>
          </div>
        </Command>
      </div>
    </div>
  );
}

function PaletteItem({
  label,
  hint,
  icon: Icon,
  onSelect,
}: {
  label: string;
  hint?: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  onSelect: () => void;
}) {
  return (
    <Command.Item
      onSelect={onSelect}
      className="flex items-center gap-3 px-4 py-2.5 text-sm text-foreground cursor-pointer data-[selected=true]:bg-accent data-[selected=true]:text-foreground transition-colors outline-none"
    >
      <div className="w-6 h-6 rounded-md bg-muted flex items-center justify-center shrink-0">
        <Icon size={13} className="text-muted-foreground" />
      </div>
      <span className="flex-1 truncate">{label}</span>
      {hint && (
        <span className="text-[10px] text-muted-foreground uppercase tracking-wider">
          {hint}
        </span>
      )}
    </Command.Item>
  );
}
