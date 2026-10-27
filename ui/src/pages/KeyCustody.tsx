import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Badge, Button, Input, Panel, StateMessage, formatDateTime } from "../components/ui";
import { humanizeEnum } from "../lib/utils";
import { PageHeader } from "../components/PageHeader";
import { ReportSkeleton } from "../components/Skeletons";

// Mirrors getKeyCustodyReport in the generated types; the generated `keys`
// entry is not usable through api.keyCustody()'s Record<string, unknown>, so
// the page casts, as the other report pages do.
type CustodyEvent = {
  action: string;
  occurred_at: string;
  requester: string;
  approver: string;
  redeemer: string;
  dual_control: boolean;
  approval_id?: string;
};
type CustodyKey = {
  key_id: string;
  algorithm: string;
  created_at?: string;
  backend: string;
  rotation_count: number;
  last_rotated_at?: string;
  access_count: number;
  last_accessed_at?: string;
  deleted?: boolean;
  imported?: boolean;
  events?: CustodyEvent[];
};
type CustodyData = {
  generated_at: string;
  backend: string;
  dual_control_escrow: boolean;
  keys?: CustodyKey[];
  event_counts?: Record<string, number>;
  truncated?: boolean;
};

function fmt(x?: string): string {
  if (!x) return "-";
  return formatDateTime(x);
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div data-testid={`field-${label}`} className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="text-sm text-foreground truncate">{value || "-"}</dd>
    </div>
  );
}

function EventRow({ ev }: { ev: CustodyEvent }) {
  return (
    <li className="rounded-xl border border-border/50 px-3 py-2 space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-mono text-sm">{ev.action}</span>
        <span className="text-xs text-muted-foreground">
          {fmt(ev.occurred_at)}
        </span>
      </div>
      <dl className="grid grid-cols-3 gap-3">
        <Field label="Requester" value={ev.requester} />
        <Field
          label="Approver"
          value={
            ev.approver || (ev.dual_control ? "" : "None (dual control off)")
          }
        />
        <Field label="Redeemer" value={ev.redeemer} />
      </dl>
    </li>
  );
}

export default function KeyCustody() {
  const q = useQuery({
    queryKey: ["report-key-custody"],
    queryFn: api.keyCustody,
  });
  const [filter, setFilter] = useState("");
  const report = q.data?.data as unknown as CustodyData | undefined;
  const keys = report?.keys ?? [];
  const needle = filter.trim().toLowerCase();
  const shown = keys.filter((k) => k.key_id.toLowerCase().includes(needle));
  const counts = Object.entries(report?.event_counts ?? {});

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto fade-in-up">
      <PageHeader
        eyebrow="Reports"
        title="Key Custody"
        description="Where each key lives, when it was rotated, and who requested, approved and redeemed every export, escrow and destroy."
      />

      {q.isLoading && <ReportSkeleton tiles={3} />}
      {q.error && (
        <StateMessage
          tone="error"
          title="Report unavailable"
          message={(q.error as Error).message}
        />
      )}

      {report && (
        <>
          <Panel title="Summary">
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <span>
                Backend: <span className="font-mono">{report.backend}</span>
              </span>
              <Badge tone={report.dual_control_escrow ? "success" : "neutral"}>
                {`Dual-control escrow ${report.dual_control_escrow ? "on" : "off"}`}
              </Badge>
              <span className="text-xs text-muted-foreground">
                Generated {fmt(report.generated_at)}
              </span>
            </div>
            {counts.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-2">
                {counts.map(([action, n]) => (
                  <Badge key={action}>{`${humanizeEnum(action)}: ${n}`}</Badge>
                ))}
              </div>
            )}
            {report.truncated && (
              <p className="mt-3 text-xs text-muted-foreground">
                The audit trail exceeded the read limit; older events may be
                missing.
              </p>
            )}
          </Panel>

          {keys.length > 0 && (
            <Input
              aria-label="Filter by key"
              placeholder="Filter by key id"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          )}

          {keys.length === 0 && (
            <StateMessage tone="neutral" title="No keys in the keystore" />
          )}
          {keys.length > 0 && shown.length === 0 && (
            <StateMessage
              tone="neutral"
              title={`No keys match "${filter.trim()}"`}
              action={
                <Button onClick={() => setFilter("")}>Clear filter</Button>
              }
            />
          )}

          {shown.map((k) => {
            const events = k.events ?? [];
            return (
              <Panel key={k.key_id} title={k.key_id}>
                {(k.deleted || k.imported) && (
                  <div className="mb-3 flex gap-2">
                    {k.deleted && <Badge tone="danger">Deleted</Badge>}
                    {k.imported && <Badge tone="info">Imported</Badge>}
                  </div>
                )}
                <dl className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm">
                  <Field label="Algorithm" value={k.algorithm} />
                  <Field label="Backend" value={k.backend} />
                  <Field label="Created" value={fmt(k.created_at)} />
                  <Field
                    label="Rotations"
                    value={
                      k.rotation_count === 0
                        ? "Never"
                        : `${k.rotation_count} (last ${fmt(k.last_rotated_at)})`
                    }
                  />
                  <Field label="Accesses" value={String(k.access_count)} />
                </dl>
                <h3 className="mt-4 mb-2 text-sm font-semibold">
                  Custody events
                </h3>
                {events.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    No custody events recorded
                  </p>
                ) : (
                  <ul className="space-y-2">
                    {events.map((ev, i) => (
                      <EventRow key={`${ev.occurred_at}-${i}`} ev={ev} />
                    ))}
                  </ul>
                )}
              </Panel>
            );
          })}
        </>
      )}
    </div>
  );
}
