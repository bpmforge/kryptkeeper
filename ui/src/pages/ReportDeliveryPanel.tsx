import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { api } from "../lib/api";
import { Button, Input, Panel, Select, StateMessage } from "../components/ui";
import type { ReportSchedule } from "../lib/models";

// W38-06: schedule any report the hub can render as CSV, XLSX or PDF. The
// report/format matrix comes from the server catalog, never hard-coded here.
export function ReportDeliveryPanel() {
  const queryClient = useQueryClient();
  const catalogQuery = useQuery({
    queryKey: ["report-schedule-catalog"],
    queryFn: api.reportScheduleCatalog,
    staleTime: 300_000,
  });
  const schedulesQuery = useQuery({
    queryKey: ["report-schedules"],
    queryFn: api.reportSchedules,
    staleTime: 30_000,
  });
  const catalog = catalogQuery.data?.data ?? [];
  const schedules: ReportSchedule[] = schedulesQuery.data?.data ?? [];
  const titleOf = (name: string) =>
    catalog.find((c) => c.report === name)?.title ?? name;

  const [report, setReport] = useState("");
  const [format, setFormat] = useState("");
  const [cadence, setCadence] = useState("weekly");
  const [recipients, setRecipients] = useState("");

  const selected = catalog.find((c) => c.report === report) ?? catalog[0];
  const formats = selected?.formats ?? [];
  const effectiveFormat = formats.includes(format)
    ? format
    : (formats[0] ?? "");

  const parseRecipients = () =>
    recipients
      .split(",")
      .map((r) => r.trim())
      .filter(Boolean);

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["report-schedules"] });

  const createMutation = useMutation({
    mutationFn: () =>
      api.createReportSchedule({
        report: selected?.report ?? "",
        format: effectiveFormat,
        cadence,
        recipients: parseRecipients(),
        enabled: true,
      }),
    onSuccess: async () => {
      setRecipients("");
      await invalidate();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteReportSchedule(id),
    onSuccess: invalidate,
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <Panel
      title="Report Delivery"
      subtitle="Scheduled reports by email as CSV, XLSX or PDF (requires SMTP). A failed send is retried 3 times, then raises report.delivery_failed."
    >
      <div className="space-y-4">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            createMutation.mutate();
          }}
        >
          <div>
            <label
              htmlFor="rd-report"
              className="text-xs text-muted-foreground"
            >
              Report
            </label>
            <Select
              id="rd-report"
              value={selected?.report ?? ""}
              onChange={(e) => setReport(e.target.value)}
            >
              {catalog.map((c) => (
                <option key={c.report} value={c.report}>
                  {c.title}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <label
              htmlFor="rd-format"
              className="text-xs text-muted-foreground"
            >
              Format
            </label>
            <Select
              id="rd-format"
              value={effectiveFormat}
              onChange={(e) => setFormat(e.target.value)}
            >
              {formats.map((f) => (
                <option key={f} value={f}>
                  {f.toUpperCase()}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <label
              htmlFor="rd-cadence"
              className="text-xs text-muted-foreground"
            >
              Cadence
            </label>
            <Select
              id="rd-cadence"
              value={cadence}
              onChange={(e) => setCadence(e.target.value)}
            >
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </Select>
          </div>
          <div className="grow">
            <label
              htmlFor="rd-recipients"
              className="text-xs text-muted-foreground"
            >
              Recipients (comma-separated)
            </label>
            <Input
              id="rd-recipients"
              value={recipients}
              onChange={(e) => setRecipients(e.target.value)}
              placeholder="board@example.com, ciso@example.com"
            />
          </div>
          <Button
            type="submit"
            tone="primary"
            disabled={
              createMutation.isPending ||
              parseRecipients().length === 0 ||
              !selected
            }
          >
            <Plus size={13} aria-hidden="true" />
            Add report schedule
          </Button>
        </form>

        {createMutation.isError ? (
          <p className="text-xs text-state-over">
            {createMutation.error instanceof Error
              ? createMutation.error.message
              : "Could not create schedule."}
          </p>
        ) : null}

        {schedulesQuery.isLoading ? (
          <StateMessage title="Loading" message="Fetching report schedules…" />
        ) : schedulesQuery.error ? (
          <StateMessage
            tone="error"
            title="Unavailable"
            message="Report schedules could not be loaded."
          />
        ) : schedules.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No scheduled reports. Add one above to email a report on a cadence.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                <th className="py-2 pr-4">Report</th>
                <th className="py-2 pr-4">Format</th>
                <th className="py-2 pr-4">Cadence</th>
                <th className="py-2 pr-4">Recipients</th>
                <th className="py-2 pr-4">Last sent</th>
                <th className="py-2 pr-4" />
              </tr>
            </thead>
            <tbody>
              {schedules.map((s) => (
                <tr key={s.id} className="border-b border-border">
                  <td className="py-2 pr-4 text-foreground">
                    {titleOf(s.report)}
                  </td>
                  <td className="py-2 pr-4 text-foreground">
                    {s.format.toUpperCase()}
                  </td>
                  <td className="py-2 pr-4 text-foreground">{s.cadence}</td>
                  <td className="py-2 pr-4 text-foreground">
                    {s.recipients.join(", ")}
                  </td>
                  <td className="py-2 pr-4 text-muted-foreground">
                    {s.last_sent_at
                      ? new Date(s.last_sent_at).toLocaleDateString()
                      : "—"}
                  </td>
                  <td className="py-2 pr-4">
                    <Button
                      tone="danger"
                      aria-label={`Delete ${titleOf(s.report)} schedule`}
                      onClick={() => deleteMutation.mutate(s.id)}
                      disabled={deleteMutation.isPending}
                    >
                      <Trash2 size={13} aria-hidden="true" />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Panel>
  );
}
