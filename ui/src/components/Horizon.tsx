import { useMemo } from "react";
import type { CertificateRecord } from "../lib/models";
import { buildHorizon, type HorizonState } from "../lib/horizon";

const STATE_BAR: Record<HorizonState, string> = {
  auto: "bg-state-auto",
  attn: "bg-state-attn",
  over: "bg-state-over",
};

const STATE_LABEL: Record<HorizonState, string> = {
  auto: "renews itself",
  attn: "needs attention",
  over: "overdue",
};

function formatDay(d: Date) {
  return d.toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

export function Horizon({
  certificates,
  now = new Date(),
  windowDays = 90,
}: {
  certificates: CertificateRecord[];
  now?: Date;
  windowDays?: number;
}) {
  const horizon = useMemo(
    () => buildHorizon(certificates, now, windowDays),
    [certificates, now, windowDays],
  );

  if (horizon.totalInWindow === 0) {
    return (
      <div className="rounded-lg border border-border bg-muted/40 px-4 py-6 text-sm text-muted-foreground">
        Nothing expires in the next {windowDays} days.
      </div>
    );
  }

  const peakDay = horizon.days.find((d) => d.total === horizon.peak);
  const chartLabel = `Bar chart: certificates expiring per day over the next ${windowDays} days, ${horizon.totalInWindow} in total, peak ${horizon.peak}${peakDay ? ` on ${formatDay(peakDay.date)}` : ""}. A table with the same data follows.`;

  return (
    <section aria-labelledby="horizon-heading" className="space-y-3">
      <div className="flex items-baseline justify-between gap-4">
        <h2 id="horizon-heading" className="text-sm font-medium text-foreground">
          Next {windowDays} days
        </h2>
        <ul className="flex flex-wrap items-center gap-x-4 gap-y-1">
          {(["auto", "attn", "over"] as const).map((s) => (
            <li key={s} className="flex items-center gap-1.5">
              <span className={`h-2 w-2 rounded-[2px] ${STATE_BAR[s]}`} aria-hidden="true" />
              <span className="text-xs text-muted-foreground">{STATE_LABEL[s]}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* The chart is decorative for assistive tech — the table below it
          carries the same numbers, so nobody depends on reading colour. */}
      <div
        role="img"
        aria-label={chartLabel}
        className="rounded-lg border border-border bg-muted/40 p-3"
      >
        <div className="flex h-28 items-end gap-px" aria-hidden="true">
          {horizon.days.map((day) => (
            <div
              key={day.offset}
              className="group relative flex-1"
              style={{ height: "100%" }}
            >
              <div
                className={`absolute bottom-0 w-full rounded-[1px] ${STATE_BAR[day.state]}`}
                style={{
                  height: horizon.peak ? `${(day.total / horizon.peak) * 100}%` : "0%",
                  minHeight: day.total > 0 ? "2px" : "0",
                }}
              />
            </div>
          ))}
        </div>
        <div className="mt-2 flex justify-between border-t border-border pt-2">
          {[0, 0.25, 0.5, 0.75, 1].map((f) => {
            const i = Math.min(horizon.days.length - 1, Math.round(f * (windowDays - 1)));
            return (
              <span key={f} className="font-mono text-[10px] text-muted-foreground">
                {f === 0 ? "today" : formatDay(horizon.days[i].date)}
              </span>
            );
          })}
        </div>
      </div>

      {horizon.cliff && horizon.cliff.needsHuman > 0 && (
        <p className="rounded-r-md border-l-[3px] border-state-over bg-state-over/10 px-3 py-2 text-sm text-foreground">
          <strong className="font-mono">{horizon.cliff.needsHuman}</strong> of{" "}
          <strong className="font-mono">{horizon.cliff.total}</strong> certificates{" "}
          {horizon.cliff.expired === 0 ? (
            <>
              expiring on <strong>{formatDay(horizon.cliff.date)}</strong> will not renew
              themselves.
            </>
          ) : horizon.cliff.expired === horizon.cliff.total ? (
            <>
              <strong>have already expired</strong> and will not renew themselves.
            </>
          ) : (
            <>
              <strong>have expired or expire today</strong> and will not renew themselves.
            </>
          )}
        </p>
      )}

      {/* Text equivalent. Visually hidden, but it is the same data — a
          screen reader gets the horizon, not a shrug. */}
      <div className="sr-only">
        <table>
          <caption>
            Certificates expiring in the next {windowDays} days: {horizon.totalInWindow} total,{" "}
            {horizon.needsHuman} needing a human.
          </caption>
          <thead>
            <tr>
              <th scope="col">Date</th>
              <th scope="col">Expiring</th>
              <th scope="col">Needs a human</th>
            </tr>
          </thead>
          <tbody>
            {horizon.days
              .filter((d) => d.total > 0)
              .map((d) => (
                <tr key={d.offset}>
                  <td>{formatDay(d.date)}</td>
                  <td>{d.total}</td>
                  <td>{d.counts.attn + d.counts.over}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
