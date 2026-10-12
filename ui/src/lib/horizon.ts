import type { CertificateRecord } from "./models";

// W-UI: the expiry horizon.
//
// The primary user's job is making sure renewals happen without them. The
// question that answers is not "how many certificates exist" but "what is
// coming, and is it handled" — so the horizon is organised by TIME, and
// every certificate is coloured by whether it renews itself.

export type HorizonState = "auto" | "attn" | "over";

export type HorizonDay = {
  /** Days from today. 0 is today. */
  offset: number;
  date: Date;
  total: number;
  /** Worst state present that day — that is what the eye should catch. */
  state: HorizonState;
  counts: Record<HorizonState, number>;
};

export type Horizon = {
  days: HorizonDay[];
  /** Busiest single day, so the bars can be scaled against something real. */
  peak: number;
  totalInWindow: number;
  needsHuman: number;
  /** The densest run of days that is not fully automated, or null. */
  cliff: { offset: number; date: Date; total: number; needsHuman: number } | null;
};

/** Renewal methods that happen without a person. */
const AUTOMATED = new Set(["acme", "est", "scep", "api"]);

export function certificateState(cert: CertificateRecord, now: Date): HorizonState {
  const until = cert.valid_until ? new Date(cert.valid_until) : null;
  if (until && until.getTime() < now.getTime()) return "over";
  const method = (cert.renewal_method ?? "").toLowerCase();
  // An unknown method is NOT assumed automated. Claiming a certificate is
  // handled when we cannot tell is the one error this view must not make.
  return AUTOMATED.has(method) ? "auto" : "attn";
}

function startOfDay(d: Date): Date {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate());
}

export function buildHorizon(
  certs: CertificateRecord[],
  now: Date,
  windowDays = 90,
): Horizon {
  const today = startOfDay(now);
  const days: HorizonDay[] = Array.from({ length: windowDays }, (_, offset) => {
    const date = new Date(today);
    date.setDate(today.getDate() + offset);
    return {
      offset,
      date,
      total: 0,
      state: "auto" as HorizonState,
      counts: { auto: 0, attn: 0, over: 0 },
    };
  });

  let totalInWindow = 0;
  let needsHuman = 0;

  for (const cert of certs) {
    if (!cert.valid_until) continue;
    const until = new Date(cert.valid_until);
    if (Number.isNaN(until.getTime())) continue;

    const state = certificateState(cert, now);
    const offset = Math.floor(
      (startOfDay(until).getTime() - today.getTime()) / 86_400_000,
    );

    // Already expired: it is work today, not history. Fold it into day 0 so
    // it cannot fall off the left edge and be forgotten.
    const slot = offset < 0 ? 0 : offset;
    if (slot >= windowDays) continue;

    const day = days[slot];
    day.total += 1;
    day.counts[state] += 1;
    totalInWindow += 1;
    if (state !== "auto") needsHuman += 1;
  }

  for (const day of days) {
    day.state = day.counts.over > 0 ? "over" : day.counts.attn > 0 ? "attn" : "auto";
  }

  const peak = days.reduce((m, d) => Math.max(m, d.total), 0);

  // The cliff is the day carrying the most certificates that will NOT renew
  // themselves — the thing most likely to page someone.
  let cliff: Horizon["cliff"] = null;
  for (const day of days) {
    const dayNeedsHuman = day.counts.attn + day.counts.over;
    if (dayNeedsHuman === 0) continue;
    if (!cliff || dayNeedsHuman > cliff.needsHuman) {
      cliff = { offset: day.offset, date: day.date, total: day.total, needsHuman: dayNeedsHuman };
    }
  }

  return { days, peak, totalInWindow, needsHuman, cliff };
}
