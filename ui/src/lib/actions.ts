import { api } from "./api";

// Shared action helpers for report/posture surfaces that need to *do*
// something with what they show, not just render it. Every action here
// either calls a real backend endpoint (real delivery — W4-01/W4-02) or
// hands off to the certificate workflow that already enforces a human
// confirmation step before it executes (Certificates.tsx renew/revoke
// dialogs) — never a silent, unconfirmed mutation.

export type ActionOutcome =
  { ok: true; message: string } | { ok: false; message: string };

export const NOTIFY_CHANNELS = [
  "email",
  "slack",
  "pagerduty",
  "webhook",
] as const;
export type NotifyChannel = (typeof NOTIFY_CHANNELS)[number];

export function isNotifyChannel(value: string): value is NotifyChannel {
  return (NOTIFY_CHANNELS as readonly string[]).includes(value);
}

// renewalPath points at the certificate workflow filtered to the CA this
// report row is about. ca_id is an exact-match filter server-side (unlike
// owner_team, which the report aggregates as free text), so this is the
// one filter guaranteed to land the operator on the right certificates.
export function renewalPath(caId: string): string {
  return `/certificates?ca_id=${encodeURIComponent(caId)}`;
}

// expiredCertificatesPath hands off to the certificate workflow filtered to
// the one exact-match status value the report's expiry buckets can vouch
// for. The other buckets are day-windows with no equivalent server-side
// filter, so only "expired" gets a link — same discipline as renewalPath
// skipping the "unknown" CA.
export function expiredCertificatesPath(): string {
  return "/certificates?status=expired";
}

// notifyOwnerTeam sends a real notification (approved by the operator
// typing in a live delivery target before submit) rather than assuming an
// address the report doesn't have for a team.
export async function notifyOwnerTeam(
  team: string,
  channel: NotifyChannel,
  target: string,
): Promise<ActionOutcome> {
  const trimmedTeam = team.trim();
  const trimmedTarget = target.trim();
  if (!trimmedTeam) {
    return { ok: false, message: "An owner team is required." };
  }
  if (!trimmedTarget) {
    return { ok: false, message: "A delivery target is required." };
  }
  try {
    const res = await api.testNotificationDelivery({
      channel,
      target: trimmedTarget,
      message: `Certificate expiry review requested for owner team "${trimmedTeam}".`,
    });
    return {
      ok: true,
      message: `Notification ${res.data.delivery.status} to ${trimmedTarget} via ${channel}.`,
    };
  } catch (err) {
    return { ok: false, message: (err as Error).message };
  }
}

// openPqcWave derives PQC migration waves from current inventory for real
// (the same action the PQC Migration page's "Auto-derive waves" button
// performs) so the operator can jump straight from "certs are expiring" to
// "here's the migration wave that covers them".
export async function openPqcWave(): Promise<ActionOutcome> {
  try {
    const res = await api.autoDerivePqcWaves();
    const count = res.data.length;
    return {
      ok: true,
      message: `PQC migration wave opened — ${count} wave${count === 1 ? "" : "s"} active.`,
    };
  } catch (err) {
    return { ok: false, message: (err as Error).message };
  }
}
