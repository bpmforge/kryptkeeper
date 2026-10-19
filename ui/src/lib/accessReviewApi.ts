import type { components } from "../generated/api-types";
import { fetchJSON } from "./api";

export type AccessReviewReport = components["schemas"]["AccessReviewReport"];
export type AccessReviewPrincipal = components["schemas"]["AccessReviewPrincipal"];
export type AccessReviewEntry = components["schemas"]["AccessReviewEntry"];
export type Campaign = components["schemas"]["AccessReviewCampaign"];
export type Decision = "keep" | "revoke" | "modify";
export type DecisionBody = { entry_id: string; decision: Decision; new_role?: string; note?: string };

const base = "/admin/access-review";

export const accessReviewApi = {
  report: (periodDays = 90) =>
    fetchJSON<{ data: AccessReviewReport }>(`${base}/report?period_days=${periodDays}`),
  // The list envelope is { data: { items } }, per the OpenAPI contract.
  campaigns: () => fetchJSON<{ data: { items?: Campaign[] } }>(`${base}/campaigns`),
  campaign: (id: string) => fetchJSON<{ data: Campaign }>(`${base}/campaigns/${encodeURIComponent(id)}`),
  open: (name: string, periodDays = 90) =>
    fetchJSON<{ data: Campaign }>(`${base}/campaigns`, {
      method: "POST",
      body: JSON.stringify({ name, period_days: periodDays }),
    }),
  decide: (id: string, body: DecisionBody) =>
    fetchJSON<{ data: AccessReviewEntry }>(`${base}/campaigns/${encodeURIComponent(id)}/decisions`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  close: (id: string, allowUndecided = false) =>
    fetchJSON<{ data: Campaign }>(`${base}/campaigns/${encodeURIComponent(id)}/close`, {
      method: "POST",
      body: JSON.stringify({ allow_undecided: allowUndecided }),
    }),
};
