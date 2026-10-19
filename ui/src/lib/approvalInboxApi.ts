import { fetchJSON, queryString } from "./api";

export type InboxItemType = "certificate_approval" | "pending_action";

export type InboxItem = {
  type: InboxItemType;
  id: string;
  summary: string;
  requester: string;
  tenant: string;
  created_at: string;
  age_seconds: number;
  action_type?: string;
};

export type InboxQuery = {
  type?: InboxItemType;
  min_age?: string;
  tenant?: string;
  limit?: number;
  offset?: number;
};

// 202 body when an n-of-m action has recorded this approval but not reached
// quorum; every other success carries a different (or empty) body.
export type QuorumProgress = { status?: string; approvals: number; required: number };

export function quorumProgress(res: unknown): QuorumProgress | null {
  const d = (res as { data?: Partial<QuorumProgress> } | undefined)?.data;
  if (d && typeof d.approvals === "number" && typeof d.required === "number") {
    return { status: d.status, approvals: d.approvals, required: d.required };
  }
  return null;
}

export const approvalInboxApi = {
  list: (q?: InboxQuery) =>
    fetchJSON<{ data: InboxItem[]; meta?: { total?: number } }>(
      `/approvals/inbox${queryString(q)}`,
    ),
  approve: (t: InboxItemType, id: string) =>
    fetchJSON<unknown>(`/approvals/inbox/${t}/${encodeURIComponent(id)}/approve`, {
      method: "POST",
    }),
  reject: (t: InboxItemType, id: string, reason: string) =>
    fetchJSON<unknown>(`/approvals/inbox/${t}/${encodeURIComponent(id)}/reject`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
};
