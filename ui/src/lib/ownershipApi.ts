import { fetchJSON } from "./api";

export type OrphanedOwner = { user_id: string; owner_email: string; cert_count: number };

export const listOrphans = () =>
  fetchJSON<{ data: OrphanedOwner[] }>("/ownership/orphans");

export const reassignOrphans = (b: { from_email: string; to_team: string; to_email?: string }) =>
  fetchJSON<{ data: { reassigned: number } }>("/ownership/reassign", {
    method: "POST",
    body: JSON.stringify(b),
  });
