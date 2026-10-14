import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { extractList } from "./models";
import type { CaRecord, TemplateRecord } from "./models";

// Display-only lookups: callers fall back to the raw ID (and keep it as a
// tooltip) when no name resolves. Shares the ["cas"/"templates", {limit:200}]
// cache keys with the pages that already list them.
const LIMIT = 200;

type Named = { id: string; display_name?: string; name?: string };

function toNameMap(items: Named[]): Map<string, string> {
  return new Map(
    items
      .filter((i) => i.display_name || i.name)
      .map((i) => [i.id, (i.display_name || i.name) as string]),
  );
}

export function useCaNames() {
  const q = useQuery({
    queryKey: ["cas", { limit: LIMIT }],
    queryFn: () => api.cas({ limit: LIMIT }),
  });
  return {
    names: toNameMap(extractList<CaRecord>(q.data?.data, ["items"])),
    ready: !q.isLoading,
  };
}

export function useTemplateNames() {
  const q = useQuery({
    queryKey: ["templates", { limit: LIMIT }],
    queryFn: () => api.templates({ limit: LIMIT }),
  });
  return {
    names: toNameMap(extractList<TemplateRecord>(q.data?.data, ["items"])),
    ready: !q.isLoading,
  };
}
