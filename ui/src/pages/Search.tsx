import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import {
  Badge,
  Button,
  Input,
  Panel,
  StateMessage,
} from "../components/ops-ui";
import { PageHeader } from "../components/PageHeader";
import { useDebouncedValue } from "../lib/useDebouncedValue";
import type { SearchResult } from "../lib/models";

const tonemap: Record<
  string,
  "info" | "warning" | "success" | "neutral" | "danger"
> = {
  certificate: "info",
  ca: "success",
  endpoint: "warning",
  template: "neutral",
};

export default function Search() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState(searchParams.get("q") ?? "");
  const debouncedQ = useDebouncedValue(query.trim(), 300);

  const searchQuery = useQuery({
    queryKey: ["search", debouncedQ],
    queryFn: () => api.search(debouncedQ),
    enabled: debouncedQ.length > 0,
  });

  const results: SearchResult[] = searchQuery.data?.data ?? [];

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Lookup"
        title="Global Search"
        description="Search certificates, authorities, templates, and endpoints from one place."
      />

      <Panel
        title="Search"
        subtitle="Type at least one character to search across all inventory surfaces"
      >
        <div className="grid gap-3 md:grid-cols-[1fr_auto]">
          <label className="space-y-2 text-sm text-foreground">
            <span>Query</span>
            <Input
              aria-label="Search all inventory"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search by name, fingerprint, host, or action"
            />
          </label>
          <Button onClick={() => setQuery("")}>Clear</Button>
        </div>
      </Panel>

      {searchQuery.isLoading ? (
        <StateMessage
          title="Searching"
          message="Pulling inventory from all surfaces..."
        />
      ) : null}
      {searchQuery.error ? (
        <StateMessage
          tone="error"
          title="Search unavailable"
          message="Server search failed."
        />
      ) : null}

      <Panel
        title={`Results${debouncedQ ? ` · ${results.length}` : ""}`}
        subtitle="Unified lookup results"
      >
        {debouncedQ ? (
          <div className="grid gap-3">
            {results.map((result) => (
              <button
                key={`${result.kind}-${result.id}`}
                type="button"
                onClick={() => result.url && navigate(result.url)}
                className="w-full rounded-2xl border border-border bg-background/60 p-4 text-left transition hover:border-primary focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="font-semibold text-foreground">
                      {result.label}
                    </div>
                    {result.description ? (
                      <div className="mt-1 text-sm text-muted-foreground">
                        {result.description}
                      </div>
                    ) : null}
                  </div>
                  <Badge tone={tonemap[result.kind] ?? "neutral"}>
                    {result.kind}
                  </Badge>
                </div>
              </button>
            ))}
            {results.length === 0 && !searchQuery.isLoading ? (
              <StateMessage
                title="No matches"
                message="Try a different fingerprint, hostname, or action name."
              />
            ) : null}
          </div>
        ) : (
          <StateMessage
            title="Start typing"
            message="Search across the full inventory with one query."
          />
        )}
      </Panel>
    </div>
  );
}
