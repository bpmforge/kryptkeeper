import { useQuery } from "@tanstack/react-query";
import { scrollableProps } from "../lib/scrollable";
import { RefreshCw } from "lucide-react";
import { api } from "../lib/api";
import {
  Badge,
  Button,
  MetricCard,
  Panel,
  StateMessage,
  formatDateTime,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";

function gradeTone(
  grade?: string,
): "neutral" | "success" | "warning" | "danger" {
  switch (grade) {
    case "A":
      return "success";
    case "B":
    case "C":
      return "warning";
    case "D":
    case "F":
      return "danger";
    default:
      return "neutral";
  }
}

export default function CodeSigning() {
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["code-signing-inventory"],
    queryFn: api.codeSigningInventory,
    staleTime: 60_000,
  });

  const inv = data?.data;

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Operations"
        title="Code-Signing Inventory"
        description="Certificates whose extended key usage includes code signing."
        actions={
          <Button
            tone="secondary"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RefreshCw size={13} aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      {isLoading ? (
        <StateMessage title="Loading" message="Building inventory…" />
      ) : error || !inv ? (
        <StateMessage
          tone="error"
          title="Inventory unavailable"
          message={
            error instanceof Error
              ? error.message
              : "The code-signing inventory could not be loaded."
          }
        />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
            <MetricCard label="Code-signing certs" value={inv.total} />
            <MetricCard
              label="Expired"
              value={inv.expired}
              tone={inv.expired > 0 ? "danger" : "neutral"}
            />
            <MetricCard
              label="Revoked"
              value={inv.revoked}
              tone={inv.revoked > 0 ? "warning" : "neutral"}
            />
          </div>

          <Panel title="Certificates">
            {inv.certs.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No code-signing certificates found. Issue a certificate with the
                code-signing extended key usage to populate this inventory.
              </p>
            ) : (
              <div className="overflow-x-auto" {...scrollableProps}>
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                      <th className="py-2 pr-4">Common name</th>
                      <th className="py-2 pr-4">Issuer</th>
                      <th className="py-2 pr-4">Algorithm</th>
                      <th className="py-2 pr-4">Expires</th>
                      <th className="py-2 pr-4">Grade</th>
                      <th className="py-2 pr-4">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {inv.certs.map((c) => (
                      <tr
                        key={c.fingerprint_sha256}
                        className="border-b border-border"
                      >
                        <td className="py-2 pr-4 text-foreground">
                          {c.common_name || c.fingerprint_sha256.slice(0, 16)}
                        </td>
                        <td className="py-2 pr-4 text-foreground">
                          {c.issuer_cn || "—"}
                        </td>
                        <td className="py-2 pr-4 text-foreground">
                          {c.public_key_algorithm || "—"}
                          {c.key_size_bits ? ` ${c.key_size_bits}-bit` : ""}
                        </td>
                        <td className="py-2 pr-4 text-foreground whitespace-nowrap">
                          {c.valid_until
                            ? formatDateTime(c.valid_until)
                            : "—"}
                        </td>
                        <td className="py-2 pr-4">
                          <Badge tone={gradeTone(c.grade)}>
                            {c.grade || "—"}
                          </Badge>
                        </td>
                        <td className="py-2 pr-4">
                          {c.revoked_at ? (
                            <Badge tone="danger">Revoked</Badge>
                          ) : c.expired ? (
                            <Badge tone="danger">Expired</Badge>
                          ) : (
                            <Badge tone="success">Valid</Badge>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
