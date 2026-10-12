import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Wand2 } from "lucide-react";
import { api } from "../lib/api";
import { extractList } from "../lib/models";
import type {
  CertificateRecord,
  SpiffeStatus,
  SpiffeSVIDResult,
} from "../lib/models";
import {
  Badge,
  Button,
  Input,
  MetricCard,
  Panel,
  StateMessage,
} from "../components/ui";
import { PageHeader } from "../components/PageHeader";

function StatusPanel({ status }: { status?: SpiffeStatus }) {
  return (
    <Panel
      title="Trust domain"
      subtitle="SPIFFE workload identity (SVID mint + trust bundle)"
    >
      {!status ? (
        <StateMessage title="Loading" message="Fetching SPIFFE status…" />
      ) : !status.enabled ? (
        <StateMessage
          tone="neutral"
          title="SPIFFE not configured"
          message="Set SPIFFE_TRUST_DOMAIN and SPIFFE_SIGNING_CA_ID (with the CA engine) to enable SVID issuance."
        />
      ) : (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
          <MetricCard label="Trust domain" value={status.trust_domain} />
          <MetricCard
            label="SVID TTL"
            value={`${Math.round(status.svid_ttl_seconds / 60)}m`}
          />
          <MetricCard
            label="Signing CA"
            value={status.signing_ca_id.slice(0, 12) || "—"}
          />
        </div>
      )}
    </Panel>
  );
}

function MintPanel({ trustDomain }: { trustDomain: string }) {
  const [path, setPath] = useState("ns/default/sa/example");
  const mutation = useMutation({
    mutationFn: (id: string) => api.mintSVID(id),
  });
  const result: SpiffeSVIDResult | undefined = mutation.data?.data;
  const fullID = `spiffe://${trustDomain}/${path.replace(/^\//, "")}`;

  return (
    <Panel title="Mint SVID" subtitle="Issue a short-lived SVID for testing">
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          mutation.mutate(fullID);
        }}
      >
        <div className="grow">
          <label className="text-xs text-muted-foreground">
            SPIFFE ID — spiffe://{trustDomain}/
          </label>
          <Input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="ns/prod/sa/checkout"
          />
        </div>
        <Button type="submit" tone="primary" disabled={mutation.isPending}>
          <Wand2 size={13} aria-hidden="true" />
          Mint SVID
        </Button>
      </form>

      {mutation.isError ? (
        <p className="mt-2 text-sm text-state-over">
          {mutation.error instanceof Error
            ? mutation.error.message
            : "Mint failed."}
        </p>
      ) : null}

      {result ? (
        <div className="mt-3 space-y-2">
          <p className="text-sm text-state-auto">
            Issued {result.spiffe_id} (expires{" "}
            {new Date(result.expires_at).toLocaleString()})
          </p>
          <p className="text-xs text-state-attn">
            The private key is shown once — copy it now.
          </p>
          <details>
            <summary className="cursor-pointer text-xs text-muted-foreground">
              SVID certificate (PEM)
            </summary>
            <pre className="mt-1 overflow-x-auto rounded-lg bg-background/60 p-2 text-[10px] text-foreground">
              {result.svid_pem}
            </pre>
          </details>
          <details>
            <summary className="cursor-pointer text-xs text-muted-foreground">
              Private key (PEM)
            </summary>
            <pre className="mt-1 overflow-x-auto rounded-lg bg-background/60 p-2 text-[10px] text-foreground">
              {result.key_pem}
            </pre>
          </details>
        </div>
      ) : null}
    </Panel>
  );
}

export default function Spiffe() {
  const statusQ = useQuery({
    queryKey: ["spiffe-status"],
    queryFn: api.spiffeStatus,
    staleTime: 60_000,
  });
  const status = statusQ.data?.data;

  const certsQ = useQuery({
    queryKey: ["spiffe-svids"],
    queryFn: () => api.certificates({ limit: 200 }),
    staleTime: 30_000,
  });
  const svids = extractList<CertificateRecord>(certsQ.data?.data).filter((c) =>
    (c.uri_sans ?? []).some((u) => u.startsWith("spiffe://")),
  );

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Identity"
        title="SPIFFE"
        description="Workload identity — SVIDs and the trust bundle."
      />

      <StatusPanel status={status} />

      {status?.enabled ? <MintPanel trustDomain={status.trust_domain} /> : null}

      <Panel
        title="Issued SVIDs"
        subtitle={`${svids.length} certificate(s) with a spiffe:// identity`}
      >
        {svids.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No SVIDs yet. Mint one above (or via POST /api/v1/spiffe/svid).
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                <th className="py-2 pr-4">SPIFFE ID</th>
                <th className="py-2 pr-4">Expires</th>
                <th className="py-2 pr-4">Status</th>
              </tr>
            </thead>
            <tbody>
              {svids.map((c) => (
                <tr
                  key={c.fingerprint_sha256}
                  className="border-b border-border"
                >
                  <td className="py-2 pr-4 font-mono text-xs text-primary">
                    {(c.uri_sans ?? []).find((u) => u.startsWith("spiffe://"))}
                  </td>
                  <td className="py-2 pr-4 text-muted-foreground">
                    {c.valid_until
                      ? new Date(c.valid_until).toLocaleString()
                      : "—"}
                  </td>
                  <td className="py-2 pr-4">
                    <Badge tone={c.revoked_at ? "danger" : "success"}>
                      {c.revoked_at ? "revoked" : "active"}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
