import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Dialog } from "./ui";
import { canManageUsers, useAuthz } from "../lib/auth";
import { getDemoStatus, resetDemoData } from "../lib/demoApi";

// Shown across the app while the hub holds `kryptkeeper demo seed` data (W37-07).
export function DemoBanner() {
  const qc = useQueryClient();
  const authz = useAuthz();
  const [confirming, setConfirming] = useState(false);
  const status = useQuery({
    queryKey: ["demo-status"],
    queryFn: getDemoStatus,
    staleTime: 60_000,
    retry: false,
  });
  const reset = useMutation({
    mutationFn: resetDemoData,
    onSuccess: () => {
      setConfirming(false);
      // Everything on screen may have changed, not only the banner.
      void qc.invalidateQueries();
    },
  });

  if (!status.data?.demo) return null;
  const isAdmin = canManageUsers(authz.data?.role, authz.data?.scopes);

  return (
    <div
      role="status"
      data-testid="demo-banner"
      className="flex flex-wrap items-center justify-between gap-2 border-b border-amber-500/40 bg-amber-500/10 px-4 py-2 text-sm text-foreground"
    >
      <span>
        <strong>Demo data.</strong> Everything here is sample data for trying
        Kryptkeeper, labelled demo=true.
      </span>
      {isAdmin ? (
        <Button tone="secondary" onClick={() => setConfirming(true)}>
          Reset demo data
        </Button>
      ) : null}
      <Dialog
        open={confirming}
        onClose={() => !reset.isPending && setConfirming(false)}
        title="Reset demo data"
        description="Revokes every certificate labelled demo=true and removes this banner. Certificates that are not demo data are not touched."
        size="sm"
        footer={
          <div className="flex justify-end gap-2">
            <Button
              tone="secondary"
              onClick={() => setConfirming(false)}
              disabled={reset.isPending}
            >
              Cancel
            </Button>
            <Button
              tone="danger"
              onClick={() => reset.mutate()}
              disabled={reset.isPending}
            >
              {reset.isPending ? "Resetting…" : "Reset"}
            </Button>
          </div>
        }
      >
        {reset.isError ? (
          <p role="alert" className="text-sm text-state-over">
            {(reset.error as Error).message}
          </p>
        ) : (
          <p className="text-sm text-muted-foreground">
            The demo CAs stay in place; run <code>kryptkeeper demo seed</code>{" "}
            again to refill them.
          </p>
        )}
      </Dialog>
    </div>
  );
}
