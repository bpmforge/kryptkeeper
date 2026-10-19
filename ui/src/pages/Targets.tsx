import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type ManagedTarget } from "../lib/api";
import { Badge, Button, Panel, StateMessage } from "../components/ui";
import { PageHeader } from "../components/PageHeader";

// W34-10: managed targets with what the latest scan could do on each, and the
// Blocked state with the recipe that clears it.

function privilegeLabel(mode: string | undefined): string {
  switch (mode) {
    case "helper":
      return "helper";
    case "nopasswd":
      return "sudo (no password)";
    case "password":
      return "sudo (password)";
    case "none":
      return "unprivileged";
    default:
      return "not scanned";
  }
}

export function TargetCoverage({ target }: { target: ManagedTarget }) {
  if (!target.last_scanned_at) {
    return <span className="text-xs text-muted-foreground">Not scanned yet</span>;
  }
  const n = target.unreadable_count ?? 0;
  const unprivileged = target.last_privilege_mode === "none" || !target.last_privilege_mode;
  return (
    <span className="text-xs text-muted-foreground">
      Scan ran {unprivileged ? "unprivileged" : `with ${privilegeLabel(target.last_privilege_mode)}`};{" "}
      {n === 0 ? "every path readable" : `${n} path${n === 1 ? "" : "s"} unreadable`}
    </span>
  );
}

function TargetRow({ target }: { target: ManagedTarget }) {
  const queryClient = useQueryClient();
  const unblock = useMutation({
    mutationFn: () => api.unblockTarget(target.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["targets"] }),
  });
  const blocked = target.blocked;
  return (
    <li className="space-y-1 rounded border border-border/50 p-3" data-testid={`target-${target.id}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{target.name}</span>
        <span className="text-sm text-muted-foreground">{target.host}</span>
        <Badge>{target.install_mode}</Badge>
        {target.credential_privileged ? <Badge tone="warning">Privileged credential</Badge> : null}
        {blocked ? <Badge tone="danger">Blocked</Badge> : null}
      </div>
      <div>
        <TargetCoverage target={target} />
      </div>
      {blocked ? (
        <div className="text-sm">
          <p>
            <strong>Blocked:</strong> {blocked.reason}
            {blocked.kind === "privilege"
              ? "; add a privileged credential or fix ownership"
              : ""}
            .
          </p>
          <p className="text-muted-foreground">{blocked.fix}</p>
          {blocked.kind === "rollback" ? (
            <Button disabled={unblock.isPending} onClick={() => unblock.mutate()}>
              Unblock
            </Button>
          ) : (
            <Link to="/targets/setup" className="underline">
              Open Target Setup
            </Link>
          )}
        </div>
      ) : null}
    </li>
  );
}

export default function Targets() {
  const targets = useQuery({ queryKey: ["targets"], queryFn: api.targets });
  const items = targets.data?.data ?? [];
  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Automation"
        title="Targets"
        description="Managed targets, what their latest scan could read, and whether renewal is blocked."
      />
      <Panel title="Managed targets">
        {targets.isLoading ? (
          <StateMessage title="Loading" message="Fetching targets…" />
        ) : targets.error ? (
          <StateMessage tone="error" title="Unavailable" message="Could not load targets." />
        ) : items.length === 0 ? (
          <StateMessage title="No targets" message="Create one from Target Setup." />
        ) : (
          <ul className="space-y-3">
            {items.map((t) => (
              <TargetRow key={t.id} target={t} />
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
