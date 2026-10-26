import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api } from "../lib/api";
import { Badge, Button, Input, Panel, Select, StateMessage } from "./ops-ui";
import { formatDateTime } from "./ui";
import { extractList } from "../lib/models";
import type {
  NotificationTeamRoute,
  OwnerlessCertificate,
} from "../lib/models";

// owner_team values with a meaning of their own (docs/openapi.yaml,
// /notifications/team-routes): "*" is the global inbox, "!ownerless" the queue
// for certificates that have no owner team.
const GLOBAL_INBOX = "*";
const OWNERLESS_QUEUE = "!ownerless";

type Scope = "team" | typeof OWNERLESS_QUEUE | typeof GLOBAL_INBOX;

function teamLabel(team: string): string {
  if (team === OWNERLESS_QUEUE) return "Ownerless queue";
  if (team === GLOBAL_INBOX) return "Global inbox";
  return team;
}

// Owner-team routing for rules whose target is "Owner team routing", the
// ownerless queue, and the expiring certificates nobody owns (W32-30).
export default function OwnerRouting({ canManage }: { canManage: boolean }) {
  const queryClient = useQueryClient();
  const [scope, setScope] = useState<Scope>("team");
  const [team, setTeam] = useState("");
  const [channel, setChannel] = useState("slack");
  const [target, setTarget] = useState("");

  const routesQuery = useQuery({
    queryKey: ["notification-team-routes"],
    queryFn: api.notificationTeamRoutes,
  });
  const ownerlessQuery = useQuery({
    queryKey: ["notification-ownerless"],
    queryFn: () => api.ownerlessCertificates(30),
  });
  const routes = extractList<NotificationTeamRoute>(routesQuery.data?.data, [
    "items",
  ]);
  const ownerless = extractList<OwnerlessCertificate>(
    ownerlessQuery.data?.data,
    ["items"],
  );
  const ownerlessTotal =
    (ownerlessQuery.data?.meta as { total?: number } | undefined)?.total ??
    ownerless.length;
  const queueRoutes = routes.filter((r) => r.owner_team === OWNERLESS_QUEUE);

  const createMutation = useMutation({
    mutationFn: () =>
      api.createNotificationTeamRoute({
        owner_team: scope === "team" ? team.trim() : scope,
        channel,
        target: target.trim(),
      }),
    onSuccess: async () => {
      setTarget("");
      setTeam("");
      await queryClient.invalidateQueries({
        queryKey: ["notification-team-routes"],
      });
    },
    onError: (err: Error) => toast.error(err.message),
  });
  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteNotificationTeamRoute(id),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ["notification-team-routes"],
      });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const canSubmit =
    target.trim() !== "" && (scope !== "team" || team.trim() !== "");

  return (
    <div className="grid gap-6 xl:grid-cols-2">
      <Panel
        title="Owner-team routing"
        subtitle="Where a rule set to “Owner team routing” sends each certificate's alert"
      >
        {routesQuery.isLoading ? (
          <StateMessage title="Loading routes" message="Fetching routes…" />
        ) : routesQuery.error ? (
          <StateMessage
            tone="error"
            title="Routes unavailable"
            message="Try again shortly."
          />
        ) : (
          <div className="space-y-4">
            <ul className="divide-y divide-border rounded-xl border border-border">
              {routes.map((r) => (
                <li
                  key={r.id}
                  className="flex items-center justify-between gap-3 px-4 py-3 text-sm"
                >
                  <span>
                    <span className="font-medium text-foreground">
                      {teamLabel(r.owner_team)}
                    </span>{" "}
                    <span className="text-muted-foreground">
                      {r.channel} · {r.target}
                    </span>
                  </span>
                  {canManage ? (
                    <Button
                      tone="danger"
                      aria-label={`Delete route ${teamLabel(r.owner_team)} ${r.channel}`}
                      disabled={deleteMutation.isPending}
                      onClick={() =>
                        void deleteMutation.mutateAsync(r.id).catch(() => {})
                      }
                    >
                      Delete
                    </Button>
                  ) : null}
                </li>
              ))}
              {routes.length === 0 ? (
                <li className="px-4 py-6 text-center text-sm text-muted-foreground">
                  No routes yet. Without one, owner-routed alerts wait in the
                  delivery queue and nothing is sent.
                </li>
              ) : null}
            </ul>
            {queueRoutes.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                No ownerless queue is configured: alerts for certificates with
                no owner team go to the global inbox, or wait in the delivery
                queue if there is none.
              </p>
            ) : null}
            {canManage ? (
              <form
                className="grid gap-3 sm:grid-cols-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (canSubmit)
                    void createMutation.mutateAsync().catch(() => {});
                }}
              >
                <Select
                  aria-label="Route applies to"
                  value={scope}
                  onChange={(e) => setScope(e.target.value as Scope)}
                >
                  <option value="team">A team</option>
                  <option value={OWNERLESS_QUEUE}>Ownerless queue</option>
                  <option value={GLOBAL_INBOX}>Global inbox</option>
                </Select>
                <Input
                  aria-label="Owner team"
                  value={scope === "team" ? team : ""}
                  disabled={scope !== "team"}
                  onChange={(e) => setTeam(e.target.value)}
                  placeholder="platform-eng"
                />
                <Select
                  aria-label="Route channel"
                  value={channel}
                  onChange={(e) => setChannel(e.target.value)}
                >
                  <option value="slack">Slack</option>
                  <option value="email">Email</option>
                  <option value="pagerduty">PagerDuty</option>
                  <option value="webhook">Webhook</option>
                </Select>
                <Input
                  aria-label="Route target"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="#platform-alerts"
                />
                <div className="sm:col-span-2">
                  <Button
                    tone="primary"
                    type="submit"
                    disabled={!canSubmit || createMutation.isPending}
                  >
                    Add route
                  </Button>
                </div>
              </form>
            ) : null}
          </div>
        )}
      </Panel>

      <Panel
        title="Ownerless expiring certificates"
        subtitle="Expiring within 30 days with no owner team"
      >
        {ownerlessQuery.isLoading ? (
          <StateMessage title="Loading" message="Fetching certificates…" />
        ) : ownerlessQuery.error ? (
          <StateMessage
            tone="error"
            title="Listing unavailable"
            message="Try again shortly."
          />
        ) : ownerless.length === 0 ? (
          <StateMessage
            title="Nothing ownerless is expiring"
            message="Every certificate expiring in the next 30 days has an owner team."
          />
        ) : (
          <div className="space-y-2">
            <div className="text-sm text-muted-foreground">
              {ownerlessTotal} certificate{ownerlessTotal === 1 ? "" : "s"}
              {ownerlessTotal > ownerless.length
                ? `, showing the first ${ownerless.length}`
                : ""}
            </div>
            <ul className="divide-y divide-border rounded-xl border border-border">
              {ownerless.map((c) => (
                <li
                  key={c.fingerprint_sha256}
                  className="flex items-center justify-between gap-3 px-4 py-3 text-sm"
                >
                  <span>
                    <a
                      className="font-medium text-foreground underline"
                      href={`/certificates/${c.fingerprint_sha256}`}
                    >
                      {c.common_name}
                    </a>
                    <span className="block text-xs text-muted-foreground">
                      Expires {formatDateTime(c.valid_until)}
                    </span>
                  </span>
                  <Badge
                    tone={
                      c.days_left < 0
                        ? "danger"
                        : c.days_left <= 7
                          ? "warning"
                          : "info"
                    }
                  >
                    {c.days_left < 0 ? "expired" : `${c.days_left}d left`}
                  </Badge>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Panel>
    </div>
  );
}
