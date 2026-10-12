import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import {
  Badge,
  Button,
  Dialog,
  Input,
  Panel,
  Select,
  StateMessage,
} from "../components/ops-ui";
import { PageHeader } from "../components/PageHeader";
import { canManageUsers, useAuthz } from "../lib/auth";
import { extractList } from "../lib/models";
import type { UserRecord } from "../lib/models";

const ROLES = [
  "pki-admin",
  "pki-operator",
  "pki-auditor",
  "discovery-operator",
  "notification-operator",
];

export default function Users() {
  const queryClient = useQueryClient();
  const authz = useAuthz();
  const canManage = canManageUsers(authz.data?.role, authz.data?.scopes);

  const [dialog, setDialog] = useState<"invite" | "edit" | null>(null);
  const [activeUser, setActiveUser] = useState<UserRecord | null>(null);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("pki-operator");
  const [editRole, setEditRole] = useState("");
  const [statusMessage, setStatusMessage] = useState<{
    tone: "success" | "error";
    title: string;
    message: string;
  } | null>(null);

  const usersQuery = useQuery({
    queryKey: ["users"],
    queryFn: api.users,
  });

  const users = extractList<UserRecord>(usersQuery.data?.data, ["items"]);

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ["users"] });
  };

  const inviteMutation = useMutation({
    mutationFn: () =>
      api.inviteUser({ email: inviteEmail.trim(), role: inviteRole }),
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "Invitation sent",
        message: `${inviteEmail} was invited as ${inviteRole}.`,
      });
      setDialog(null);
      setInviteEmail("");
      setInviteRole("pki-operator");
      await refresh();
    },
    onError: (e) =>
      setStatusMessage({
        tone: "error",
        title: "Invitation failed",
        message: e instanceof Error ? e.message : "Try again.",
      }),
  });

  const updateMutation = useMutation({
    mutationFn: () => {
      if (!activeUser) throw new Error("No user selected");
      return api.updateUser(activeUser.id, { role: editRole });
    },
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "Role updated",
        message: "The user's role was changed.",
      });
      setDialog(null);
      await refresh();
    },
    onError: (e) =>
      setStatusMessage({
        tone: "error",
        title: "Update failed",
        message: e instanceof Error ? e.message : "Try again.",
      }),
  });

  const deactivateMutation = useMutation({
    mutationFn: (id: string) => api.deactivateUser(id),
    onSuccess: async () => {
      setStatusMessage({
        tone: "success",
        title: "User deactivated",
        message: "The user can no longer log in.",
      });
      await refresh();
    },
    onError: (e) =>
      setStatusMessage({
        tone: "error",
        title: "Deactivation failed",
        message: e instanceof Error ? e.message : "Try again.",
      }),
  });

  const openEdit = (user: UserRecord) => {
    setActiveUser(user);
    setEditRole(user.role);
    setDialog("edit");
    setStatusMessage(null);
  };

  function statusTone(
    status: string,
  ): "success" | "warning" | "danger" | "neutral" {
    if (status === "active") return "success";
    if (status === "invited") return "warning";
    if (status === "deactivated") return "danger";
    return "neutral";
  }

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        eyebrow="Administration"
        title="Users"
        description="Manage who has access to Kryptkeeper and what they can do."
        actions={
          canManage ? (
            <Button
              tone="primary"
              onClick={() => {
                setDialog("invite");
                setStatusMessage(null);
              }}
            >
              Invite user
            </Button>
          ) : undefined
        }
      />

      {statusMessage ? (
        <StateMessage
          tone={statusMessage.tone}
          title={statusMessage.title}
          message={statusMessage.message}
        />
      ) : null}

      <Panel title="Team" subtitle="All users with access to this installation">
        {usersQuery.isLoading ? (
          <StateMessage title="Loading users" message="Fetching team list…" />
        ) : usersQuery.error ? (
          <StateMessage
            tone="error"
            title="Users unavailable"
            message="Try again shortly."
          />
        ) : (
          <div className="overflow-hidden rounded-xl border border-border">
            <table className="min-w-full divide-y divide-border">
              <thead className="bg-background/80">
                <tr>
                  {["Email", "Role", "Status", "Last seen", "Actions"].map(
                    (h) => (
                      <th
                        key={h}
                        scope="col"
                        className="px-4 py-3 text-left text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground"
                      >
                        {h}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody className="divide-y divide-border bg-background/40">
                {users.map((user) => (
                  <tr key={user.id}>
                    <td className="px-4 py-3 text-sm font-medium text-foreground">
                      {user.email}
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">
                      {user.role}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <Badge tone={statusTone(user.status)}>
                        {user.status}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">
                      {user.last_seen_at?.slice(0, 10) || "—"}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {canManage ? (
                        <div className="flex flex-wrap gap-2">
                          <Button onClick={() => openEdit(user)}>
                            Change role
                          </Button>
                          <Button
                            tone="danger"
                            onClick={() =>
                              void deactivateMutation.mutateAsync(user.id)
                            }
                            disabled={
                              user.status === "deactivated" ||
                              deactivateMutation.isPending
                            }
                          >
                            Deactivate
                          </Button>
                        </div>
                      ) : (
                        <span className="text-xs text-muted-foreground">
                          Read only
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
                {users.length === 0 ? (
                  <tr>
                    <td
                      colSpan={5}
                      className="px-4 py-10 text-center text-sm text-muted-foreground"
                    >
                      No users yet. Invite a teammate with the Invite user button above.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Dialog
        open={dialog === "invite"}
        title="Invite user"
        description="Send an invitation to a new team member."
        onClose={() => setDialog(null)}
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void inviteMutation.mutateAsync();
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>Email address</span>
            <Input
              type="email"
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              placeholder="user@example.com"
              required
            />
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>Role</span>
            <Select
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value)}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </Select>
          </label>
          <div className="flex gap-2">
            <Button
              tone="primary"
              type="submit"
              disabled={inviteMutation.isPending}
            >
              {inviteMutation.isPending ? "Sending…" : "Send invitation"}
            </Button>
            <Button onClick={() => setDialog(null)}>Cancel</Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={dialog === "edit"}
        title="Change role"
        description={activeUser?.email ?? undefined}
        onClose={() => setDialog(null)}
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void updateMutation.mutateAsync();
          }}
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>Role</span>
            <Select
              value={editRole}
              onChange={(e) => setEditRole(e.target.value)}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </Select>
          </label>
          <div className="flex gap-2">
            <Button
              tone="primary"
              type="submit"
              disabled={updateMutation.isPending}
            >
              Save
            </Button>
            <Button onClick={() => setDialog(null)}>Cancel</Button>
          </div>
        </form>
      </Dialog>
    </div>
  );
}
