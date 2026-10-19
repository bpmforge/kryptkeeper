import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AgentHostReportView } from "./Agents";

describe("AgentHostReportView (W34-09)", () => {
  it("says an agent that predates reporting has unknown posture", () => {
    render(<AgentHostReportView report={{ received_at: "", posture_known: false, unreadable_count: 0, listener_count: 0, listeners_hidden: 0 }} />);
    expect(screen.getByTestId("agent-host-report")).toHaveTextContent("Install posture unknown");
    expect(screen.queryByText("Every path readable")).toBeNull();
  });

  it("shows insufficient privilege with the count, paths and the fix", () => {
    render(
      <AgentHostReportView
        report={{
          received_at: "",
          posture_known: true,
          privilege_mode: "none",
          unreadable_count: 2,
          unreadable_paths: [{ path: "/opt/tomcat/conf/keystore.jks", error: "permission denied" }],
          findings: ["INSUFFICIENT_PRIVILEGE: uid=1; user=a; mode=none; unreadable=2; paths=/x; fix=Install the helper."],
          posture_counts: { privileged: 1, standard: 3 },
          listener_count: 4,
          listeners_hidden: 1,
        }}
      />,
    );
    const view = screen.getByTestId("agent-host-report");
    expect(view).toHaveTextContent("Insufficient privilege: 2 paths unreadable");
    expect(view).toHaveTextContent("Unprivileged");
    expect(view).toHaveTextContent("1 file need root");
    expect(view).toHaveTextContent("4 listeners (1 hidden)");
    expect(view).toHaveTextContent("/opt/tomcat/conf/keystore.jks");
    expect(view).toHaveTextContent("Install the helper.");
  });

  it("shows every path readable after the helper rule is added", () => {
    render(<AgentHostReportView report={{ received_at: "", posture_known: true, privilege_mode: "helper", unreadable_count: 0, listener_count: 1, listeners_hidden: 0 }} />);
    expect(screen.getByText("Every path readable")).toBeInTheDocument();
    expect(screen.getByText("Privilege: helper")).toBeInTheDocument();
  });
});
