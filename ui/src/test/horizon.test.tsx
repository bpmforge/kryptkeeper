import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Horizon } from "../components/Horizon";
import { buildHorizon, certificateState } from "../lib/horizon";
import type { CertificateRecord } from "../lib/models";

const NOW = new Date("2026-08-20T12:00:00Z");

function cert(days: number, renewal_method?: string): CertificateRecord {
  const d = new Date(NOW);
  d.setDate(d.getDate() + days);
  return {
    fingerprint_sha256: `fp-${days}-${renewal_method ?? "none"}-${Math.random()}`,
    common_name: `host-${days}.example.com`,
    valid_until: d.toISOString(),
    renewal_method,
  };
}

describe("horizon state", () => {
  it("treats only genuinely automated methods as handled", () => {
    for (const m of ["acme", "est", "scep", "api"]) {
      expect(certificateState(cert(10, m), NOW)).toBe("auto");
    }
    expect(certificateState(cert(10, "manual"), NOW)).toBe("attn");
  });

  // The one error this view must not make: claiming something is handled
  // when we cannot tell.
  it("does not assume an unknown renewal method is automated", () => {
    expect(certificateState(cert(10, undefined), NOW)).toBe("attn");
    expect(certificateState(cert(10, ""), NOW)).toBe("attn");
    expect(certificateState(cert(10, "something-new"), NOW)).toBe("attn");
  });

  it("counts an expired certificate as overdue work, not history", () => {
    expect(certificateState(cert(-5, "acme"), NOW)).toBe("over");
  });
});

describe("buildHorizon", () => {
  it("folds already-expired certificates into today so they cannot fall off the edge", () => {
    const h = buildHorizon([cert(-30, "acme"), cert(-1, "manual")], NOW);
    expect(h.days[0].total).toBe(2);
    expect(h.totalInWindow).toBe(2);
  });

  it("excludes certificates beyond the window", () => {
    const h = buildHorizon([cert(200, "acme")], NOW, 90);
    expect(h.totalInWindow).toBe(0);
  });

  it("marks a day by its worst state, since that is what must be noticed", () => {
    const h = buildHorizon([cert(10, "acme"), cert(10, "acme"), cert(10, "manual")], NOW);
    expect(h.days[10].state).toBe("attn");
    expect(h.days[10].counts.auto).toBe(2);
  });

  it("finds the cliff by unautomated load, not raw volume", () => {
    // Day 5 is busier, but every one of them renews itself.
    const certs = [
      ...Array.from({ length: 20 }, () => cert(5, "acme")),
      ...Array.from({ length: 3 }, () => cert(40, "manual")),
    ];
    const h = buildHorizon(certs, NOW);
    expect(h.cliff?.offset).toBe(40);
    expect(h.cliff?.needsHuman).toBe(3);
  });

  it("reports no cliff when the whole window is automated", () => {
    const h = buildHorizon([cert(3, "acme"), cert(9, "est")], NOW);
    expect(h.cliff).toBeNull();
    expect(h.needsHuman).toBe(0);
  });
});

describe("Horizon component", () => {
  it("gives assistive tech the same numbers as the chart", () => {
    render(<Horizon certificates={[cert(4, "manual"), cert(4, "acme")]} now={NOW} />);
    const table = screen.getByRole("table", { name: /expiring in the next 90 days/i });
    expect(table).toBeInTheDocument();
    expect(screen.getByText(/2 total/)).toBeInTheDocument();
    expect(screen.getByText(/1 needing a human/)).toBeInTheDocument();
  });

  it("says so plainly when nothing is expiring", () => {
    render(<Horizon certificates={[]} now={NOW} />);
    expect(screen.getByText(/nothing expires in the next 90 days/i)).toBeInTheDocument();
  });

  it("names the cliff only when something will not renew itself", () => {
    render(<Horizon certificates={[cert(12, "manual")]} now={NOW} />);
    expect(screen.getByText(/will not renew themselves/i)).toBeInTheDocument();

    render(<Horizon certificates={[cert(12, "acme")]} now={NOW} />);
    expect(screen.queryAllByText(/will not renew themselves/i)).toHaveLength(1);
  });
});
