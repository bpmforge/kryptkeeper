import { describe, expect, it } from "vitest";
import {
  observedProtocol,
  primaryTrustClass,
  topFindingChips,
} from "./discoveryDisplay";

describe("observedProtocol", () => {
  it("shows what was observed, not the intended protocol", () => {
    expect(
      observedProtocol({ protocol: "tls", issues: ["NOT_TLS: plain http"] }),
    ).toBe("not TLS");
    expect(
      observedProtocol({
        protocol: "starttls-postgres",
        issues: ["POSTGRES_TLS_DISABLED: declined"],
      }),
    ).toBe("postgres (TLS off)");
    expect(
      observedProtocol({
        protocol: "https",
        issues: ["TLS_HANDSHAKE_FAILED: EOF"],
      }),
    ).toBe("https (handshake failed)");
    expect(observedProtocol({ protocol: "https" })).toBe("https");
  });
});

describe("topFindingChips", () => {
  it("puts high-severity first, hides informational, caps at two + count", () => {
    const chips = topFindingChips({
      protocol: "https",
      issues: [],
      mapped_certs: [
        {
          fingerprint: "a",
          risk_score: 50,
          risk_flags: [
            "PQC_VULNERABLE",
            "INCOMPLETE_CHAIN",
            "EXPIRED",
            "SELF_SIGNED",
          ],
        },
      ],
    });
    expect(chips.shown.map((c) => c.code)).toEqual(["EXPIRED", "SELF_SIGNED"]);
    expect(chips.more).toBe(1);
    expect(chips.shown[0].label).toBe("expired");
  });

  it("leads with the endpoint's own finding and ignores served CA certs", () => {
    const chips = topFindingChips({
      protocol: "tls",
      issues: ["NOT_TLS: x"],
      mapped_certs: [
        {
          fingerprint: "ca",
          risk_score: 0,
          chain_ca: true,
          risk_flags: ["SELF_SIGNED"],
        },
      ],
    });
    expect(chips.shown.map((c) => c.code)).toEqual(["NOT_TLS"]);
    expect(chips.more).toBe(0);
  });
});

describe("primaryTrustClass", () => {
  it("is the leaf's class, not a served intermediate's", () => {
    expect(
      primaryTrustClass({
        protocol: "https",
        mapped_certs: [
          {
            fingerprint: "i",
            risk_score: 0,
            chain_ca: true,
            trust_class: "public",
          },
          { fingerprint: "l", risk_score: 0, trust_class: "managed" },
        ],
      }),
    ).toBe("managed");
  });
});
