import { describe, expect, it } from "vitest";
import { expiryBucketClass, ruleChips, sortRoles } from "../lib/pageHelpers";

describe("sortRoles", () => {
  it("puts built-in roles first, then custom, each alphabetical", () => {
    const out = sortRoles([
      { name: "zeta", builtin: false },
      { name: "viewer", builtin: true },
      { name: "alpha", builtin: false },
      { name: "admin", builtin: true },
    ]);
    expect(out.map((r) => r.name)).toEqual(["admin", "viewer", "alpha", "zeta"]);
  });
});

describe("ruleChips", () => {
  it("splits rules into one chip each", () => {
    expect(
      ruleChips({
        allowed_algorithms: ["ECDSA-P256", "RSA-3072"],
        min_rsa_bits: 3072,
        max_validity_days: 398,
      }),
    ).toEqual(["ECDSA-P256", "RSA-3072", "RSA ≥ 3072", "Validity ≤ 398d"]);
    expect(ruleChips({})).toEqual([]);
  });
});

describe("expiryBucketClass", () => {
  it("colours by state", () => {
    expect(expiryBucketClass("Expired")).toBe("bg-state-over");
    expect(expiryBucketClass("0-7 days")).toBe("bg-state-attn");
    expect(expiryBucketClass("91-365 days")).toBe("bg-state-auto");
  });
});
