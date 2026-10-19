import { describe, expect, it } from "vitest";
import { humanizeEnum } from "../lib/utils";

describe("humanizeEnum", () => {
  it.each([
    ["pending_ceremony", "Pending ceremony"],
    ["WEAK_KEY", "Weak key"],
    ["adcs_export", "AD CS export"],
    ["codesign.oidc_trust_rule", "Codesign OIDC trust rule"],
    ["pending_approval", "Pending approval"],
    ["active", "Active"],
    ["", ""],
  ])("%s -> %s", (input, want) => {
    expect(humanizeEnum(input)).toBe(want);
  });
  it("tolerates null", () => expect(humanizeEnum(null)).toBe(""));
});
