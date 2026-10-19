import { describe, expect, it } from "vitest";
import { formatAge, humanizeInboxSummary } from "./inboxFormat";

describe("formatAge", () => {
  it("uses relative wording", () => {
    expect(formatAge(10)).toBe("just now");
    expect(formatAge(12 * 60)).toBe("12 min ago");
    expect(formatAge(3 * 3600 + 5)).toBe("3 h ago");
    expect(formatAge(50 * 3600)).toBe("2 d ago");
  });
});

describe("humanizeInboxSummary", () => {
  const cas = new Map([["53ae75df", "Issuing CA"]]);
  const tpls = new Map([["tpl-1", "Code signing"]]);
  it("resolves template and CA names", () => {
    expect(humanizeInboxSummary("issue from template tpl-1 on CA 53ae75df", cas, tpls)).toBe(
      "issue from template Code signing on CA Issuing CA",
    );
  });
  it("keeps unknown ids and humanizes the action kind", () => {
    expect(humanizeInboxSummary("issue from template x on CA y", cas, tpls)).toBe(
      "issue from template x on CA y",
    );
    expect(humanizeInboxSummary("codesign.oidc_trust_rule release signing", cas, tpls)).toBe(
      "Codesign OIDC trust rule release signing",
    );
    expect(humanizeInboxSummary("exception_create foo", cas, tpls)).toBe("Exception create foo");
  });
});
