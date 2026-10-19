import { describe, expect, it } from "vitest";
import { summarizeChange } from "./changeSummary";

describe("summarizeChange", () => {
  it("renders known keys", () => {
    const names = new Map([["tpl-1", "Web server"]]);
    expect(summarizeChange('{"cn":"edge-lb.acme.test","template":"tpl-1"}', names)).toBe(
      "edge-lb.acme.test · template Web server",
    );
  });
  it("falls back to key value pairs, never raw JSON", () => {
    expect(summarizeChange('{"approval_id":"apr-1","reason":"expired"}')).toBe(
      "reason: expired · approval id apr-1",
    );
  });
  it("handles truncated JSON and plain text", () => {
    expect(summarizeChange('{"approval_id":"apr-1","rea')).toBe("approval id apr-1");
    expect(summarizeChange("renewed by policy")).toBe("renewed by policy");
    expect(summarizeChange(undefined)).toBe("");
  });
});
