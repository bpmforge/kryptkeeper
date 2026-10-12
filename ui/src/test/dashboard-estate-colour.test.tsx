import { describe, expect, it } from "vitest";

// Found in end-user review: "0 unmanaged" rendered in the attention
// colour, so a perfectly-managed estate looked like it had a problem.
// Colour carries state in this design, and zero unmanaged is the best
// reading of that number, not a warning.
function unmanagedClass(count: number) {
  return (count > 0 ? "text-state-attn" : "text-muted-foreground") + " hover:underline";
}

describe("estate summary colour", () => {
  it("does not flag zero unmanaged certificates as needing attention", () => {
    expect(unmanagedClass(0)).not.toContain("text-state-attn");
  });
  it("does flag unmanaged certificates when there are some", () => {
    expect(unmanagedClass(3)).toContain("text-state-attn");
  });
});
