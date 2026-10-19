import { describe, expect, it } from "vitest";
import {
  GRADE_CUE,
  RISK_GRADES,
  TRUST_CLASSES,
  TRUST_CLASS_CUE,
  gradeCue,
} from "./trustClass";

describe("status cues (W33-14)", () => {
  it("gradeCue covers every grade", () => {
    const icons = new Set<string>();
    for (const g of RISK_GRADES) {
      const cue = gradeCue(g);
      expect(cue.text.length).toBeGreaterThan(0);
      expect(cue).toBe(GRADE_CUE[g]);
      icons.add(`${g}:${cue.icon}`);
    }
    // Tone groups match GRADE_TONE: A/B success, C warning, D/F danger.
    expect(gradeCue("A").icon).toBe(gradeCue("B").icon);
    expect(gradeCue("C").icon).not.toBe(gradeCue("A").icon);
    expect(gradeCue("C").icon).not.toBe(gradeCue("D").icon);
    expect(gradeCue("D").icon).toBe(gradeCue("F").icon);
    expect(new Set(RISK_GRADES.map((g) => gradeCue(g).text)).size).toBe(RISK_GRADES.length);
  });

  it("gradeCue normalises case and suffixes", () => {
    expect(gradeCue("A+")).toBe(GRADE_CUE.A);
    expect(gradeCue("b")).toBe(GRADE_CUE.B);
  });

  it("gradeCue unknown", () => {
    for (const v of [undefined, "", "Z", "?"]) {
      expect(gradeCue(v)).toEqual({ text: "Not graded", icon: "minus" });
    }
  });

  it("TRUST_CLASS_CUE has an entry for every TRUST_CLASSES member", () => {
    for (const c of TRUST_CLASSES) {
      expect(TRUST_CLASS_CUE[c].text.length).toBeGreaterThan(0);
    }
    expect(TRUST_CLASS_CUE.managed.text).toBe("Healthy");
    expect(TRUST_CLASS_CUE.self_signed.text).toBe("Needs a decision");
  });
});
