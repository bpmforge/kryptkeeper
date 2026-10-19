// Whose certificate a discovered leaf is. Mirrors the closed vocabulary the
// hub computes (internal/discovery/scanner/chain.go); the order is display order.
export const TRUST_CLASSES = [
  "managed",
  "public",
  "private_other",
  "self_signed",
  "unknown",
] as const;

export type TrustClass = (typeof TRUST_CLASSES)[number];

export type TrustClassCounts = Record<TrustClass, number>;

export const TRUST_CLASS_LABEL: Record<TrustClass, string> = {
  managed: "managed",
  public: "public",
  private_other: "other private CA",
  self_signed: "self-signed",
  unknown: "unknown",
};

export function isTrustClass(value: string | undefined): value is TrustClass {
  return (TRUST_CLASSES as readonly string[]).includes(value ?? "");
}

export function trustClassLabel(value: string | undefined): string {
  return isTrustClass(value) ? TRUST_CLASS_LABEL[value] : "";
}

// Non-colour status cues: every grade / trust class carries a word and an icon
// so state is never conveyed by colour alone (WCAG 1.4.1).
export type StatusCue = { text: string; icon: "check" | "alert" | "x" | "minus" };

export const RISK_GRADES = ["A", "B", "C", "D", "F"] as const;
export type RiskGrade = (typeof RISK_GRADES)[number];

export const GRADE_CUE: Record<RiskGrade, StatusCue> = {
  A: { text: "Strong", icon: "check" },
  B: { text: "Good", icon: "check" },
  C: { text: "Weak", icon: "alert" },
  D: { text: "Poor", icon: "x" },
  F: { text: "Failing", icon: "x" },
};

export function gradeCue(grade: string | undefined): StatusCue {
  const letter = (grade ?? "").trim().charAt(0).toUpperCase();
  return (RISK_GRADES as readonly string[]).includes(letter)
    ? GRADE_CUE[letter as RiskGrade]
    : { text: "Not graded", icon: "minus" };
}

export const TRUST_CLASS_CUE: Record<TrustClass, StatusCue> = {
  managed: { text: "Healthy", icon: "check" },
  public: { text: "Healthy", icon: "check" },
  private_other: { text: "Needs a decision", icon: "alert" },
  self_signed: { text: "Needs a decision", icon: "alert" },
  unknown: { text: "Needs a decision", icon: "alert" },
};

// Word for a 0-100 certificate risk score (thresholds match the colour bands
// used on the Certificates page) so severity is not carried by colour alone.
export function riskLevelText(score: number): "high" | "medium" | "low" {
  return score >= 70 ? "high" : score >= 40 ? "medium" : "low";
}
