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
