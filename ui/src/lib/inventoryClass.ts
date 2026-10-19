// The headline class of a discovered certificate (W34-06). Mirrors the closed
// vocabulary the hub derives (internal/bootstrap/discovery_trust.go); the order
// is least trusted first, which is also how an endpoint with several leaves is
// summarised.
export const INVENTORY_CLASSES = [
  "unknown_issuer",
  "self_signed",
  "ours_unmanaged",
  "authorized_external",
  "managed",
] as const;

export type InventoryClass = (typeof INVENTORY_CLASSES)[number];

export type InventoryClassCounts = Record<InventoryClass, number>;

export const INVENTORY_CLASS_LABEL: Record<InventoryClass, string> = {
  unknown_issuer: "Unknown issuer",
  self_signed: "Self-signed",
  ours_unmanaged: "Ours, not managed",
  authorized_external: "Authorized external CA",
  managed: "Managed",
};

export function isInventoryClass(
  value: string | undefined,
): value is InventoryClass {
  return (INVENTORY_CLASSES as readonly string[]).includes(value ?? "");
}

export function inventoryClassLabel(value: string | undefined): string {
  return isInventoryClass(value) ? INVENTORY_CLASS_LABEL[value] : "";
}

// Worst (least trusted) class among an endpoint's leaf certificates.
export function worstInventoryClass(
  classes: Array<string | undefined>,
): InventoryClass | undefined {
  const ranks = classes
    .filter(isInventoryClass)
    .map((c) => INVENTORY_CLASSES.indexOf(c));
  return ranks.length ? INVENTORY_CLASSES[Math.min(...ranks)] : undefined;
}

type MappedCert = {
  chain_ca?: boolean;
  issuer_dn?: string;
  issuer_class?: string;
  inventory_class?: string;
};
type EndpointLike = { inventory_class?: string; mapped_certs?: MappedCert[] };

// Same canonical form the hub compares issuer DNs in (case-folded, no space
// after separators).
export function normalizeDN(dn: string): string {
  return dn
    .split(",")
    .map((p) => p.trim())
    .join(",")
    .toLowerCase();
}

// Re-classifies a cached endpoint list after an issuer was authorized: every
// unknown-issuer leaf the issuer signed becomes authorized-external, and each
// endpoint's headline is recomputed. The hub does the same for stored rows, so
// this only makes the page agree before the refetch lands.
export function applyAuthorizedIssuer<T extends EndpointLike>(
  endpoints: T[],
  issuerDN: string,
): T[] {
  const wanted = normalizeDN(issuerDN);
  return endpoints.map((ep) => {
    let changed = false;
    const mapped = (ep.mapped_certs ?? []).map((mc) => {
      if (
        mc.chain_ca ||
        mc.inventory_class !== "unknown_issuer" ||
        !mc.issuer_dn ||
        normalizeDN(mc.issuer_dn) !== wanted
      ) {
        return mc;
      }
      changed = true;
      return {
        ...mc,
        issuer_class: "authorized",
        inventory_class: "authorized_external",
      };
    });
    if (!changed) return ep;
    return {
      ...ep,
      mapped_certs: mapped,
      inventory_class: worstInventoryClass(
        mapped.filter((m) => !m.chain_ca).map((m) => m.inventory_class),
      ),
    };
  });
}
