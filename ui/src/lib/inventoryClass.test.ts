import { describe, expect, it } from "vitest";
import {
  applyAuthorizedIssuer,
  normalizeDN,
  INVENTORY_CLASSES,
  inventoryClassLabel,
  isInventoryClass,
  worstInventoryClass,
} from "./inventoryClass";

describe("inventory class", () => {
  it("knows its closed vocabulary", () => {
    expect(INVENTORY_CLASSES).toHaveLength(5);
    expect(isInventoryClass("unknown_issuer")).toBe(true);
    expect(isInventoryClass("public")).toBe(false);
    expect(isInventoryClass(undefined)).toBe(false);
  });

  it("labels classes and ignores unknown values", () => {
    expect(inventoryClassLabel("authorized_external")).toBe(
      "Authorized external CA",
    );
    expect(inventoryClassLabel("bogus")).toBe("");
  });

  it("summarises several leaves as the least trusted", () => {
    expect(
      worstInventoryClass(["managed", "unknown_issuer", "authorized_external"]),
    ).toBe("unknown_issuer");
    expect(worstInventoryClass(["managed", "ours_unmanaged"])).toBe(
      "ours_unmanaged",
    );
    expect(worstInventoryClass([undefined, "bogus"])).toBeUndefined();
  });
});

describe("applyAuthorizedIssuer", () => {
  const leaf = (dn: string, cls = "unknown_issuer") => ({
    issuer_dn: dn,
    inventory_class: cls,
  });

  it("matches issuer DNs ignoring case and spacing", () => {
    expect(normalizeDN("CN=Corp CA, O=Corp")).toBe(normalizeDN("cn=corp ca,o=corp"));
  });

  it("re-classifies the matching unknown-issuer leaves and the endpoint headline", () => {
    const eps = [
      { id: "a", inventory_class: "unknown_issuer", mapped_certs: [leaf("CN=Corp CA, O=Corp"), leaf("CN=Other", "managed")] },
      { id: "b", inventory_class: "unknown_issuer", mapped_certs: [leaf("CN=Stranger")] },
      { id: "c", inventory_class: "self_signed", mapped_certs: [leaf("CN=Corp CA,O=Corp", "self_signed")] },
    ];
    const out = applyAuthorizedIssuer(eps, "cn=corp ca,o=corp");
    expect(out[0].mapped_certs?.[0].inventory_class).toBe("authorized_external");
    expect(out[0].mapped_certs?.[0]).toMatchObject({ issuer_class: "authorized" });
    expect(out[0].inventory_class).toBe("authorized_external");
    expect(out[1]).toBe(eps[1]);
    expect(out[2]).toBe(eps[2]);
  });

  it("never touches chain CAs", () => {
    const eps = [
      { inventory_class: "unknown_issuer", mapped_certs: [{ ...leaf("CN=Corp CA"), chain_ca: true }] },
    ];
    expect(applyAuthorizedIssuer(eps, "CN=Corp CA")[0]).toBe(eps[0]);
  });
});
