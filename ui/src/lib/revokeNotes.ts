// Imported, discovered and synced certificates have no issuing CA in this hub, so there is no
// CRL or OCSP responder to publish to: the revocation is an inventory record only.
export const EXTERNAL_REVOKE_NOTE =
  "Marked revoked in inventory — revoke at the issuing CA. This hub is not the issuer.";

export const UPSTREAM_REVOKE_NOTE =
  "This revokes the certificate at the issuing CA first. If the CA refuses, nothing changes here.";

export function revokeScopeNote(
  scope: string | undefined,
  connectorName?: string,
): string {
  if (scope === "upstream") {
    return connectorName
      ? `Revoked at the issuing CA through ${connectorName}.`
      : "Revoked at the issuing CA.";
  }
  if (scope === "inventory_only") return EXTERNAL_REVOKE_NOTE;
  return "";
}
