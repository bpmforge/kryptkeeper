import type { CertificateRecord } from "./models";

// hostForCert is the host a certificate is served from: the first
// non-wildcard SAN, else the CN, else "".
export function hostForCert(c: CertificateRecord): string {
  const san = (c.subject_alt_names ?? []).find((s) => !s.startsWith("*."));
  return (
    san ??
    (c.common_name && !c.common_name.startsWith("*.") ? c.common_name : "")
  );
}
