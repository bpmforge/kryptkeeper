import type { DiscoveryEndpointRecord } from "./models";
import { humanizeEnum } from "./utils";

type Endpoint = Pick<
  DiscoveryEndpointRecord,
  "protocol" | "issues" | "mapped_certs"
>;

// Mirrors scanner.HighSeverity* in internal/discovery/scanner/legacy.go: shown
// first so the two chips an endpoint gets are the ones that matter.
const HIGH_SEVERITY = new Set([
  "NOT_TLS",
  "POSTGRES_TLS_DISABLED",
  "MSSQL_TLS_DISABLED",
  "MYSQL_TLS_DISABLED",
  "TLS_HANDSHAKE_FAILED",
  "DEPRECATED_TLS_VERSION",
  "EXPIRED",
  "SELF_SIGNED",
  "WEAK_KEY",
  "WEAK_SIGNATURE",
  "HOSTNAME_MISMATCH",
  "UNTRUSTED_ROOT",
]);

// Informational on every RSA/ECDSA certificate; a chip for it is noise.
const INFORMATIONAL = new Set(["PQC_VULNERABLE"]);

const CODE = /^[A-Z][A-Z0-9_]+$/;

// "NOT_TLS: first record ..." -> "NOT_TLS"; cipheraudit prose is kept whole.
function findingCode(issue: string): string {
  const head = issue.split(":", 1)[0].trim();
  return CODE.test(head) ? head : issue.trim();
}

// Raw Go dial/handshake errors ("connection failed: tls: first record ...")
// leak through as finding text when the scanner has no code for them.
const GO_NET_ERROR = /^(connection failed|dial |tls:|x509:|read tcp|i\/o timeout)|handshake failure|connection refused|connection reset/i;

function chipLabel(code: string): string {
  if (CODE.test(code)) return humanizeEnum(code);
  if (GO_NET_ERROR.test(code)) return "TLS handshake failed";
  return code.length > 28 ? `${code.slice(0, 27)}…` : code;
}

// Full-text variant for detail views: "WEAK_KEY: rsa 1024" -> "Weak key: rsa 1024".
export function findingLabel(issue: string): string {
  const [head, ...rest] = issue.split(":");
  if (head.trim() === "INSUFFICIENT_PRIVILEGE") {
    // W34-10: "uid=…; user=…; mode=none; unreadable=3; paths=…; fix=…".
    const mode = /mode=(\w+)/.exec(issue)?.[1];
    const n = Number(/unreadable=(\d+)/.exec(issue)?.[1] ?? "0");
    const how = !mode || mode === "none" ? "unprivileged" : `with ${mode} privilege`;
    return `Scan ran ${how}; ${n} path${n === 1 ? "" : "s"} unreadable`;
  }
  if (CODE.test(head.trim())) {
    return [humanizeEnum(head.trim()), ...rest].join(":");
  }
  return GO_NET_ERROR.test(issue.trim()) ? "TLS handshake failed" : issue;
}

export function endpointFindingCodes(ep: Endpoint): string[] {
  return (ep.issues ?? []).map(findingCode);
}

// The protocol to show for an endpoint. The scan records the protocol it
// INTENDED for the port (443 -> "tls"); when the endpoint then turned out not
// to speak it, the intended name is wrong ("443 · tls" for a plain HTTP
// server), so say what was observed.
export function observedProtocol(ep: Endpoint): string {
  const codes = endpointFindingCodes(ep);
  if (codes.includes("NOT_TLS")) return "not TLS";
  if (codes.includes("POSTGRES_TLS_DISABLED")) return "postgres (TLS off)";
  if (codes.includes("MSSQL_TLS_DISABLED")) return "mssql (TLS off)";
  if (codes.includes("MYSQL_TLS_DISABLED")) return "mysql (TLS off)";
  if (codes.includes("TLS_HANDSHAKE_FAILED")) {
    return `${ep.protocol} (handshake failed)`;
  }
  return ep.protocol;
}

export type FindingChips = {
  shown: { code: string; label: string; high: boolean }[];
  more: number;
};

// Endpoint findings plus the flags of the mapped certificates, most severe
// first, deduplicated; at most `max` chips and a count of the rest.
export function topFindingChips(ep: Endpoint, max = 2): FindingChips {
  const seen = new Set<string>();
  const all: string[] = [];
  const add = (code: string) => {
    if (!code || INFORMATIONAL.has(code) || seen.has(code)) return;
    seen.add(code);
    all.push(code);
  };
  endpointFindingCodes(ep).forEach(add);
  (ep.mapped_certs ?? [])
    .filter((mc) => !mc.chain_ca)
    .forEach((mc) => (mc.risk_flags ?? []).forEach(add));
  const ordered = [
    ...all.filter((c) => HIGH_SEVERITY.has(c)),
    ...all.filter((c) => !HIGH_SEVERITY.has(c)),
  ];
  return {
    shown: ordered.slice(0, max).map((code) => ({
      code,
      label: chipLabel(code),
      high: HIGH_SEVERITY.has(code),
    })),
    more: Math.max(ordered.length - max, 0),
  };
}

// Trust class of the leaf the endpoint presents (not an intermediate it served
// alongside).
export function primaryTrustClass(ep: Endpoint): string | undefined {
  return (ep.mapped_certs ?? []).find((mc) => !mc.chain_ca && mc.trust_class)
    ?.trust_class;
}
