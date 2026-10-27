#!/usr/bin/env python3
"""Lint the certificate/CRL/OCSP corpus written by TestProfileLintCorpus.

Runs pkilint (RFC 5280, CA/B Forum BR + S/MIME BR, CRL, OCSP) and zlint over
every artifact in the manifest and fails on any ERROR/FATAL/WARN finding that
is not in allowlist.json. Every allowlist entry carries a reason; an entry
that matched nothing is reported as stale so the list cannot silently rot.

Kryptkeeper issues private-PKI certificates, so CA/B Forum public-TLS lints
are mostly not applicable. They are still run: the structural checks inside
them catch real encoding defects, and each N/A lint is recorded by name with
the reason it does not apply rather than the whole linter being switched off.

Usage: profile_lint.py CORPUS_DIR ALLOWLIST_JSON [--raw]
Env:   PKILINT_BIN_DIR (dir holding lint_* scripts), ZLINT_BIN (zlint binary)
"""
import fnmatch
import json
import os
import shutil
import subprocess
import sys

FAIL_SEVERITIES = {"FATAL", "ERROR", "WARNING"}

# CA/B Forum certificate type per artifact profile, for lint_cabf_serverauth_cert.
SERVERAUTH_TYPE = {
    "tls-server": "DV-FINAL-CERTIFICATE",
}


def tool(name):
    d = os.environ.get("PKILINT_BIN_DIR")
    p = os.path.join(d, name) if d else shutil.which(name)
    if not p or not os.path.exists(p):
        sys.exit(f"{name} not found (set PKILINT_BIN_DIR)")
    return p


def run_json(argv):
    r = subprocess.run(argv, capture_output=True, text=True)
    if not r.stdout.strip():
        return None, (r.stderr.strip() or f"exit {r.returncode}")
    try:
        return json.loads(r.stdout), None
    except json.JSONDecodeError:
        return None, r.stdout.strip()[:300] + r.stderr.strip()[:300]


def pkilint_findings(argv):
    data, err = run_json(argv + ["-s", "WARNING", "-f", "JSON"])
    if data is None:
        return None, err
    out = []
    for res in data.get("results", []):
        for fd in res.get("finding_descriptions", []):
            out.append((fd["code"], fd["severity"], f'{fd["message"]} @ {res.get("node_path", "")}'))
    return out, None


def zlint_findings(zlint, path):
    data, err = run_json([zlint, "-format", "pem", path])
    if data is None:
        return None, err
    out = []
    for name, res in data.items():
        if not isinstance(res, dict):
            continue
        sev = {"fatal": "FATAL", "error": "ERROR", "warn": "WARNING"}.get(res.get("result"))
        if sev:
            out.append((name, sev, res.get("details", "")))
    return out, None


def artifact_runs(a, corpus, zlint):
    """Yield (linter, findings, error) for each linter that applies to a."""
    path = os.path.join(corpus, a["file"])
    kind, prof, pqc = a["kind"], a["profile"], a.get("pqc", False)
    if kind == "cert":
        yield ("pkilint-pkix",) + pkilint_findings([tool("lint_pkix_cert"), "lint", path])
        # zlint parses with zcrypto, which has no ML-DSA support.
        if not pqc:
            yield ("zlint",) + zlint_findings(zlint, path)
            if prof in SERVERAUTH_TYPE:
                yield ("pkilint-cabf-serverauth",) + pkilint_findings(
                    [tool("lint_cabf_serverauth_cert"), "lint", "-t", SERVERAUTH_TYPE[prof], path])
            if prof == "smime":
                yield ("pkilint-cabf-smime",) + pkilint_findings(
                    [tool("lint_cabf_smime_cert"), "lint", "-t", "MAILBOX-STRICT", path])
    elif kind == "crl":
        yield ("pkilint-crl",) + pkilint_findings([tool("lint_crl"), "lint", "-t", "CRL", "-p", "PKIX", path])
    elif kind == "ocsp":
        yield ("pkilint-ocsp",) + pkilint_findings(
            [tool("lint_ocsp_response"), "lint", "--document-format", "DER", path])


def allowed(entries, linter, code, name, profile):
    for i, e in enumerate(entries):
        if e["linter"] == linter and e["code"] == code \
                and any(fnmatch.fnmatch(name, g) or g == profile for g in e["applies_to"]):
            return i
    return None


def main():
    corpus, allow_path = sys.argv[1], sys.argv[2]
    raw = "--raw" in sys.argv
    zlint = os.environ.get("ZLINT_BIN") or shutil.which("zlint")
    if not zlint:
        sys.exit("zlint not found (set ZLINT_BIN)")
    entries = json.load(open(allow_path))["entries"]
    for e in entries:
        if not e.get("reason", "").strip():
            sys.exit(f"allowlist entry without a reason: {e}")
    used = set()
    manifest = json.load(open(os.path.join(corpus, "manifest.json")))
    bad = tool_errors = checked = 0
    by_class = {}
    for a in manifest:
        for linter, findings, err in artifact_runs(a, corpus, zlint):
            if findings is None:
                tool_errors += 1
                print(f"TOOL-ERROR {a['name']} [{linter}]: {err}")
                continue
            checked += 1
            res = [f for f in findings if f[1] in FAIL_SEVERITIES]
            status = "ok" if not res else f"{len(res)} finding(s)"
            print(f"{a['name']:<34} {linter:<26} {status}")
            for code, sev, msg in res:
                idx = None if raw else allowed(entries, linter, code, a["name"], a["profile"])
                if idx is None:
                    bad += 1
                    print(f"    FAIL  {sev:<7} {code}: {msg}")
                else:
                    by_class[entries[idx]["class"]] = by_class.get(entries[idx]["class"], 0) + 1
                    used.add(idx)
                    print(f"    {entries[idx]['class']:<14} {sev:<7} {code}")
    for i, e in enumerate(entries):
        if i not in used:
            print(f"STALE allowlist entry: {e['linter']} {e['code']} ({e['applies_to']})")
    print(f"\n{len(manifest)} artifacts, {checked} linter runs, {bad} unallowlisted finding(s), "
          f"allowlisted {by_class or 0}, {tool_errors} tool error(s)")
    sys.exit(1 if bad or tool_errors else 0)


if __name__ == "__main__":
    main()
