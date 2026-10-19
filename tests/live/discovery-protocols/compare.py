#!/usr/bin/env python3
"""W24-03: expected-vs-found per protocol for the live protocol-scan fixture.

usage: compare.py expected.json scan.json fingerprints.json [report.json] [rdp_mode]

fingerprints.json: {"<cert stem>": "<sha256 hex>", "ssh_algorithms": ["ssh-ed25519", ...]}
Endpoints are matched by port (the stored coarse protocol is `other`/`rdps`).
Exit 1 when any protocol's recall is below 0.95 (with these counts: any miss).
"""
import json
import sys

RECALL_MIN = 0.95
RSA_EQUIV = {"ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"}


def norm(fp):
    return (fp or "").replace(":", "").lower()


def found(exp, ep, fps):
    if ep is None:
        return False, "no endpoint row"
    if exp.get("hostkeys"):
        advertised = set(ep.get("ssh_host_key_algorithms") or [])
        missing = []
        for alg in fps["ssh_algorithms"]:
            ok = alg in advertised or (alg in RSA_EQUIV and advertised & RSA_EQUIV)
            if not ok:
                missing.append(alg)
        return (not missing), f"missing algorithms {missing} (advertised {sorted(advertised)})"
    want = norm(fps.get(exp["cert"]))
    got = [norm(c.get("fingerprint")) for c in (ep.get("mapped_certs") or [])]
    if want and any(want in g for g in got):
        return True, ""
    return False, f"fingerprint {want[:16]}... not in {[g[:16] for g in got]}"


def main():
    expected, scan_p, fps_p = sys.argv[1:4]
    report_p = sys.argv[4] if len(sys.argv) > 4 else None
    rdp_mode = sys.argv[5] if len(sys.argv) > 5 else "xrdp"
    exp = json.load(open(expected))["endpoints"]
    by_port = {}
    for e in json.load(open(scan_p)):
        by_port.setdefault(e["port"], e)
    fps = json.load(open(fps_p))
    recall = {}
    for x in exp:
        r = recall.setdefault(x["protocol"], {"found": 0, "expected": 0})
        r["expected"] += 1
        ok, why = found(x, by_port.get(x["port"]), fps)
        if ok:
            r["found"] += 1
        else:
            print(f"  MISS {x['protocol']}:{x['port']}: {why}")
    bad = False
    for proto, r in recall.items():
        label = proto + (":stub" if proto == "rdp" and rdp_mode == "stub" else "")
        print(f"{label:<10} {r['found']}/{r['expected']}")
        if r["found"] / r["expected"] < RECALL_MIN:
            bad = True
    tf = sum(r["found"] for r in recall.values())
    te = sum(r["expected"] for r in recall.values())
    print(f"TOTAL      {tf}/{te}")
    if report_p:
        json.dump({"recall": recall, "total": {"found": tf, "expected": te}, "rdp_mode": rdp_mode},
                  open(report_p, "w"), indent=1)
    print("RESULT:", "FAIL" if bad else "PASS")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
