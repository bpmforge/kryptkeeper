#!/usr/bin/env python3
"""W24-01: compare what discovery stored with the corpus ground truth.

usage: compare.py ground-truth.json scan.json served.json PREFIX report.json [fast_scan_seconds]

Exit 1 when overall recall < 0.95, false-positive rate > 0.02 or any found
served-TLS endpoint has a posture mismatch.
"""
import json
import sys

RECALL_MIN, FP_MAX = 0.95, 0.02
FP_FLAGS = {"SELF_SIGNED", "EXPIRED", "WEAK_KEY"}


def norm(fp):
    return (fp or "").replace(":", "").lower()


def issue_codes(ep):
    return {i.split(":", 1)[0] for i in (ep.get("issues") or [])}


def main():
    gt_path, scan_path, served_path, prefix, report_path = sys.argv[1:6]
    fast_s = int(sys.argv[6]) if len(sys.argv) > 6 else None
    gt = json.load(open(gt_path))
    scan = json.load(open(scan_path))
    served = json.load(open(served_path))
    start = gt["subnet_octet4_start"]
    by_key = {(e["hostname"], e["port"]): e for e in scan}

    def host(e):
        return f"{prefix}.{start + e['ip_index']}"

    classes, posture_bad, found_ids = {}, [], set()
    for t in gt["endpoints"]:
        ep = by_key.get((host(t), t["port"]))
        cls = classes.setdefault(t["class"], {"found": 0, "expected": 0})
        cls["expected"] += 1
        if ep is None:
            continue
        certs = ep.get("mapped_certs") or []
        codes = issue_codes(ep)
        if t["class"] == "not_tls":
            ok = "NOT_TLS" in codes
        elif t["class"] in ("tls10", "tls11"):
            ok = "DEPRECATED_TLS_VERSION" in codes or bool(certs)
        else:
            ok = bool(certs)
        if ok and certs:
            want = norm(served.get(t["id"], {}).get("leaf_sha256"))
            got = norm(certs[0].get("fingerprint"))
            if got and want and got != want:
                ok = False
        if not ok:
            continue
        cls["found"] += 1
        found_ids.add(t["id"])
        if t["class"] == "not_tls":
            continue  # no TLS, so no posture to compare
        cp = ep.get("crypto_posture") or {}
        flags = {f for c in certs for f in (c.get("risk_flags") or [])}
        problems = []
        if cp.get("negotiated_version") != t["tls_max"]:
            problems.append(f"version {cp.get('negotiated_version')!r} != {t['tls_max']}")
        if bool((cp.get("pqc") or {}).get("hybrid_negotiated")) != t["hybrid"]:
            problems.append(f"hybrid_negotiated != {t['hybrid']}")
        if not set(t["expect_flags"]) <= flags:
            problems.append(f"flags {sorted(flags)} missing {t['expect_flags']}")
        if problems:
            posture_bad.append({"id": t["id"], "problems": problems})

    # Extra-port endpoints (full-scan phase, 8443/9443): reported separately,
    # never in the 43-endpoint denominator and never false positives.
    extras = gt.get("extra_port_endpoints", [])
    extras_found = sum(1 for x in extras if (by_key.get((host(x), x["port"])) or {}).get("mapped_certs"))
    known = {(host(t), t["port"]) for t in gt["endpoints"]} | {(host(x), x["port"]) for x in extras}
    truth_flags = {(host(t), t["port"]): set(t["expect_flags"]) for t in gt["endpoints"]}
    reported = [e for e in scan if e["hostname"].startswith(prefix + ".")]
    fps = []
    for e in reported:
        k = (e["hostname"], e["port"])
        if k not in known:
            fps.append({"endpoint": f"{k[0]}:{k[1]}", "why": "not in ground truth"})
            continue
        flags = {f for c in (e.get("mapped_certs") or []) for f in (c.get("risk_flags") or [])}
        extra = (flags & FP_FLAGS) - truth_flags.get(k, set())
        if extra:
            fps.append({"endpoint": f"{k[0]}:{k[1]}", "why": f"unexpected flags {sorted(extra)}"})

    n_exp = len(gt["endpoints"])
    n_found = sum(c["found"] for c in classes.values())
    recall = n_found / n_exp
    fp_rate = len(fps) / len(reported) if reported else 0.0
    print(f"{'class':<14} found/expected")
    for name, c in classes.items():
        print(f"{name:<14} {c['found']}/{c['expected']}")
    print(f"{'extra-ports':<14} {extras_found}/{len(extras)}")
    print(f"TOTAL          {n_found}/{n_exp}  recall={recall:.4f}")
    print(f"reported endpoints on {prefix}.*: {len(reported)}  false positives: {len(fps)}  fp_rate={fp_rate:.4f}")
    for f in fps:
        print("  FP:", f)
    print(f"posture mismatches among found: {len(posture_bad)}")
    for p in posture_bad:
        print("  POSTURE:", p)
    report = {
        "expected": n_exp, "found": n_found, "recall": round(recall, 4),
        "false_positive_rate": round(fp_rate, 4), "false_positives": fps,
        "posture_mismatches": len(posture_bad), "posture_detail": posture_bad,
        "extra_port_found": extras_found, "extra_port_expected": len(extras),
        "classes": classes, "fast_scan_seconds": fast_s,
    }
    json.dump(report, open(report_path, "w"), indent=1)
    ok = recall >= RECALL_MIN and fp_rate <= FP_MAX and not posture_bad
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
