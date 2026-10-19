#!/usr/bin/env python3
"""Reference verifier for Kryptkeeper signed webhooks (W32-09).

Same algorithm as docs/ops/WEBHOOK_VERIFY.md: HMAC-SHA256(secret,
timestamp + "." + raw body), header `v1=<hex>[,v1=<hex>]`, reject a missing
signature, reject |now - timestamp| > max-age, constant-time compare.

Input is one JSONL record as written by echo_receiver.py (ts, method, path,
headers, body). Exit 0 = accepted, 1 = rejected (reason on stderr), 2 = usage.

Tamper helpers for the live test (applied to the record before verifying):
  --drop-signature        remove X-Kryptkeeper-Signature
  --restamp-age SECONDS   rewrite X-Kryptkeeper-Timestamp to now-SECONDS and
                          recompute a VALID signature, so only staleness is wrong
"""
import argparse
import hashlib
import hmac
import json
import sys
import time

SIG = "x-kryptkeeper-signature"
TS = "x-kryptkeeper-timestamp"


def sign(secret, ts, body):
    mac = hmac.new(secret.encode(), ts.encode() + b"." + body.encode(), hashlib.sha256)
    return "v1=" + mac.hexdigest()


def verify(secret, headers, body, max_age, now=None):
    """Return (ok, reason)."""
    sig = headers.get(SIG, "")
    if not sig:
        return False, "missing signature"
    ts = headers.get(TS, "")
    try:
        ts_int = int(ts)
    except ValueError:
        return False, "bad timestamp"
    if abs((now if now is not None else time.time()) - ts_int) > max_age:
        return False, "stale timestamp"
    want = sign(secret, ts, body)
    if any(hmac.compare_digest(p.strip(), want) for p in sig.split(",")):
        return True, "ok"
    return False, "signature mismatch"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--secret", required=True)
    ap.add_argument("--max-age", type=int, default=300)
    ap.add_argument("--record", help="file holding ONE JSON record (default: stdin)")
    ap.add_argument("--drop-signature", action="store_true")
    ap.add_argument("--restamp-age", type=int)
    a = ap.parse_args()
    raw = open(a.record).read() if a.record else sys.stdin.read()
    try:
        rec = json.loads(raw)
        headers = {k.lower(): v for k, v in rec["headers"].items()}
        body = rec["body"]
    except (ValueError, KeyError) as e:
        print("unreadable record: %s" % e, file=sys.stderr)
        return 2
    if a.drop_signature:
        headers.pop(SIG, None)
    if a.restamp_age is not None:
        ts = str(int(time.time()) - a.restamp_age)
        headers[TS] = ts
        headers[SIG] = sign(a.secret, ts, body)
    ok, reason = verify(a.secret, headers, body, a.max_age)
    print(("ACCEPT: " if ok else "REJECT: ") + reason, file=sys.stderr if not ok else sys.stdout)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
