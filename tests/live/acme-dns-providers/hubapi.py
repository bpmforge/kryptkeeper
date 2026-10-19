#!/usr/bin/env python3
"""Hub API helpers for the live harnesses (stdlib only).

Secrets are read from files here and sent only to the hub; they are never
printed and never put on a command line.

  hubapi.py cred  --hub U --bearer T --name N --type api_token --file F
                  [--wrap dns] [--raw-key K] [--set k=v ...]
      Creates an outbound credential and prints its id. --file is JSON (or, with
      --raw-key K, a raw text file stored under K, e.g. a GCP service-account
      key). --wrap dns nests the payload under "dns" (the ACME connector's
      provider-credential object). --set adds non-secret fields.
  hubapi.py scan  --hub U --bearer T --hublog F --secret FILE [--secret FILE ...]
      Reads the whole audit trail through the API (must be non-empty) and counts
      occurrences of every secret value (and every line >= 8 chars of a
      multi-line one) in the hub log and the audit dump. Prints counts only.
      Exit 1 if any occurrence or an empty audit trail.
  hubapi.py selftest
"""
import argparse
import json
import re
import sys
import tempfile
import urllib.error
import urllib.request

SECRET_KEY = re.compile(r"(secret|token|password|passphrase|private_key|key_id|api_key|service_account|username)", re.I)
MIN_LEN = 8


def call(hub, bearer, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(hub + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + bearer, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("message", "")[:200]
        except Exception:
            msg = ""
        sys.stderr.write(f"hub {method} {path} -> HTTP {e.code} {msg}\n")
        sys.exit(1)


def cmd_cred(a):
    if a.raw_key:
        base = {a.raw_key: open(a.file).read()}
    else:
        base = json.load(open(a.file))
    for kv in a.set or []:
        k, _, v = kv.partition("=")
        base[k] = v
    payload = {"dns": base} if a.wrap == "dns" else base
    d = call(a.hub, a.bearer, "POST", "/api/v1/credentials",
             {"name": a.name, "credential_type": a.type, "payload": payload})
    print(d["data"]["id"])


def candidates(text):
    """Every string worth searching for derived from one secret value."""
    out = set()
    t = text.strip()
    if len(t) >= MIN_LEN:
        out.add(t)
    for line in t.splitlines():
        line = line.strip()
        if len(line) >= MIN_LEN:
            out.add(line)
    # a service-account JSON stored as a string: its own private_key counts too
    if t.startswith("{"):
        try:
            out |= secret_values(json.loads(t))
        except ValueError:
            pass
    return out


def secret_values(node, key=""):
    out = set()
    if isinstance(node, dict):
        for k, v in node.items():
            out |= secret_values(v, k)
    elif isinstance(node, list):
        for v in node:
            out |= secret_values(v, key)
    elif isinstance(node, str) and SECRET_KEY.search(key):
        out |= candidates(node)
    return out


def load_secrets(path):
    raw = open(path).read()
    try:
        return secret_values(json.loads(raw))
    except ValueError:
        return candidates(raw)


def dump_audit(hub, bearer):
    rows, cursor = [], ""
    while True:
        d = call(hub, bearer, "GET", "/api/v1/audit?limit=100" + ("&cursor=" + cursor if cursor else ""))
        rows += d["data"]
        cursor = (d.get("meta") or {}).get("next_cursor") or ""
        if not cursor:
            return rows


def count(haystacks, needles):
    return sum(h.count(n) for h in haystacks for n in needles)


def cmd_scan(a):
    rows = dump_audit(a.hub, a.bearer)
    if a.audit_out:
        json.dump(rows, open(a.audit_out, "w"))
    audit = json.dumps(rows)
    log = open(a.hublog, errors="ignore").read()
    total = 0
    for path in a.secret:
        vals = load_secrets(path)
        if not vals:
            print("FAIL: no scannable secret values in a secret file (scan would prove nothing)")
            return 1
        n = count([audit, log], vals)
        total += n
        print(f"secret-file#{a.secret.index(path) + 1}: {len(vals)} values, occurrences in hub log+audit: {n}")
    print(f"audit entries read: {len(rows)}; total occurrences: {total}")
    if not rows:
        print("FAIL: empty audit trail")
        return 1
    return 1 if total else 0


def cmd_selftest(_a):
    with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
        json.dump({"zone": "example.test", "tsig_key_name": "keyname-not-secret", "tsig_secret": "c2VjcmV0LXZhbHVlLXRzaWc="}, f)
        f.flush()
        vals = load_secrets(f.name)
        assert vals == {"c2VjcmV0LXZhbHVlLXRzaWc="}, vals
        assert count(["xx c2VjcmV0LXZhbHVlLXRzaWc= yy"], vals) == 1
        assert count(["nothing here"], vals) == 0
    sa = {"private_key": "-----BEGIN PRIVATE KEY-----\nAAAABBBBCCCCDDDD\n-----END PRIVATE KEY-----\n", "client_email": "a@b"}
    with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
        json.dump({"service_account_json": json.dumps(sa), "project_id": "p"}, f)
        f.flush()
        vals = load_secrets(f.name)
        assert "AAAABBBBCCCCDDDD" in vals and "a@b" not in vals, vals
    print("selftest ok")
    return 0


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("cred")
    for x in ("--hub", "--bearer", "--name", "--file"):
        c.add_argument(x, required=True)
    c.add_argument("--type", default="api_token")
    c.add_argument("--wrap", choices=["dns", "none"], default="none")
    c.add_argument("--raw-key")
    c.add_argument("--set", action="append")
    s = sub.add_parser("scan")
    for x in ("--hub", "--bearer", "--hublog"):
        s.add_argument(x, required=True)
    s.add_argument("--secret", action="append", required=True)
    s.add_argument("--audit-out")
    sub.add_parser("selftest")
    a = p.parse_args()
    sys.exit({"cred": lambda a: cmd_cred(a) or 0, "scan": cmd_scan, "selftest": cmd_selftest}[a.cmd](a))


if __name__ == "__main__":
    main()
