#!/usr/bin/env python3
"""Read a secret store DIRECTLY (not through the plugin or the hub) and report the
current version's certificate fingerprint and the version count.

  storeread.py --provider vault|akv|gcpsm|aws-sm --cred FILE [--set k=v ...]
               [--cafile PEM]
  --cred is the same credential payload file the hub got (JSON; for gcpsm the raw
  service-account key). --set carries non-secret target facts:
    vault: mount=secret path=...        (base_url/token come from --cred)
    akv:   secret_name=...
    gcpsm: project_id=... secret_id=...
    aws-sm: region=... secret_id=...
Prints one JSON line {"version": ..., "fingerprint": hex-or-"", "count": N};
count 0 / empty fingerprint when the secret does not exist yet. Exit 2 on a
query error (the harness treats that as FAIL). Never prints secret material.

  storeread.py selftest      (SigV4 against AWS's published vector)
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)


def die(msg):
    print("QUERY-ERROR: " + msg)
    sys.exit(2)


def http(method, url, headers=None, data=None, ctx=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def fingerprint(text):
    m = CERT_RE.search(text or "")
    if not m:
        return ""
    return hashlib.sha256(base64.b64decode("".join(m.group(1).split()))).hexdigest()


def out(version, text, count):
    print(json.dumps({"version": str(version), "fingerprint": fingerprint(text), "count": count}))


# ---- Vault KV v2 -------------------------------------------------------------
def vault(c, t, cafile):
    ctx = ssl.create_default_context(cafile=cafile) if cafile else None
    base = c["base_url"].rstrip("/")
    mount, path = t.get("mount", "secret").strip("/"), t["path"]
    h = {"X-Vault-Token": c["token"]}
    st, body = http("GET", f"{base}/v1/{mount}/metadata/{path}", h, ctx=ctx)
    if st == 404:
        return print(json.dumps({"version": "0", "fingerprint": "", "count": 0}))
    if st != 200:
        die(f"vault metadata HTTP {st}")
    md = json.loads(body)["data"]
    cur = md["current_version"]
    st, body = http("GET", f"{base}/v1/{mount}/data/{path}", h, ctx=ctx)
    if st != 200:
        die(f"vault data HTTP {st}")
    out(cur, json.loads(body)["data"]["data"].get("certificate", ""), len(md["versions"]))


# ---- OAuth helpers -------------------------------------------------------------
def aad_token(c, scope):
    form = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": c["client_id"],
                                   "client_secret": c["client_secret"], "scope": scope}).encode()
    st, body = http("POST", f"https://login.microsoftonline.com/{c['tenant_id']}/oauth2/v2.0/token",
                    {"Content-Type": "application/x-www-form-urlencoded"}, form)
    if st != 200:
        die(f"aad token HTTP {st}")
    return json.loads(body)["access_token"]


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def gcp_token(sa, scope):
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    aud = "https://oauth2.googleapis.com/token"  # the key's token_uri is not trusted, as in the plugin
    claims = {"iss": sa["client_email"], "scope": scope, "aud": aud, "iat": now, "exp": now + 600}
    si = b64u(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()) + "." + b64u(json.dumps(claims).encode())
    with tempfile.TemporaryDirectory() as d:
        kp = os.path.join(d, "k.pem")
        with os.fdopen(os.open(kp, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            f.write(sa["private_key"])
        r = subprocess.run(["openssl", "dgst", "-sha256", "-sign", kp], input=si.encode(), capture_output=True)
    if r.returncode:
        die("openssl could not sign the JWT")
    form = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                   "assertion": si + "." + b64u(r.stdout)}).encode()
    st, body = http("POST", aud, {"Content-Type": "application/x-www-form-urlencoded"}, form)
    if st != 200:
        die(f"gcp token HTTP {st}")
    return json.loads(body)["access_token"]


# ---- Azure Key Vault -------------------------------------------------------------
def akv(c, t, _cafile):
    tok = aad_token(c, "https://vault.azure.net/.default")
    h = {"Authorization": "Bearer " + tok}
    base, name = c["vault_url"].rstrip("/"), t["secret_name"]
    st, body = http("GET", f"{base}/secrets/{name}?api-version=7.4", h)
    if st == 404:
        return print(json.dumps({"version": "0", "fingerprint": "", "count": 0}))
    if st != 200:
        die(f"akv get secret HTTP {st}")
    cur = json.loads(body)
    count, url = 0, f"{base}/secrets/{name}/versions?api-version=7.4"
    while url:
        st, vb = http("GET", url, h)
        if st != 200:
            die(f"akv list versions HTTP {st}")
        v = json.loads(vb)
        count += len(v.get("value", []))
        url = v.get("nextLink")
    out(cur["id"].rsplit("/", 1)[-1], cur.get("value", ""), count)


# ---- GCP Secret Manager -------------------------------------------------------------
def gcpsm(c, t, _cafile):
    tok = gcp_token(json.loads(c["service_account_json"]), "https://www.googleapis.com/auth/cloud-platform")
    h = {"Authorization": "Bearer " + tok}
    base = f"https://secretmanager.googleapis.com/v1/projects/{urllib.parse.quote(t['project_id'], safe='')}/secrets/{urllib.parse.quote(t['secret_id'], safe='')}"
    st, body = http("GET", base + "/versions/latest:access", h)
    if st == 404:
        return print(json.dumps({"version": "0", "fingerprint": "", "count": 0}))
    if st != 200:
        die(f"gcpsm access latest HTTP {st}")
    cur = json.loads(body)
    count, url = 0, base + "/versions?pageSize=1000"
    while url:
        st, vb = http("GET", url, h)
        if st != 200:
            die(f"gcpsm list versions HTTP {st}")
        v = json.loads(vb)
        count += len(v.get("versions", []))
        url = base + "/versions?pageSize=1000&pageToken=" + urllib.parse.quote(v["nextPageToken"], safe="") if v.get("nextPageToken") else None
    pem = base64.b64decode(cur["payload"]["data"]).decode(errors="ignore")
    out(cur["name"].rsplit("/", 1)[-1], pem, count)


# ---- AWS Secrets Manager (SigV4) -------------------------------------------------------------
def _hmac(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigv4(method, path, query, headers, payload, region, service, access, secret, amzdate):
    names = sorted(headers)
    canon_headers = "".join(f"{n}:{' '.join(headers[n].split())}\n" for n in names)
    signed = ";".join(names)
    canon = "\n".join([method, path, query, canon_headers, signed, hashlib.sha256(payload).hexdigest()])
    scope = f"{amzdate[:8]}/{region}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, hashlib.sha256(canon.encode()).hexdigest()])
    k = _hmac(_hmac(_hmac(_hmac(("AWS4" + secret).encode(), amzdate[:8]), region), service), "aws4_request")
    return hmac.new(k, sts.encode(), hashlib.sha256).hexdigest(), signed, scope


def aws_call(c, region, target, body):
    host = f"secretsmanager.{region}.amazonaws.com"
    payload = json.dumps(body).encode()
    amzdate = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    h = {"content-type": "application/x-amz-json-1.1", "host": host, "x-amz-date": amzdate, "x-amz-target": "secretsmanager." + target}
    if c.get("session_token"):
        h["x-amz-security-token"] = c["session_token"]
    sig, signed, scope = sigv4("POST", "/", "", h, payload, region, "secretsmanager", c["access_key_id"], c["secret_access_key"], amzdate)
    hdrs = {k: v for k, v in h.items() if k != "host"}
    hdrs["Authorization"] = f"AWS4-HMAC-SHA256 Credential={c['access_key_id']}/{scope}, SignedHeaders={signed}, Signature={sig}"
    return http("POST", f"https://{host}/", hdrs, payload)


def awssm(c, t, _cafile):
    region, sid = t["region"], t["secret_id"]
    st, body = aws_call(c, region, "GetSecretValue", {"SecretId": sid})
    if st == 400 and b"ResourceNotFoundException" in body:
        return print(json.dumps({"version": "0", "fingerprint": "", "count": 0}))
    if st != 200:
        die(f"aws GetSecretValue HTTP {st}")
    cur = json.loads(body)
    st, vb = aws_call(c, region, "ListSecretVersionIds", {"SecretId": sid, "IncludeDeprecated": True})
    if st != 200:
        die(f"aws ListSecretVersionIds HTTP {st}")
    out(cur["VersionId"], json.loads(cur["SecretString"]).get("certificate", ""), len(json.loads(vb).get("Versions", [])))


def selftest():
    h = {"content-type": "application/x-www-form-urlencoded; charset=utf-8", "host": "iam.amazonaws.com",
         "x-amz-date": "20150830T123600Z"}
    sig, _, _ = sigv4("GET", "/", "Action=ListUsers&Version=2010-05-08", h, b"", "us-east-1", "iam",
                      "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830T123600Z")
    assert sig == "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7", sig
    pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----"
    assert fingerprint(pem) == hashlib.sha256(base64.b64decode("AAAA")).hexdigest()
    print("selftest ok")


def main():
    if sys.argv[1:] == ["selftest"]:
        return selftest()
    p = argparse.ArgumentParser()
    p.add_argument("--provider", required=True, choices=["vault", "akv", "gcpsm", "aws-sm"])
    p.add_argument("--cred", required=True)
    p.add_argument("--set", action="append")
    p.add_argument("--cafile")
    a = p.parse_args()
    try:
        c = json.load(open(a.cred))
    except ValueError:
        c = {}
    if a.provider == "gcpsm" and "service_account_json" not in c:
        c = {"service_account_json": open(a.cred).read()}
    t = dict(kv.split("=", 1) for kv in (a.set or []))
    try:
        {"vault": vault, "akv": akv, "gcpsm": gcpsm, "aws-sm": awssm}[a.provider](c, t, a.cafile)
    except (KeyError, ValueError) as e:
        die(f"malformed credential or response ({type(e).__name__})")
    except (urllib.error.URLError, ssl.SSLError, OSError) as e:
        die(f"network: {getattr(e, 'reason', type(e).__name__)}")


if __name__ == "__main__":
    main()
