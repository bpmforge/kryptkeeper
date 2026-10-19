#!/usr/bin/env python3
"""Independent check that no _acme-challenge TXT record is left in a DNS provider.

Uses the provider's own HTTP API with the SAME credential file the hub used, so
a stale record cannot hide behind the hub's own bookkeeping.

  txtleft.py --provider route53|azure|gcp --cred FILE --zone ZONE --fqdn NAME
             [--set k=v ...]          (non-secret extras: resource_group, project_id, ...)
Exit 0: no TXT record at NAME. Exit 1: a TXT record is still there.
Exit 2: the provider could not be queried (the harness treats that as FAIL).
Prints a one-line summary, never a secret.
  txtleft.py selftest     (SigV4 against AWS's published test vector)
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


def http(method, url, headers=None, data=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def die(msg):
    print("QUERY-ERROR: " + msg)
    sys.exit(2)


# ---- AWS Signature Version 4 ------------------------------------------------
def _hmac(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigv4(method, path, query, headers, payload, region, service, access, secret, amzdate):
    """Returns (signature, signed_headers, credential_scope). headers must be
    lower-case names and include host and x-amz-date."""
    names = sorted(headers)
    canon_headers = "".join(f"{n}:{' '.join(headers[n].split())}\n" for n in names)
    signed = ";".join(names)
    canon = "\n".join([method, path, query, canon_headers, signed, hashlib.sha256(payload).hexdigest()])
    scope = f"{amzdate[:8]}/{region}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, hashlib.sha256(canon.encode()).hexdigest()])
    k = _hmac(_hmac(_hmac(_hmac(("AWS4" + secret).encode(), amzdate[:8]), region), service), "aws4_request")
    return hmac.new(k, sts.encode(), hashlib.sha256).hexdigest(), signed, scope


def aws_get(host, path, query, cred, region="us-east-1", service="route53"):
    amzdate = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    h = {"host": host, "x-amz-date": amzdate}
    if cred.get("session_token"):
        h["x-amz-security-token"] = cred["session_token"]
    sig, signed, scope = sigv4("GET", path, query, h, b"", region, service,
                               cred["access_key_id"], cred["secret_access_key"], amzdate)
    auth = f"AWS4-HMAC-SHA256 Credential={cred['access_key_id']}/{scope}, SignedHeaders={signed}, Signature={sig}"
    hdrs = {k: v for k, v in h.items() if k != "host"}
    hdrs["Authorization"] = auth
    return http("GET", f"https://{host}{path}" + ("?" + query if query else ""), hdrs)


def route53(cred, zone, fqdn):
    host = "route53.amazonaws.com"
    zid = (cred.get("hosted_zone_id") or "").removeprefix("/hostedzone/")
    if not zid:
        q = "dnsname=" + urllib.parse.quote(zone.rstrip(".") + ".", safe="") + "&maxitems=1"
        st, body = aws_get(host, "/2013-04-01/hostedzonesbyname", q, cred)
        if st != 200:
            die(f"route53 hostedzonesbyname HTTP {st}")
        ns = {"r": "https://route53.amazonaws.com/doc/2013-04-01/"}
        z = ET.fromstring(body).find(".//r:HostedZone", ns)
        if z is None or z.findtext("r:Name", namespaces=ns) != zone.rstrip(".") + ".":
            die("route53: zone not found")
        zid = z.findtext("r:Id", namespaces=ns).removeprefix("/hostedzone/")
    name = fqdn.rstrip(".") + "."
    q = "name=" + urllib.parse.quote(name, safe="") + "&type=TXT&maxitems=1"
    st, body = aws_get(host, f"/2013-04-01/hostedzone/{zid}/rrset", q, cred)
    if st != 200:
        die(f"route53 rrset list HTTP {st}")
    ns = {"r": "https://route53.amazonaws.com/doc/2013-04-01/"}
    left = [r for r in ET.fromstring(body).findall(".//r:ResourceRecordSet", ns)
            if r.findtext("r:Type", namespaces=ns) == "TXT" and (r.findtext("r:Name", namespaces=ns) or "").lower() == name.lower()]
    return len(left)


# ---- Azure DNS ----------------------------------------------------------------
def azure(cred, zone, fqdn):
    form = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": cred["client_id"],
                                   "client_secret": cred["client_secret"],
                                   "scope": "https://management.azure.com/.default"}).encode()
    st, body = http("POST", f"https://login.microsoftonline.com/{cred['tenant_id']}/oauth2/v2.0/token",
                    {"Content-Type": "application/x-www-form-urlencoded"}, form)
    if st != 200:
        die(f"azure token HTTP {st}")
    tok = json.loads(body)["access_token"]
    rel = fqdn.rstrip(".")[: -len(zone.rstrip(".")) - 1]
    rg = cred.get("resource_group")
    base = f"https://management.azure.com/subscriptions/{cred['subscription_id']}"
    if rg:
        base += f"/resourceGroups/{rg}"
    if not rg:
        die("azure: set resource_group (KK_AZ_RESOURCE_GROUP) so the record can be queried")
    url = f"{base}/providers/Microsoft.Network/dnsZones/{zone.rstrip('.')}/TXT/{urllib.parse.quote(rel, safe='')}?api-version=2018-05-01"
    st, _ = http("GET", url, {"Authorization": "Bearer " + tok})
    if st == 200:
        return 1
    if st == 404:
        return 0
    die(f"azure record-set GET HTTP {st}")


# ---- GCP Cloud DNS ------------------------------------------------------------
def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def gcp(cred, zone, fqdn):
    sa = json.loads(cred["service_account_json"])
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    aud = sa.get("token_uri", "https://oauth2.googleapis.com/token")
    claims = {"iss": sa["client_email"], "scope": "https://www.googleapis.com/auth/ndev.clouddns.readonly",
              "aud": aud, "iat": now, "exp": now + 600}
    signing_input = b64u(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()) + "." + b64u(json.dumps(claims).encode())
    with tempfile.TemporaryDirectory() as d:
        kp = os.path.join(d, "k.pem")
        fd = os.open(kp, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(sa["private_key"])
        r = subprocess.run(["openssl", "dgst", "-sha256", "-sign", kp], input=signing_input.encode(), capture_output=True)
    if r.returncode != 0:
        die("gcp: openssl could not sign the JWT")
    jwt = signing_input + "." + b64u(r.stdout)
    form = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jwt}).encode()
    st, body = http("POST", aud, {"Content-Type": "application/x-www-form-urlencoded"}, form)
    if st != 200:
        die(f"gcp token HTTP {st}")
    h = {"Authorization": "Bearer " + json.loads(body)["access_token"]}
    proj = urllib.parse.quote(cred["project_id"], safe="")
    st, body = http("GET", f"https://dns.googleapis.com/dns/v1/projects/{proj}/managedZones?dnsName=" +
                    urllib.parse.quote(zone.rstrip(".") + ".", safe=""), h)
    if st != 200:
        die(f"gcp managedZones HTTP {st}")
    zones = json.loads(body).get("managedZones", [])
    if not zones:
        die("gcp: no managed zone for that dns name")
    name = fqdn.rstrip(".") + "."
    st, body = http("GET", f"https://dns.googleapis.com/dns/v1/projects/{proj}/managedZones/{zones[0]['name']}/rrsets?type=TXT&name=" +
                    urllib.parse.quote(name, safe=""), h)
    if st != 200:
        die(f"gcp rrsets HTTP {st}")
    return len(json.loads(body).get("rrsets", []))


def selftest():
    # AWS's published example (Signature Version 4 test suite, iam ListUsers).
    h = {"content-type": "application/x-www-form-urlencoded; charset=utf-8", "host": "iam.amazonaws.com",
         "x-amz-date": "20150830T123600Z"}
    sig, signed, _ = sigv4("GET", "/", "Action=ListUsers&Version=2010-05-08", h, b"", "us-east-1", "iam",
                           "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830T123600Z")
    want = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    assert sig == want, (sig, want)
    assert signed == "content-type;host;x-amz-date"
    print("selftest ok")


def main():
    if sys.argv[1:] == ["selftest"]:
        return selftest()
    p = argparse.ArgumentParser()
    p.add_argument("--provider", required=True, choices=["route53", "azure", "gcp"])
    p.add_argument("--cred", required=True)
    p.add_argument("--zone", required=True)
    p.add_argument("--fqdn", required=True)
    p.add_argument("--set", action="append")
    a = p.parse_args()
    cred = {}
    try:
        cred = json.load(open(a.cred))
    except (OSError, ValueError):
        if a.provider == "gcp":  # a raw service-account key file
            cred = {"service_account_json": open(a.cred).read()}
        else:
            die("credential file is not JSON")
    if a.provider == "gcp" and "service_account_json" not in cred and "private_key" in cred:
        cred = {"service_account_json": open(a.cred).read()}
    for kv in a.set or []:
        k, _, v = kv.partition("=")
        cred[k] = v
    try:
        n = {"route53": route53, "azure": azure, "gcp": gcp}[a.provider](cred, a.zone, a.fqdn)
    except (KeyError, ValueError) as e:
        die(f"malformed credential or response ({type(e).__name__})")
    except urllib.error.URLError as e:
        die(f"network: {e.reason}")
    print(f"{n} TXT record(s) at {a.fqdn}")
    sys.exit(1 if n else 0)


if __name__ == "__main__":
    main()
