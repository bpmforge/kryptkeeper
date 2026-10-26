"""W32-03: Python SDK contract smoke. Uses ONLY the generated package
(sdk/api-py, installed into the run's venv); the spec declares no response
schemas, so bodies are read from raw_data of the *_with_http_info result."""
import json
import os
import sys

import kryptkeeper_api
from kryptkeeper_api.api.certificates_api import CertificatesApi
from kryptkeeper_api.models.issue_certificate_request import IssueCertificateRequest
from kryptkeeper_api.models.revoke_certificate_request import RevokeCertificateRequest


def fail(msg):
    print(f"[sdk-smoke py] FAIL {msg}", file=sys.stderr)
    sys.exit(1)


def env(name):
    v = os.environ.get(name)
    if not v:
        fail(f"{name} must be set")
    return v


def body(resp):
    raw = resp.raw_data
    return raw.decode() if isinstance(raw, (bytes, bytearray)) else (raw or "")


def main():
    hub, token, ca_id, template_id, csr_dir = (
        env("HUB_URL"), env("HUB_TOKEN"), env("CA_ID"), env("TEMPLATE_ID"), env("CSR_DIR"))
    cfg = kryptkeeper_api.Configuration(host=hub + "/api/v1", access_token=token)
    with kryptkeeper_api.ApiClient(cfg) as client:
        api = CertificatesApi(client)

        issued, first = set(), ""
        for i in range(1, 6):
            with open(os.path.join(csr_dir, f"csr-{i}.pem")) as f:
                csr = f.read()
            res = api.issue_certificate_with_http_info(
                IssueCertificateRequest(ca_id=ca_id, template_id=template_id, csr_pem=csr))
            text = body(res)
            if res.status_code != 201:
                fail(f"issue {i}: status {res.status_code} (want 201): {text}")
            fp = (json.loads(text).get("data") or {}).get("fingerprint_sha256")
            if not fp:
                fail(f"issue {i}: no fingerprint in {text}")
            issued.add(fp)
            first = first or fp

        seen, requests, cursor = set(), 0, None
        while True:
            res = api.list_certificates_with_http_info(limit=2, cursor=cursor)
            requests += 1
            page = json.loads(body(res))
            for c in page.get("data") or []:
                seen.add(c.get("fingerprint_sha256"))
            nxt = (page.get("meta") or {}).get("next_cursor")
            if nxt in (None, ""):
                break
            try:
                cursor = int(nxt)
            except ValueError:
                fail(f"list: non-integer next_cursor {nxt!r}")
            if requests > 100:
                fail("list: pagination did not terminate")
        if requests < 3:
            fail(f"list: {requests} requests, want >= 3 (>= 2 pages)")
        missing = issued - seen
        if missing:
            fail(f"list: issued fingerprints not seen across pages: {sorted(missing)}")

        res = api.revoke_certificate_with_http_info(first, revoke_certificate_request=RevokeCertificateRequest(reason_code=1))
        if res.status_code != 200:
            fail(f"revoke: status {res.status_code} (want 200, no approval gate expected): {body(res)}")
        res = api.get_certificate_with_http_info(first)
        text = body(res)
        d = json.loads(text).get("data") or {}
        if d.get("renewal_status") != "revoked" or not d.get("revoked_at"):
            fail(f"get after revoke: renewal_status {d.get('renewal_status')!r}, body {text}")
    print(f"[sdk-smoke py] ok: issued 5, listed in {requests} requests, revoked 1")


main()
