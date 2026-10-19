#!/usr/bin/env python3
"""Recorded-fixture vendor API server for tests/live/inventory-sources (W24-28).

usage: fixture_server.py <port> <fixtures_dir> <pem_dir> [bind_addr]

Serves the Sectigo, Entrust, AWS Private CA and Google CAS response shapes the
hub's inventory sources consume (internal/bootstrap/inventory_source_commercial.go),
each under its own path prefix (/sectigo /entrust /aws /gcp). Fixture bodies
live in fixtures/<vendor>/ with {{PEM_n}} placeholders; the PEMs are generated
by run.sh at run time into <pem_dir>/<vendor>_<n>.pem (nothing committed).
Credentials are checked loosely (presence only), except that a Sectigo login of
"kk-bad-login" is rejected with 401 (the isolation check). Header values are
never logged. Standard library only.
"""
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BAD_SECTIGO_LOGIN = "kk-bad-login"


class Handler(BaseHTTPRequestHandler):
    fixtures = ""
    pems = ""

    def log_message(self, fmt, *args):  # request line only, never headers
        sys.stderr.write("%s %s\n" % (self.command, self.path))

    # -- helpers ---------------------------------------------------------
    def _render(self, vendor, name):
        path = os.path.join(self.fixtures, vendor, name)
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        is_json = name.endswith(".json")

        def sub(m):
            with open(os.path.join(self.pems, "%s_%s.pem" % (vendor, m.group(1))), encoding="utf-8") as fh:
                pem = fh.read().strip()
            return json.dumps(pem)[1:-1] if is_json else pem

        return re.sub(r"\{\{PEM_(\d+)\}\}", sub, body)

    def _send(self, code, body, ctype="application/json"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _deny(self):
        self._send(401, '{"error":"unauthorized"}')

    def _missing(self):
        self._send(404, '{"error":"not found"}')

    def _fixture(self, vendor, name, ctype="application/json"):
        try:
            self._send(200, self._render(vendor, name), ctype)
        except FileNotFoundError:
            self._missing()

    # -- routes ----------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path
        if p == "/healthz":
            return self._send(200, "ok", "text/plain")
        if p.startswith("/sectigo/"):
            h = self.headers
            if not (h.get("login") and h.get("password") and h.get("customerUri")) or h.get("login") == BAD_SECTIGO_LOGIN:
                return self._deny()
            rest = p[len("/sectigo"):]
            if rest == "/api/ssl/v1":
                if q.get("position", ["0"])[0] == "0":
                    return self._fixture("sectigo", "listing.json")
                return self._send(200, "[]")
            m = re.fullmatch(r"/api/ssl/v1/collect/(\d+)/x509CO", rest)
            if m:
                return self._fixture("sectigo", "collect_%s.txt" % m.group(1), "text/plain")
        elif p.startswith("/entrust/"):
            if not (self.headers.get("Authorization") or "").startswith("Bearer ") or len(self.headers.get("Authorization")) <= 7:
                return self._deny()
            rest = p[len("/entrust"):]
            if rest == "/cvs/api/v1/certificates":
                return self._fixture("entrust", "listing.json")
            m = re.fullmatch(r"/cvs/api/v1/certificates/(\d+)", rest)
            if m:
                return self._fixture("entrust", "detail_%s.json" % m.group(1))
        elif p.startswith("/gcp/"):
            auth = self.headers.get("Authorization") or ""
            # A real OAuth bearer token never contains quote characters; this
            # catches a JSON-quoted payload being sent verbatim.
            if not auth.startswith("Bearer ") or len(auth) <= 7 or '"' in auth:
                return self._deny()
            if re.fullmatch(r"/gcp/v1/projects/[^/]+/locations/[^/]+/caPools/[^/]+/certificates", p):
                page = "page2.json" if q.get("pageToken", [""])[0] == "tok2" else "page1.json"
                return self._fixture("gcp", page)
        return self._missing()

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if u.path.rstrip("/") == "/aws":
            if not (self.headers.get("Authorization") or "").startswith("AWS4-HMAC-SHA256"):
                return self._deny()
            target = self.headers.get("X-Amz-Target", "")
            if target == "ACMPrivateCA.ListCertificateAuthorities":
                return self._fixture("aws", "list.json")
            if target == "ACMPrivateCA.GetCertificateAuthorityCertificate":
                try:
                    arn = json.loads(raw or b"{}").get("CertificateAuthorityArn", "")
                except ValueError:
                    arn = ""
                m = re.search(r"certificate-authority/ca-(\d+)$", arn)
                if m:
                    return self._fixture("aws", "get_ca_%s.json" % m.group(1))
        return self._missing()


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    port, Handler.fixtures, Handler.pems = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    bind = sys.argv[4] if len(sys.argv) > 4 else os.environ.get("KK_FIXTURE_BIND", "127.0.0.1")
    ThreadingHTTPServer((bind, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
