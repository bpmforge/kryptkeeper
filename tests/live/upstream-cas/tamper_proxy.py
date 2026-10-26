#!/usr/bin/env python3
"""W36-16 tamper proxy: an HTTPS reverse proxy in front of Vault that makes the
upstream CA misbehave. It swaps the CSR in every pki/sign request for another
one (MODE file: "key" = a CSR for a different key, same names; "san" = the same
names plus one extra SAN) so Vault signs something other than what the hub
requested. The hub must refuse the result. Test fixture only."""
import http.client, json, ssl, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_PORT, CERT, KEY, UPSTREAM, UPSTREAM_CA, MODE_FILE, CSR_KEY, CSR_SAN = sys.argv[1:9]
host, _, port = UPSTREAM.partition(":")


class H(BaseHTTPRequestHandler):
    def _do(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if "/sign/" in self.path and body:
            mode = open(MODE_FILE).read().strip()
            d = json.loads(body)
            d["csr"] = open(CSR_KEY if mode == "key" else CSR_SAN).read()
            if mode == "san":
                d["alt_names"] = (d.get("alt_names", "") + ",extra-san.uat.example").lstrip(",")
            body = json.dumps(d).encode()
            print("tampered sign request, mode=" + mode, flush=True)
        ctx = ssl.create_default_context(cafile=UPSTREAM_CA)
        c = http.client.HTTPSConnection(host, int(port), context=ctx, timeout=30)
        hdrs = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length")}
        c.request(self.command, self.path, body=body or None, headers=hdrs)
        r = c.getresponse()
        data = r.read()
        self.send_response(r.status)
        self.send_header("Content-Type", r.getheader("Content-Type", "application/json"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = _do

    def log_message(self, *a):
        pass


srv = ThreadingHTTPServer(("0.0.0.0", int(LISTEN_PORT)), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
