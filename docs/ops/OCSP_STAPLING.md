# OCSP stapling and Must-Staple for nginx, Apache and HAProxy (W23-53)

How to make a web server staple the hub's OCSP response, how to check that it
does, and what Must-Staple can and cannot do today. Every snippet below was run
once against a real server in a container (section 8). Anything not run is
marked "not verified".

## 1. Before you start

Stapling means the web server fetches a signed OCSP response for its own
certificate and sends it inside the TLS handshake, so the client does not have
to contact the responder.

Prerequisites:

- The leaf is valid for more than 7 days. The hub puts an OCSP pointer on a
  leaf only when its validity exceeds 7 days (`issueLeafCertificate` in
  `internal/ca/engine.go`), so a short-lived leaf has nothing to staple.
- The web server host can reach the certificate's OCSP URL over plain HTTP.
  The hub's URL is `<revocation base>/ocsp`, from
  `KRYPTKEEPER_REVOCATION_BASE_URL` (else `KRYPTKEEPER_BASE_URL`), served by the
  listener on `KRYPTKEEPER_REVOCATION_HTTP_ADDR` (`cmd/kryptkeeper/revocation_http.go`).
- The issuing CA certificate is on the host. Hub responses are signed by the
  issuing CA key itself (`internal/ocsp/responder.go`) and valid for 24 hours,
  so the issuing CA certificate alone verifies them.

| | nginx | Apache httpd 2.4 | HAProxy |
|---|---|---|---|
| Turn it on | `ssl_stapling on;` | `SSLUseStapling on` plus a global `SSLStaplingCache` | `ocsp-update on` in a `crt-list`, or an `.ocsp` file beside the PEM |
| Issuer certificate | `ssl_trusted_certificate` (and the chain in `ssl_certificate`) | the chain in `SSLCertificateFile` | the chain in the PEM, or a `.issuer` file |
| Fetching | lazy: the first handshake after start has no staple | on the first handshake in the test (section 8) | `ocsp-update on`: right after start; file mode: you refresh the file |
| Responder down | no staple, error logged | synthesized `tryLater` unless `SSLStaplingFakeTryLater off`, then no staple | not exercised here |
| Revoked response | not stapled, error logged | stapled as `revoked` | stapled as `revoked` |

Directive names were checked against the official documentation:
[nginx ngx_http_ssl_module](https://nginx.org/en/docs/http/ngx_http_ssl_module.html),
[Apache mod_ssl](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html),
[HAProxy 3.0 configuration](https://docs.haproxy.org/3.0/configuration.html) and
[management](https://docs.haproxy.org/3.0/management.html) manuals.

Use `example.internal` below as a stand-in for your own host name, and replace
the `/pki/...` paths with your own.

## 2. nginx

Tested on nginx 1.27.5.

```nginx
worker_processes 1;
error_log /dev/stderr info;
events { worker_connections 64; }
http {
    access_log off;
    server {
        listen 8443 ssl;
        server_name example.internal;

        ssl_certificate         /pki/fullchain.pem;
        ssl_certificate_key     /pki/leaf.key;

        ssl_stapling            on;
        ssl_stapling_verify     on;
        ssl_trusted_certificate /pki/ca.pem;

        resolver 192.0.2.53 valid=300s;
        resolver_timeout 5s;

        location / { return 200 "ok\n"; }
    }
}
```

- `fullchain.pem` is the leaf followed by the issuing CA certificate.
  `ca.pem` is the issuing CA certificate. nginx documents that
  `ssl_stapling_verify` needs the issuer, the root and every intermediate
  configured as trusted through `ssl_trusted_certificate`.
- `resolver` is needed only because this certificate's OCSP URL is a host
  name; remove it if the URL is an IP address. Use your own DNS server. The test
  used the container's DNS server, `192.168.127.1`.
- Override the responder with `ssl_stapling_responder http://host:port/ocsp;`
  (`http://` only, per the nginx docs). Not verified.
- Lazy fetch: the first handshake after start has no staple. Warm it up with
  `curl -k https://example.internal:8443/` and check the second handshake.
  Observed: first handshake `no responses sent`, second handshake `good`.
- `ssl_stapling_file /path/response.der;` serves a file produced by
  `openssl ocsp -respout` instead of querying the responder. Not verified.

## 3. Apache httpd 2.4

Tested on Apache 2.4.69 with OpenSSL 3.5.7.

```apache
ServerRoot "/usr/local/apache2"
ServerName example.internal
Listen 8443

LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule socache_shmcb_module modules/mod_socache_shmcb.so
LoadModule ssl_module modules/mod_ssl.so

User daemon
Group daemon
ErrorLog /proc/self/fd/2
LogLevel ssl:info

SSLStaplingCache "shmcb:/usr/local/apache2/logs/ssl_stapling(128000)"

<VirtualHost *:8443>
    ServerName example.internal
    SSLEngine on
    SSLCertificateFile    /pki/fullchain.pem
    SSLCertificateKeyFile /pki/leaf.key

    SSLUseStapling on
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors off
    SSLStaplingFakeTryLater off
</VirtualHost>
```

- The `LoadModule` lines and the `User`/`Group`/`ErrorLog` lines are the
  minimum the official `httpd` image needs; on a packaged install keep your own.
- `SSLStaplingCache` is valid only in server config, outside any
  `<VirtualHost>`; mod_ssl requires it before stapling can be enabled.
- `SSLStaplingReturnResponderErrors off` keeps responder errors away from
  clients. Apache still synthesized a `tryLater` response when the responder was
  down, until `SSLStaplingFakeTryLater off` was added (observed in the test; the
  Apache documentation says the fake response is only effective with
  `SSLStaplingReturnResponderErrors` on). Revoked responses are always
  stapled regardless of these settings, per the Apache docs.
- `SSLStaplingForceURL http://host:port/ocsp` overrides the URL in the
  certificate. Not verified.

## 4. HAProxy

Tested on HAProxy 3.4.7. Both ways need the issuer: put the leaf, the issuing CA
certificate and the private key in one PEM, or provide a `site.pem.issuer` file
(`ssl-load-extra-files`, HAProxy configuration manual).

Common `haproxy.cfg` skeleton (the `bind` line changes per mode):

```haproxy
global
    log stdout format raw local0
defaults
    mode http
    log global
    timeout connect 5s
    timeout client  30s
    timeout server  30s

frontend fe
    bind :8443 ssl crt /certs/site.pem
    http-request return status 200 content-type text/plain string "ok\n"
```

### 4a. File based

`site.pem` is the leaf, then the issuing CA certificate, then the key.
HAProxy loads `site.pem.ocsp` from beside it. Create and refresh that file with:

```sh
openssl ocsp -issuer ca.pem -cert leaf.pem -url http://ocsp.example.internal:19080/ocsp \
  -CAfile ca.pem -respout /certs/site.pem.ocsp -no_nonce
```

Run it from cron or a systemd timer well inside the 24 hour response validity,
then reload HAProxy, or push the file with the runtime command
`set ssl ocsp-response` (HAProxy management manual). Verified: HAProxy 3.4.7
staples a `site.pem.ocsp` present at start. Not verified: the timer refresh and
the runtime command.

### 4b. Automatic (`ocsp-update`)

Replace the `bind` line with a `crt-list`:

```haproxy
    bind :8443 ssl crt-list /certs/site.crtlist
```

and put this in `/certs/site.crtlist` (the certificate path must be absolute, or
use `crt-base`):

```
/certs/site.pem [ocsp-update on] example.internal
```

HAProxy fetches the response from the URL in the certificate right after
start and then at least hourly (HAProxy manual: `ocsp-update`). It logs
`<OCSP-UPDATE> /certs/site.pem 1 "Update successful" 0 1`. The issuer must be
known, here from the PEM. Tested on 3.4.7 only. The HAProxy 2.8 configuration
manual documents `ocsp-update`; the 2.6 manual does not. 2.8 itself was not run.

## 5. Verify

```sh
openssl s_client -connect HOST:PORT -servername HOST -status -CAfile ca.pem </dev/null 2>&1 | sed -n '/OCSP response/,/^---/p'
```

- Working: `OCSP Response Status: successful (0x0)`, `Cert Status: good`, and a
  `This Update` / `Next Update` pair.
- Not stapling: `no responses sent`. On nginx run the command a second time
  before concluding.
- Revoked: after `POST /api/v1/certificates/{fp}/revoke` the staple reads
  `Cert Status: revoked` on Apache and HAProxy. nginx does not staple a
  revoked response and logs `certificate status "revoked" in the OCSP response`,
  so a client sees `no responses sent`. The web server keeps its cached staple until it next
  refreshes, so restart it or wait to see the change.
- Hub side, independent of any web server:

```sh
openssl ocsp -issuer ca.pem -cert leaf.pem -url http://ocsp.example.internal:19080/ocsp -CAfile ca.pem
```

### Known hub issue: GET requests whose base64 contains `/`

nginx requests the response with `GET /ocsp/<base64 of the DER request>`. The
hub's GET handler (`Handler` in `internal/ocsp/responder.go`) takes the part of
the decoded path after the last `/`. A `/` inside the base64 (percent-encoded as
`%2F` on the wire) cuts the request in half, and the hub answers
`malformedrequest`. The hub logs `ocsp: malformed request: asn1: structure error:
length too large`, and nginx logs `OCSP response not successful (1: malformedrequest)`.

Whether it happens depends on the CA's issuer hashes and the serial number,
which are part of the request. In the run in section 8, 5 of 9 hub CAs
produced a request containing `/`; nginx stapled fine against a CA whose
request had none, and `openssl ocsp -url` (POST) worked for the two CAs tried. Until the
handler is fixed, nginx against a hub CA can silently get no staple. Apache and
HAProxy were not run against the hub in this record.

## 6. Must-Staple

Must-Staple is the TLS Feature extension (OID `1.3.6.1.5.5.7.1.24`) with value
`status_request` (RFC 7633). A client that sees it in the certificate refuses
the connection when the server sends no valid staple.

**The hub cannot issue Must-Staple certificates in v1.0.** The OID sits under the
PKIX arc `1.3.6.1.5.5.7.1`, and `isEngineControlledExtension` in
`internal/ca/engine.go` rejects any caller-supplied extension under that arc
("controlled by the CA and cannot be supplied"). No template field emits it
(`grep -rin 'tlsfeature\|must-staple' internal` is empty). A template flag
(`must_staple`) is a follow-up for the product owner; do not rely on it.

For a certificate from another CA, request the extension with an
`openssl.cnf`:

```ini
[req]
distinguished_name = dn
req_extensions = ext
prompt = no
[dn]
CN = example.internal
[ext]
subjectAltName = DNS:example.internal
tlsfeature = status_request
```

```sh
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ms.key -out ms.csr -config ms.cnf
openssl req  -in ms.csr  -noout -text | grep -A1 'TLS Feature'
openssl x509 -in ms.pem  -noout -text | grep -A1 'TLS Feature'
```

Both commands print `status_request` (run once; the CA must copy the extension
into the certificate, which a CA that ignores CSR extensions will not).

Operational rule: a Must-Staple site must staple on every server that can
answer for it, and the staple must be present before the first client connects.
Apache stapled on the first handshake and HAProxy `ocsp-update on` fetches right
after start; nginx fetches lazily, so warm it up after every start and reload.
If the responder is unreachable and the cached staple expires, Must-Staple
clients get a hard failure, so treat the responder as part of the site's
availability. nginx not stapling a `revoked` response is the safe direction for
Must-Staple (the client refuses).

## 7. Failure behaviour and troubleshooting

"Observed" lines were produced in the section 8 run.

| Symptom | Cause | Log line to look for |
|---|---|---|
| No staple, responder down | responder unreachable | nginx, observed: `recv() failed (111: Connection refused) while requesting certificate status` and `OCSP responder prematurely closed connection`. Apache, observed: `AH01974: could not connect to OCSP responder` and `AH01941: stapling_renew_response: responder error` |
| Apache sends `trylater` | `SSLStaplingFakeTryLater` left at its default | `OCSP Response Status: trylater (0x3)` in `s_client` (observed) |
| No staple, certificate revoked | nginx drops revoked responses | nginx, observed: `certificate status "revoked" in the OCSP response`. Apache, observed: `AH02969: stapling_check_response: response has certificate status revoked` (and the revoked staple is sent) |
| nginx gets `malformedrequest` from the hub | the GET issue above | nginx, observed: `OCSP response not successful (1: malformedrequest)`; hub log: `ocsp: malformed request` |
| Wrong or missing issuer chain | `ssl_trusted_certificate`, the PEM chain or the `.issuer` file lacks the issuing CA | not reproduced; nginx and HAProxy document the issuer requirement. Test with the stand-in responder did not make nginx drop the staple when `ssl_trusted_certificate` held an unrelated CA, so do not rely on that setting alone; check with `s_client` |
| OCSP host name does not resolve (nginx) | no `resolver` | not reproduced; nginx documents that `resolver` is needed for a host name |
| Staple rejected as expired or not yet valid | clock skew between web server and responder | not reproduced; Apache documents `SSLStaplingResponseTimeSkew` (default 300 s) and `SSLStaplingResponseMaxAge` |
| Staple stops refreshing in HAProxy file mode | the `.ocsp` file is stale | not reproduced; HAProxy `ocsp-update on` avoids this |

## 8. Verification record

Date 2026-10-16 (UTC), repository commit `de19969b` (branch `kk/w23-g1`), run by
the Claude agent for batch W23 group 1, with `podman` on macOS. Responder for
the section 2 to 4 runs: a stand-in `openssl ocsp -index ... -rsigner ca.pem`
(OpenSSL 3.6.5) on the host, throwaway ECDSA P-256 CA, 30-day leaf with an
OCSP URL on `host.containers.internal`. Digests are the image digests `podman`
reported for the platform it pulled.

| Server | Image and digest | Command | Result |
|---|---|---|---|
| nginx 1.27.5 | `docker.io/library/nginx:1.27-alpine` `sha256:63ffc0d1f14e4082b832c6a42e606e9a0384a526f16ddd720af7c1f018f2f7c4` | `s_client -status`, twice | 1st: `no responses sent`; 2nd: `successful`, `Cert Status: good` |
| nginx 1.27.5, revoked leaf | same | restart, warm up, `s_client -status` | `no responses sent`; error log `certificate status "revoked"` |
| Apache 2.4.69 | `docker.io/library/httpd:2.4` `sha256:cabd93f700c94b496e901a253f2cf1860c8532451fe97e6711cf7c084e46db6c` | `s_client -status` | `successful`, `Cert Status: good` on the first handshake |
| Apache 2.4.69, revoked leaf | same | `s_client -status` | `successful`, `Cert Status: revoked` |
| Apache 2.4.69, responder down | same | `s_client -status` | default `SSLStaplingFakeTryLater`: `trylater (0x3)`; with `SSLStaplingFakeTryLater off`: `no responses sent`; staple `good` again after the responder returned |
| HAProxy 3.4.7, file mode | `docker.io/library/haproxy:lts` `sha256:023faeb06253e48a1059ea043ebca7c99c1b19452c6bee561e649e0a4861b146` | `s_client -status` | `successful`, `Cert Status: good` |
| HAProxy 3.4.7, `ocsp-update on` | same | `s_client -status` | `successful`, `Cert Status: good` immediately after start; log `Update successful` |
| HAProxy 3.4.7, `ocsp-update on`, revoked leaf | same | `s_client -status` | `successful`, `Cert Status: revoked` |
| nginx 1.27.5 against the real hub | nginx as above; hub built from this commit, `KRYPTKEEPER_REVOCATION_HTTP_ADDR=0.0.0.0:19080`, 30-day hub-issued leaf | `s_client -status`, twice | 1st: `no responses sent`; 2nd: `successful`, `Cert Status: good`, responder `CN = Stapling Root 1`. After `POST /api/v1/certificates/{fp}/revoke`: `openssl ocsp` reports `revoked`; nginx logs `certificate status "revoked"` and sends no staple |
| nginx against the real hub, first CA | same | `s_client -status` | no staple: the GET issue in section 5 |
| Must-Staple CSR and certificate | OpenSSL 3.6.5 | commands in section 6 | `TLS Feature: status_request` in the request and in a certificate signed with `tlsfeature = status_request` |

Not verified: `ssl_stapling_file`, `ssl_stapling_responder`, `SSLStaplingForceURL`,
the HAProxy runtime `set ssl ocsp-response` and timer refresh, HAProxy 2.8, Apache
and HAProxy against the hub, and the troubleshooting rows marked "not
reproduced". Re-run the relevant row before relying on any of them.
