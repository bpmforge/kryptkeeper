# Copyright 2026 Kryptkeeper Authors
# SPDX-License-Identifier: Apache-2.0
import contextlib
import datetime
import io
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

TOKEN = "unit-test-token-SECRET"


class Resp(io.BytesIO):
    pass


class FakeHub(object):
    """Stands in for ansible's fetch_url. routes: {(METHOD, path): (status, body)}; body dict -> JSON."""

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.calls = []

    def __call__(self, module, url, data=None, headers=None, method=None, **kw):
        path = url.split("/api/v1", 1)[1].split("?", 1)[0]
        self.calls.append((method, path, json.loads(data) if data else None, dict(headers or {})))
        route = self.routes.get((method, path))
        if route is None:
            return None, {"status": 404, "body": b'{"error":"not found"}'}
        status, body = route() if callable(route) else route
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        if status >= 400:
            return None, {"status": status, "body": raw}
        return Resp(raw), {"status": status}

    def paths(self, method=None):
        return [c[1] for c in self.calls if method is None or c[0] == method]


@contextlib.contextmanager
def module_args(args):
    try:
        from ansible.module_utils.testing import patch_module_args
    except ImportError:  # ansible-core < 2.19
        from ansible.module_utils import basic
        from ansible.module_utils.common.text.converters import to_bytes
        basic._ANSIBLE_ARGS = to_bytes(json.dumps({"ANSIBLE_MODULE_ARGS": args}))
        yield
        return
    with patch_module_args(args):
        yield


def make_key():
    return ec.generate_private_key(ec.SECP256R1())


def make_csr(key, cn="host.example"):
    return (x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .sign(key, hashes.SHA256()))


def csr_pem(csr):
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def make_cert(key, days_left=90, age_days=1, cn="host.example"):
    now = datetime.datetime.utcnow()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=age_days))
            .not_valid_after(now + datetime.timedelta(days=days_left))
            .sign(key, hashes.SHA256()))


def cert_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def fp(cert):
    return cert.fingerprint(hashes.SHA256()).hex()
