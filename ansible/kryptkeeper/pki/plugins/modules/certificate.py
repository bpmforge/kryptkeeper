#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Kryptkeeper Authors
# SPDX-License-Identifier: Apache-2.0
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: certificate
short_description: Issue, renew or revoke a certificate on a Kryptkeeper hub
version_added: "1.1.0"
description:
  - With O(state=present) issues a certificate from a CSR and writes the PEM (and chain) to O(path).
  - Idempotent. When O(path) already holds a certificate that has not expired, is not within O(renew_before_days)
    of expiry, matches the CSR's public key and is not revoked at the hub, nothing is changed.
    An expiring certificate that the hub still holds as active is renewed through the renew endpoint,
    anything else is issued.
  - With O(state=absent) revokes the certificate identified by O(fingerprint) or by the certificate at O(path).
  - Needs the C(cryptography) Python library on the managed host to read PEM files.
author:
  - Kryptkeeper Authors (@bpmforge)
requirements:
  - cryptography
options:
  state:
    description: V(present) issues or renews, V(absent) revokes.
    type: str
    choices: [present, absent]
    default: present
  hub_url:
    description: Base URL of the hub, for example V(https://kryptkeeper.example.com). Falls back to E(KRYPTKEEPER_URL).
    type: str
    required: true
  token:
    description: Bearer API token. Falls back to E(KRYPTKEEPER_TOKEN). Never logged.
    type: str
  ca_path:
    description: CA bundle used to verify the hub's TLS certificate. Falls back to E(KRYPTKEEPER_CA_BUNDLE).
    type: path
  validate_certs:
    description: Verify the hub's TLS certificate. Leave on outside throwaway labs.
    type: bool
    default: true
  timeout:
    description: HTTP timeout in seconds.
    type: int
    default: 30
  csr_path:
    description: Path of a PEM CSR on the managed host. Exactly one of O(csr_path) and O(csr_content) for O(state=present).
    type: path
  csr_content:
    description: PEM CSR as a string.
    type: str
  ca_id:
    description: ID of the hub CA to sign with. Required to issue.
    type: str
  template_id:
    description: ID of the certificate template to apply. Required to issue.
    type: str
  path:
    description:
      - Where the certificate PEM is written (with the chain appended unless O(chain_path) is set).
      - For O(state=absent) the certificate here is revoked when O(fingerprint) is not given.
    type: path
  chain_path:
    description: Write the issuing chain here instead of appending it to O(path).
    type: path
  renew_before_days:
    description: Renew when the certificate at O(path) expires within this many days.
    type: int
    default: 30
  fingerprint:
    description: SHA-256 fingerprint (hex) of the certificate to revoke.
    type: str
  reason:
    description: Revocation reason (RFC 5280 name).
    type: str
    default: unspecified
    choices:
      - unspecified
      - key_compromise
      - ca_compromise
      - affiliation_changed
      - superseded
      - cessation_of_operation
      - certificate_hold
      - privilege_withdrawn
  scope:
    description: V(inventory_only) records the revocation in the hub without asking the issuing CA (admin only).
    type: str
    choices: [inventory_only]
extends_documentation_fragment:
  - ansible.builtin.files
seealso:
  - module: kryptkeeper.pki.certificate_info
notes:
  - Check mode is supported. It performs only read requests and reports what would change.
  - A hub that answers 202 (the template needs approval) makes the module fail with the approval id; re-run after approval.
"""

EXAMPLES = r"""
- name: Issue a certificate for a web server (re-running is a no-op until 30 days before expiry)
  kryptkeeper.pki.certificate:
    hub_url: https://kryptkeeper.example.com
    ca_id: "{{ issuing_ca_id }}"
    template_id: "{{ web_template_id }}"
    csr_path: /etc/ssl/private/web.csr
    path: /etc/ssl/certs/web.pem
    renew_before_days: 21
    mode: "0644"
    owner: root
  environment:
    KRYPTKEEPER_TOKEN: "{{ vault_kryptkeeper_token }}"

- name: Revoke the certificate that is on disk
  kryptkeeper.pki.certificate:
    state: absent
    hub_url: https://kryptkeeper.example.com
    path: /etc/ssl/certs/web.pem
    reason: cessation_of_operation
  environment:
    KRYPTKEEPER_TOKEN: "{{ vault_kryptkeeper_token }}"

- name: Record a revocation that was already done at the upstream CA
  kryptkeeper.pki.certificate:
    state: absent
    hub_url: https://kryptkeeper.example.com
    fingerprint: "{{ old_fingerprint }}"
    scope: inventory_only
  environment:
    KRYPTKEEPER_TOKEN: "{{ vault_kryptkeeper_token }}"
"""

RETURN = r"""
fingerprint:
  description: SHA-256 fingerprint (hex) of the certificate issued, kept or revoked.
  returned: when a certificate is involved
  type: str
serial:
  description: Serial number of the certificate.
  returned: when known
  type: str
not_after:
  description: Expiry (RFC 3339).
  returned: when known
  type: str
action:
  description: What happened.
  returned: always
  type: str
  sample: issued
  choices: [unchanged, issued, renewed, revoked]
revocation_scope:
  description: Where the revocation was recorded (V(ca), V(upstream) or V(inventory_only)).
  returned: when a certificate was revoked
  type: str
"""

import os
import tempfile
import traceback
from datetime import datetime, timedelta, timezone

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils.common.text.converters import to_bytes, to_native
from ansible_collections.kryptkeeper.pki.plugins.module_utils.kryptkeeper import (
    KryptkeeperClient,
    KryptkeeperError,
    connection_argument_spec,
)

CRYPTO_IMP_ERR = None
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    CRYPTO_IMP_ERR = traceback.format_exc()
    HAS_CRYPTO = False

REASON_CODES = {
    "unspecified": 0,
    "key_compromise": 1,
    "ca_compromise": 2,
    "affiliation_changed": 3,
    "superseded": 4,
    "cessation_of_operation": 5,
    "certificate_hold": 6,
    "privilege_withdrawn": 9,
}


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def read_text(path):
    with open(path, "rb") as fh:
        return fh.read()


def load_cert(pem):
    return x509.load_pem_x509_certificate(pem)


def cert_fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def not_after_of(cert):
    try:
        return cert.not_valid_after_utc.replace(tzinfo=None)
    except AttributeError:  # cryptography < 42
        return cert.not_valid_after


def not_before_of(cert):
    try:
        return cert.not_valid_before_utc.replace(tzinfo=None)
    except AttributeError:
        return cert.not_valid_before


def spki_der(public_key):
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


class CertificateModule(object):
    def __init__(self, module, client=None):
        self.module = module
        self.p = module.params
        self.client = client or KryptkeeperClient(module)

    # -- helpers -----------------------------------------------------
    def csr_pem(self):
        if self.p["csr_content"]:
            return self.p["csr_content"]
        try:
            return to_native(read_text(self.p["csr_path"]))
        except (IOError, OSError) as exc:
            self.module.fail_json(msg="cannot read CSR %s: %s" % (self.p["csr_path"], to_native(exc)))

    def existing_cert(self):
        path = self.p["path"]
        if not path or not os.path.exists(path):
            return None
        try:
            return load_cert(read_text(path))
        except ValueError:
            return None  # unreadable or not a certificate: treat as absent and replace it

    # -- present -----------------------------------------------------
    def present(self):
        csr_pem = self.csr_pem()
        try:
            csr = x509.load_pem_x509_csr(to_bytes(csr_pem))
        except ValueError as exc:
            self.module.fail_json(msg="the CSR is not valid PEM: %s" % to_native(exc))
        if not csr.is_signature_valid:
            self.module.fail_json(msg="the CSR's self-signature does not verify")

        old = self.existing_cert()
        old_fp = None
        reuse = False
        renewable = False
        if old is not None:
            old_fp = cert_fingerprint(old)
            now = utcnow()
            fresh = (not_before_of(old) <= now
                     and not_after_of(old) - now > timedelta(days=self.p["renew_before_days"]))
            same_key = spki_der(old.public_key()) == spki_der(csr.public_key())
            item = self.client.get_certificate(old_fp)
            revoked = item is not None and item.get("renewal_status") == "revoked"
            if fresh and same_key and not revoked:
                reuse = True
            renewable = same_key and item is not None and item.get("renewal_status") == "active"

        if reuse:
            result = dict(changed=False, action="unchanged", fingerprint=old_fp,
                          serial=format(old.serial_number, "x"),
                          not_after=not_after_of(old).strftime("%Y-%m-%dT%H:%M:%SZ"))
            self.apply_file_attrs(result)
            return result

        action = "renewed" if renewable else "issued"
        if self.module.check_mode:
            return dict(changed=True, action=action, fingerprint=old_fp or "")

        data = None
        if renewable:
            status, doc = self.client.post("/certificates/%s/renew" % old_fp, {"csr_pem": csr_pem}, ok_statuses=(409,))
            if status == 409:
                renewable = False
                action = "issued"
            else:
                data = (doc or {}).get("data", doc)
        if data is None:
            if not self.p["ca_id"] or not self.p["template_id"]:
                self.module.fail_json(msg="ca_id and template_id are required to issue a certificate")
            status, doc = self.client.post("/certificates", {
                "ca_id": self.p["ca_id"], "template_id": self.p["template_id"], "csr_pem": csr_pem})
            data = (doc or {}).get("data", doc) or {}
            if status == 202:
                self.module.fail_json(
                    msg="the template requires approval; request is pending (approval_id %s). Re-run once approved."
                    % data.get("approval_id", "unknown"))

        fp = data.get("fingerprint_sha256")
        if not fp:
            self.module.fail_json(msg="the hub's response carried no fingerprint")
        _, leaf = self.client.get("/certificates/%s/download" % fp, query={"format": "pem"}, raw=True)
        chain = b""
        ca_id = data.get("ca_id") or self.p["ca_id"]
        if ca_id:
            _, chain = self.client.get("/cas/%s/chain" % ca_id, query={"format": "pem"}, raw=True)
        self.write_outputs(leaf, chain)
        result = dict(changed=True, action=action, fingerprint=fp, serial=data.get("serial_number", ""),
                      not_after=data.get("valid_until", ""))
        self.apply_file_attrs(result)
        return result

    def write_outputs(self, leaf, chain):
        path, chain_path = self.p["path"], self.p["chain_path"]
        if not path:
            return
        body = leaf if leaf.endswith(b"\n") else leaf + b"\n"
        if chain and not chain_path:
            body += chain
        self._write(path, body)
        if chain and chain_path:
            self._write(chain_path, chain)

    def _write(self, dest, content):
        tmp_fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(dest)), prefix=".kk-")
        try:
            with os.fdopen(tmp_fd, "wb") as fh:
                fh.write(content)
            self.module.atomic_move(tmp, dest, unsafe_writes=self.p.get("unsafe_writes", False))
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def apply_file_attrs(self, result):
        if self.p["path"] and os.path.exists(self.p["path"]) and not self.module.check_mode:
            if self.module.set_fs_attributes_if_different(
                    self.module.load_file_common_arguments(self.p), False):
                result["changed"] = True

    # -- absent ------------------------------------------------------
    def absent(self):
        fp = (self.p["fingerprint"] or "").lower()
        if not fp:
            cert = self.existing_cert() if self.p["path"] else None
            if cert is None:
                if self.p["path"] and not os.path.exists(self.p["path"]):
                    return dict(changed=False, action="unchanged", msg="no certificate at path")
                self.module.fail_json(msg="state=absent needs fingerprint, or a path holding a certificate")
            fp = cert_fingerprint(cert)
        item = self.client.get_certificate(fp)
        if item is None or item.get("renewal_status") == "revoked":
            return dict(changed=False, action="unchanged", fingerprint=fp,
                        serial=(item or {}).get("serial_number", ""))
        if self.module.check_mode:
            return dict(changed=True, action="revoked", fingerprint=fp, serial=item.get("serial_number", ""))
        body = {"reason_code": REASON_CODES[self.p["reason"]], "reason_text": "revoked by ansible"}
        if self.p["scope"]:
            body["scope"] = self.p["scope"]
        _, doc = self.client.post("/certificates/%s/revoke" % fp, body)
        data = (doc or {}).get("data", doc) or {}
        return dict(changed=True, action="revoked", fingerprint=fp, serial=item.get("serial_number", ""),
                    not_after=item.get("valid_until", ""), revocation_scope=data.get("revocation_scope", ""))

    def run(self):
        try:
            return self.present() if self.p["state"] == "present" else self.absent()
        except KryptkeeperError as exc:
            self.module.fail_json(msg=to_native(exc), http_status=exc.status)


def build_module():
    spec = connection_argument_spec()
    spec.update(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        csr_path=dict(type="path"),
        csr_content=dict(type="str"),
        ca_id=dict(type="str"),
        template_id=dict(type="str"),
        path=dict(type="path"),
        chain_path=dict(type="path"),
        renew_before_days=dict(type="int", default=30),
        fingerprint=dict(type="str"),
        reason=dict(type="str", default="unspecified", choices=sorted(REASON_CODES)),
        scope=dict(type="str", choices=["inventory_only"]),
    )
    return AnsibleModule(
        argument_spec=spec,
        mutually_exclusive=[("csr_path", "csr_content")],
        required_if=[("state", "present", ("csr_path", "csr_content"), True)],
        add_file_common_args=True,
        supports_check_mode=True,
    )


def main():
    module = build_module()
    if not HAS_CRYPTO:
        module.fail_json(msg=missing_required_lib("cryptography"), exception=CRYPTO_IMP_ERR)
    module.exit_json(**CertificateModule(module).run())


if __name__ == "__main__":
    main()
