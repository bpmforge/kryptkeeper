#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Kryptkeeper Authors
# SPDX-License-Identifier: Apache-2.0
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: certificate_info
short_description: Read certificates from a Kryptkeeper hub
version_added: "1.1.0"
description:
  - Look a certificate up by SHA-256 fingerprint or serial number, or list certificates matching filters.
  - Read-only. Works in check mode.
author:
  - Kryptkeeper Authors (@bpmforge)
options:
  hub_url:
    description: Base URL of the hub. Falls back to E(KRYPTKEEPER_URL).
    type: str
    required: true
  token:
    description: Bearer API token. Falls back to E(KRYPTKEEPER_TOKEN). Never logged.
    type: str
  ca_path:
    description: CA bundle used to verify the hub's TLS certificate. Falls back to E(KRYPTKEEPER_CA_BUNDLE).
    type: path
  validate_certs:
    description: Verify the hub's TLS certificate.
    type: bool
    default: true
  timeout:
    description: HTTP timeout in seconds.
    type: int
    default: 30
  fingerprint:
    description: SHA-256 fingerprint (hex). A fingerprint the hub does not know yields an empty result.
    type: str
  serial:
    description: Certificate serial number as the hub reports it.
    type: str
  query:
    description: Free-text search (the hub matches names, not serial numbers; use O(serial) for those).
    type: str
    aliases: [q]
  ca_id:
    description: Only certificates issued by this CA.
    type: str
  status:
    description: Only certificates in this status as the hub's list filter defines it (V(active) or V(revoked)).
    type: str
  origin:
    description: Only certificates of this origin.
    type: str
    choices: [internal, imported, discovered, synced]
  management_state:
    description: Only certificates in this management state.
    type: str
    choices: [managed, external, unmanaged]
  owner:
    description: Only certificates owned by this team or owner.
    type: str
  limit:
    description: Return at most this many items.
    type: int
seealso:
  - module: kryptkeeper.pki.certificate
"""

EXAMPLES = r"""
- name: Is this certificate still active at the hub?
  kryptkeeper.pki.certificate_info:
    hub_url: https://kryptkeeper.example.com
    fingerprint: "{{ cert_fp }}"
  register: info
  environment:
    KRYPTKEEPER_TOKEN: "{{ vault_kryptkeeper_token }}"

- name: Active certificates from one CA
  kryptkeeper.pki.certificate_info:
    hub_url: https://kryptkeeper.example.com
    ca_id: "{{ issuing_ca_id }}"
    status: active
    limit: 50
  environment:
    KRYPTKEEPER_TOKEN: "{{ vault_kryptkeeper_token }}"
"""

RETURN = r"""
certificates:
  description: Matching certificate items exactly as the hub's API returns them (empty when none match).
  returned: always
  type: list
  elements: dict
  contains:
    fingerprint_sha256:
      description: SHA-256 fingerprint.
      type: str
    serial_number:
      description: Serial number.
      type: str
    common_name:
      description: Subject common name.
      type: str
    valid_until:
      description: Expiry (RFC 3339).
      type: str
    renewal_status:
      description: Lifecycle status.
      type: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native
from ansible_collections.kryptkeeper.pki.plugins.module_utils.kryptkeeper import (
    KryptkeeperClient,
    KryptkeeperError,
    connection_argument_spec,
)


def find(client, params):
    if params["fingerprint"]:
        item = client.get_certificate(params["fingerprint"].lower())
        return [item] if item else []
    query = {}
    for key, name in (("query", "q"), ("ca_id", "ca_id"), ("status", "status"), ("origin", "origin"),
                      ("management_state", "management_state"), ("owner", "owner")):
        if params.get(key):
            query[name] = params[key]
    # The hub's q filter does not match serial numbers, so a serial lookup walks
    # the (otherwise filtered) list and compares client-side.
    items = client.list_certificates(query, None if params["serial"] else params["limit"])
    if params["serial"]:
        want = params["serial"].strip().lower()
        items = [i for i in items if str(i.get("serial_number", "")).lower() == want]
        if params["limit"]:
            items = items[:params["limit"]]
    return items


def main():
    spec = connection_argument_spec()
    spec.update(
        fingerprint=dict(type="str"),
        serial=dict(type="str"),
        query=dict(type="str", aliases=["q"]),
        ca_id=dict(type="str"),
        status=dict(type="str"),
        origin=dict(type="str", choices=["internal", "imported", "discovered", "synced"]),
        management_state=dict(type="str", choices=["managed", "external", "unmanaged"]),
        owner=dict(type="str"),
        limit=dict(type="int"),
    )
    module = AnsibleModule(argument_spec=spec, supports_check_mode=True,
                           mutually_exclusive=[("fingerprint", "serial")])
    client = KryptkeeperClient(module)
    try:
        items = find(client, module.params)
    except KryptkeeperError as exc:
        module.fail_json(msg=to_native(exc), http_status=exc.status)
    module.exit_json(changed=False, certificates=items)


if __name__ == "__main__":
    main()
