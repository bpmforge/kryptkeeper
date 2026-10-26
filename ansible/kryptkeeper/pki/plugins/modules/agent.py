#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Kryptkeeper Authors
# SPDX-License-Identifier: Apache-2.0
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: agent
short_description: Mint an agent enrolment token and optionally install and enrol the Linux agent
version_added: "1.1.0"
description:
  - Mints a single-use enrolment token through the hub API (admin token required).
  - With O(install=true) downloads the agent release archive from O(package_url), verifies its SHA-256 against
    O(package_sha256) B(before extracting or running anything), installs the binary, writes a systemd unit and a
    private environment file holding the token, and starts the service. The agent exchanges the token for its
    long-lived credential on first start and keeps that in its own credentials file.
  - Idempotent for installs. A host that already has the agent binary and its credentials file is reported unchanged
    and no token is minted.
  - Linux with systemd only. Must run as root for O(install=true).
author:
  - Kryptkeeper Authors (@bpmforge)
options:
  hub_url:
    description: Base URL of the hub. Falls back to E(KRYPTKEEPER_URL).
    type: str
    required: true
  token:
    description: Admin bearer API token. Falls back to E(KRYPTKEEPER_TOKEN). Never logged.
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
  label:
    description: Label stored with the token (at most 128 characters). Defaults to the host name.
    type: str
  ttl_seconds:
    description: Token lifetime, 1 to 604800.
    type: int
    default: 3600
  install:
    description: Install and enrol the agent on this host.
    type: bool
    default: false
  package_url:
    description: URL of the C(kryptkeeper-agent_<version>_linux_<arch>.tar.gz) release archive. Required with O(install=true).
    type: str
  package_sha256:
    description: Expected SHA-256 (hex) of the archive, from the release's C(checksums.txt). Required with O(install=true).
    type: str
  agent_ca_file:
    description: Path on this host of the PEM bundle the agent uses to verify the hub (when the hub's CA is private).
    type: path
  agent_name:
    description: Name the agent registers under. Defaults to the host name.
    type: str
notes:
  - Check mode reports whether an install or token would happen and mints nothing.
  - Verify O(package_sha256) against the cosign-signed C(checksums.txt) of the release, not against a value fetched from the same place as the archive.
"""

EXAMPLES = r"""
- name: Mint a token to hand to an agent installed another way
  kryptkeeper.pki.agent:
    hub_url: https://kryptkeeper.example.com
    label: build-farm
    ttl_seconds: 900
  register: enrol
  environment:
    KRYPTKEEPER_TOKEN: "{{ vault_kryptkeeper_admin_token }}"

- name: Install and enrol the Linux agent
  become: true
  kryptkeeper.pki.agent:
    hub_url: https://kryptkeeper.example.com
    install: true
    package_url: https://github.com/bpmforge/kryptkeeper/releases/download/v1.1.0/kryptkeeper-agent_1.1.0_linux_amd64.tar.gz
    package_sha256: "{{ agent_archive_sha256 }}"
    agent_ca_file: /etc/ssl/certs/kryptkeeper-hub-ca.pem
  environment:
    KRYPTKEEPER_TOKEN: "{{ vault_kryptkeeper_admin_token }}"
"""

RETURN = r"""
token_id:
  description: ID of the enrolment token that was minted.
  returned: when a token was minted
  type: str
expires_at:
  description: Token expiry (RFC 3339).
  returned: when a token was minted
  type: str
enrollment_token:
  description: The single-use token. Returned only when O(install=false), because then the caller needs it. Treat as a secret.
  returned: when a token was minted and install is false
  type: str
installed:
  description: Whether the agent was installed and started by this run.
  returned: always
  type: bool
"""

import hashlib
import io
import os
import platform
import socket
import tarfile
import tempfile

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.urls import fetch_url
from ansible_collections.kryptkeeper.pki.plugins.module_utils.kryptkeeper import (
    KryptkeeperClient,
    KryptkeeperError,
    connection_argument_spec,
)

BIN = "/usr/local/bin/kryptkeeper-agent"
STATE_DIR = "/var/lib/kryptkeeper-agent"
CRED_FILE = STATE_DIR + "/credentials.env"
ENV_DIR = "/etc/kryptkeeper-agent"
ENV_FILE = ENV_DIR + "/env"
UNIT = "/etc/systemd/system/kryptkeeper-agent.service"
MAX_ARCHIVE = 200 * 1024 * 1024

UNIT_TEXT = """[Unit]
Description=Kryptkeeper Satellite Agent
Documentation=https://github.com/bpmforge/kryptkeeper
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=kryptkeeper-agent
Group=kryptkeeper-agent
EnvironmentFile=%(env)s
ExecStart=%(bin)s
Restart=on-failure
RestartSec=30s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%(state)s
PrivateTmp=true
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
""" % {"env": ENV_FILE, "bin": BIN, "state": STATE_DIR}


def download_verified(module, url, expected_sha256):
    """Fetch the archive and return its bytes only if the SHA-256 matches."""
    resp, info = fetch_url(module, url, timeout=module.params["timeout"] * 4, ca_path=module.params["ca_path"])
    if info.get("status") != 200 or resp is None:
        module.fail_json(msg="cannot download %s: HTTP %s %s" % (url, info.get("status"), info.get("msg")))
    data = resp.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        module.fail_json(msg="agent archive is larger than %d bytes; refusing" % MAX_ARCHIVE)
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256.lower():
        module.fail_json(msg="sha256 mismatch for %s: expected %s, got %s. Nothing was extracted or run."
                         % (url, expected_sha256.lower(), actual))
    return data


def extract_agent_binary(module, data):
    """Return the kryptkeeper-agent file from the (already verified) archive, reading nothing else."""
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.isfile() and os.path.basename(member.name) == "kryptkeeper-agent":
                    return tar.extractfile(member).read()
    except (tarfile.TarError, OSError) as exc:
        module.fail_json(msg="cannot read the agent archive: %s" % to_native(exc))
    module.fail_json(msg="the archive does not contain a kryptkeeper-agent binary")


def write_file(module, dest, content, mode, owner=None, group=None):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dest), prefix=".kk-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content if isinstance(content, bytes) else content.encode("utf-8"))
        os.chmod(tmp, mode)
        module.atomic_move(tmp, dest)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    if owner or group:
        module.set_owner_if_different(dest, owner, False)
        if group:
            module.set_group_if_different(dest, group, False)


def run(module, cmd, check=True):
    rc, out, err = module.run_command(cmd)
    if check and rc != 0:
        module.fail_json(msg="command failed: %s: %s" % (" ".join(cmd), (err or out).strip()))
    return rc


def install(module, data, enrol_token):
    p = module.params
    binary = extract_agent_binary(module, data)
    if run(module, ["id", "-u", "kryptkeeper-agent"], check=False) != 0:
        run(module, ["useradd", "--system", "--home-dir", STATE_DIR, "--shell", "/usr/sbin/nologin",
                     "--user-group", "kryptkeeper-agent"])
    os.makedirs(STATE_DIR, exist_ok=True)
    module.set_owner_if_different(STATE_DIR, "kryptkeeper-agent", False)
    module.set_group_if_different(STATE_DIR, "kryptkeeper-agent", False)
    os.chmod(STATE_DIR, 0o700)
    os.makedirs(ENV_DIR, exist_ok=True)
    os.chmod(ENV_DIR, 0o755)
    write_file(module, BIN, binary, 0o755)
    env = ["KRYPTKEEPER_HUB_URL=%s" % p["hub_url"].rstrip("/"),
           "KRYPTKEEPER_ENROLL_TOKEN=%s" % enrol_token,
           "KRYPTKEEPER_AGENT_CREDENTIALS_FILE=%s" % CRED_FILE,
           "KRYPTKEEPER_AGENT_NAME=%s" % (p["agent_name"] or socket.gethostname())]
    if p["agent_ca_file"]:
        env.append("KRYPTKEEPER_HUB_CA_CERT_FILE=%s" % p["agent_ca_file"])
    write_file(module, ENV_FILE, "\n".join(env) + "\n", 0o600)
    write_file(module, UNIT, UNIT_TEXT, 0o644)
    run(module, ["systemctl", "daemon-reload"])
    run(module, ["systemctl", "enable", "--now", "kryptkeeper-agent"])


def main():
    spec = connection_argument_spec()
    spec.update(
        label=dict(type="str"),
        ttl_seconds=dict(type="int", default=3600),
        install=dict(type="bool", default=False),
        package_url=dict(type="str"),
        package_sha256=dict(type="str"),
        agent_ca_file=dict(type="path"),
        agent_name=dict(type="str"),
    )
    module = AnsibleModule(
        argument_spec=spec,
        required_if=[("install", True, ("package_url", "package_sha256"))],
        supports_check_mode=True,
    )
    p = module.params
    if not 1 <= p["ttl_seconds"] <= 604800:
        module.fail_json(msg="ttl_seconds must be between 1 and 604800")
    if p["install"]:
        if platform.system() != "Linux":
            module.fail_json(msg="install is supported on Linux only")
        if os.geteuid() != 0 and not module.check_mode:
            module.fail_json(msg="install needs root (use become)")
        if os.path.exists(BIN) and os.path.exists(CRED_FILE):
            module.exit_json(changed=False, installed=False, msg="agent is already installed and enrolled")
        if len(p["package_sha256"]) != 64 or any(c not in "0123456789abcdefABCDEF" for c in p["package_sha256"]):
            module.fail_json(msg="package_sha256 must be a 64-character hex SHA-256")
    if module.check_mode:
        module.exit_json(changed=True, installed=False, msg="would mint a token" + (" and install the agent" if p["install"] else ""))

    archive = None
    if p["install"]:
        # Verify first so a bad archive never costs a minted token.
        archive = download_verified(module, p["package_url"], p["package_sha256"])

    client = KryptkeeperClient(module)
    try:
        _, doc = client.post("/agent/enrollment-tokens", {
            "label": (p["label"] or socket.gethostname())[:128], "ttl_seconds": p["ttl_seconds"]})
    except KryptkeeperError as exc:
        module.fail_json(msg=to_native(exc), http_status=exc.status)
    data = (doc or {}).get("data", doc) or {}
    result = dict(changed=True, installed=False, token_id=data.get("id", ""), expires_at=data.get("expires_at", ""))
    if p["install"]:
        install(module, archive, data["token"])
        result["installed"] = True
    else:
        result["enrollment_token"] = data.get("token", "")
    module.exit_json(**result)


if __name__ == "__main__":
    main()
