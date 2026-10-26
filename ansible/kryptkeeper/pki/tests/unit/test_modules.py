# Copyright 2026 Kryptkeeper Authors
# SPDX-License-Identifier: Apache-2.0
import hashlib
import io
import json
import tarfile

import pytest

from ansible_collections.kryptkeeper.pki.plugins.modules import agent, certificate, certificate_info
from ansible_collections.kryptkeeper.pki.plugins.module_utils import kryptkeeper as utils

from helpers import (TOKEN, FakeHub, cert_pem, csr_pem, fp, make_cert, make_csr, make_key, module_args)

HUB = "https://hub.test"
BASE = {"hub_url": HUB, "token": TOKEN}


def run(mod, args, hub, capsys, monkeypatch):
    monkeypatch.setattr(utils, "fetch_url", hub)
    monkeypatch.setattr(mod, "fetch_url", hub, raising=False)
    with module_args(dict(BASE, **args)):
        with pytest.raises(SystemExit):
            mod.main()
    out = capsys.readouterr().out
    return json.loads(out)


def issue_routes(cert, ca_id="ca1", chain=b"CHAINPEM\n"):
    f = fp(cert)
    return {
        ("POST", "/certificates"): (201, {"data": {"fingerprint_sha256": f, "serial_number": "1", "valid_until": "2030-01-01T00:00:00Z", "ca_id": ca_id}}),
        ("GET", "/certificates/%s/download" % f): (200, cert_pem(cert)),
        ("GET", "/cas/%s/chain" % ca_id): (200, chain),
    }


@pytest.fixture
def csr_file(tmp_path):
    key = make_key()
    p = tmp_path / "req.csr"
    p.write_text(csr_pem(make_csr(key)))
    return key, str(p)


def test_issue_writes_pem_and_chain_with_mode(csr_file, tmp_path, capsys, monkeypatch):
    key, csr = csr_file
    new = make_cert(key)
    hub = FakeHub(issue_routes(new))
    dest = tmp_path / "out.pem"
    res = run(certificate, {"csr_path": csr, "ca_id": "ca1", "template_id": "t1", "path": str(dest), "mode": "0640"}, hub, capsys, monkeypatch)
    assert res["changed"] and res["action"] == "issued" and res["fingerprint"] == fp(new)
    body = dest.read_bytes()
    assert body.startswith(b"-----BEGIN CERTIFICATE") and body.endswith(b"CHAINPEM\n")
    assert oct(dest.stat().st_mode & 0o777) == "0o640"
    assert hub.calls[0][3]["Authorization"] == "Bearer " + TOKEN


def test_valid_matching_cert_is_unchanged_and_makes_no_write_calls(csr_file, tmp_path, capsys, monkeypatch):
    key, csr = csr_file
    have = make_cert(key, days_left=90)
    dest = tmp_path / "out.pem"
    dest.write_bytes(cert_pem(have))
    hub = FakeHub({("GET", "/certificates/%s" % fp(have)): (200, {"data": {"renewal_status": "active"}})})
    res = run(certificate, {"csr_path": csr, "ca_id": "ca1", "template_id": "t1", "path": str(dest)}, hub, capsys, monkeypatch)
    assert not res["changed"] and res["action"] == "unchanged"
    assert hub.paths("POST") == []


def test_inside_renew_window_renews_via_renew_endpoint(csr_file, tmp_path, capsys, monkeypatch):
    key, csr = csr_file
    have = make_cert(key, days_left=5)
    new = make_cert(key, days_left=90)
    dest = tmp_path / "out.pem"
    dest.write_bytes(cert_pem(have))
    routes = issue_routes(new)
    routes.pop(("POST", "/certificates"))
    routes[("GET", "/certificates/%s" % fp(have))] = (200, {"data": {"renewal_status": "active"}})
    renewed = {"fingerprint_sha256": fp(new), "serial_number": "2", "valid_until": "x", "ca_id": "ca1"}
    routes[("POST", "/certificates/%s/renew" % fp(have))] = (201, {"data": renewed})
    hub = FakeHub(routes)
    res = run(certificate, {"csr_path": csr, "ca_id": "ca1", "template_id": "t1", "path": str(dest), "renew_before_days": 30}, hub, capsys, monkeypatch)
    assert res["action"] == "renewed" and res["fingerprint"] == fp(new)
    assert fp(have) != fp(new) and b"CHAINPEM" in dest.read_bytes()


def test_different_csr_key_issues_instead_of_unchanged(csr_file, tmp_path, capsys, monkeypatch):
    key, csr = csr_file
    other = make_cert(make_key(), days_left=90)
    new = make_cert(key)
    dest = tmp_path / "out.pem"
    dest.write_bytes(cert_pem(other))
    routes = issue_routes(new)
    routes[("GET", "/certificates/%s" % fp(other))] = (200, {"data": {"renewal_status": "active"}})
    res = run(certificate, {"csr_path": csr, "ca_id": "ca1", "template_id": "t1", "path": str(dest)}, FakeHub(routes), capsys, monkeypatch)
    assert res["action"] == "issued"


def test_revoked_at_hub_triggers_reissue(csr_file, tmp_path, capsys, monkeypatch):
    key, csr = csr_file
    have = make_cert(key, days_left=90)
    new = make_cert(key)
    dest = tmp_path / "out.pem"
    dest.write_bytes(cert_pem(have))
    routes = issue_routes(new)
    routes[("GET", "/certificates/%s" % fp(have))] = (200, {"data": {"renewal_status": "revoked"}})
    res = run(certificate, {"csr_path": csr, "ca_id": "ca1", "template_id": "t1", "path": str(dest)}, FakeHub(routes), capsys, monkeypatch)
    assert res["action"] == "issued"


def test_check_mode_reports_change_without_writing(csr_file, tmp_path, capsys, monkeypatch):
    _, csr = csr_file
    hub = FakeHub()
    dest = tmp_path / "out.pem"
    res = run(certificate, {"csr_path": csr, "ca_id": "ca1", "template_id": "t1", "path": str(dest), "_ansible_check_mode": True}, hub, capsys, monkeypatch)
    assert res["changed"] and not dest.exists() and hub.paths("POST") == []


def test_pending_approval_fails_with_id(csr_file, tmp_path, capsys, monkeypatch):
    _, csr = csr_file
    hub = FakeHub({("POST", "/certificates"): (202, {"data": {"approval_id": "ap-9"}})})
    res = run(certificate, {"csr_path": csr, "ca_id": "ca1", "template_id": "t1", "path": str(tmp_path / "o.pem")}, hub, capsys, monkeypatch)
    assert res["failed"] and "ap-9" in res["msg"]


def test_hub_error_message_is_surfaced_and_token_not_leaked(csr_file, tmp_path, capsys, monkeypatch):
    _, csr = csr_file
    refusal = {"error": "forbidden", "message": "team policy refuses this CA", "error_code": "team_policy_ca_not_allowed"}
    hub = FakeHub({("POST", "/certificates"): (403, refusal)})
    res = run(certificate, {"csr_path": csr, "ca_id": "ca1", "template_id": "t1", "path": str(tmp_path / "o.pem")}, hub, capsys, monkeypatch)
    assert res["failed"] and "team policy refuses this CA" in res["msg"] and "team_policy_ca_not_allowed" in res["msg"]
    assert "HTTP 403" in res["msg"]
    assert TOKEN not in json.dumps(res)


def test_revoke_by_fingerprint_reports_scope(capsys, monkeypatch):
    routes = {
        ("GET", "/certificates/abc"): (200, {"data": {"renewal_status": "active", "serial_number": "7"}}),
        ("POST", "/certificates/abc/revoke"): (200, {"data": {"revocation_scope": "inventory_only"}}),
    }
    hub = FakeHub(routes)
    res = run(certificate, {"state": "absent", "fingerprint": "ABC", "reason": "superseded", "scope": "inventory_only"}, hub, capsys, monkeypatch)
    assert res["changed"] and res["revocation_scope"] == "inventory_only"
    body = [c for c in hub.calls if c[0] == "POST"][0][2]
    assert body["reason_code"] == 4 and body["scope"] == "inventory_only"


def test_revoke_by_path_and_already_revoked_is_noop(csr_file, tmp_path, capsys, monkeypatch):
    key, _ = csr_file
    have = make_cert(key)
    dest = tmp_path / "c.pem"
    dest.write_bytes(cert_pem(have))
    hub = FakeHub({("GET", "/certificates/%s" % fp(have)): (200, {"data": {"renewal_status": "revoked"}})})
    res = run(certificate, {"state": "absent", "path": str(dest)}, hub, capsys, monkeypatch)
    assert not res["changed"] and hub.paths("POST") == []


def test_revoke_unknown_certificate_is_noop(capsys, monkeypatch):
    res = run(certificate, {"state": "absent", "fingerprint": "zz"}, FakeHub(), capsys, monkeypatch)
    assert not res["changed"]


def test_revoke_check_mode(capsys, monkeypatch):
    hub = FakeHub({("GET", "/certificates/abc"): (200, {"data": {"renewal_status": "active"}})})
    res = run(certificate, {"state": "absent", "fingerprint": "abc", "_ansible_check_mode": True}, hub, capsys, monkeypatch)
    assert res["changed"] and hub.paths("POST") == []


def test_token_is_required(capsys, monkeypatch):
    monkeypatch.delenv("KRYPTKEEPER_TOKEN", raising=False)
    with module_args({"hub_url": HUB, "fingerprint": "a"}):
        with pytest.raises(SystemExit):
            certificate_info.main()
    assert "token is required" in json.loads(capsys.readouterr().out)["msg"]


def test_token_from_env(monkeypatch, capsys):
    monkeypatch.setenv("KRYPTKEEPER_TOKEN", "from-env")
    hub = FakeHub({("GET", "/certificates/abc"): (200, {"data": {"fingerprint_sha256": "abc"}})})
    monkeypatch.setattr(utils, "fetch_url", hub)
    with module_args({"hub_url": HUB, "fingerprint": "abc"}):
        with pytest.raises(SystemExit):
            certificate_info.main()
    assert hub.calls[0][3]["Authorization"] == "Bearer from-env"


def test_unreachable_hub(capsys, monkeypatch):
    def down(module, url, **kw):
        return None, {"status": -1, "msg": "connection refused"}
    monkeypatch.setattr(utils, "fetch_url", down)
    with module_args(dict(BASE, fingerprint="a")):
        with pytest.raises(SystemExit):
            certificate_info.main()
    assert "cannot reach hub" in json.loads(capsys.readouterr().out)["msg"]


def test_info_by_fingerprint_unknown_is_empty(capsys, monkeypatch):
    res = run(certificate_info, {"fingerprint": "nope"}, FakeHub(), capsys, monkeypatch)
    assert res["certificates"] == [] and not res["changed"]


def test_info_serial_walks_pages_and_filters(capsys, monkeypatch):
    pages = iter([
        (200, {"data": [{"serial_number": "1"}, {"serial_number": "2"}], "meta": {"next_cursor": "c2"}}),
        (200, {"data": [{"serial_number": "3", "common_name": "hit"}], "meta": {"next_cursor": None}}),
    ])
    hub = FakeHub({("GET", "/certificates"): lambda: next(pages)})
    res = run(certificate_info, {"serial": "3"}, hub, capsys, monkeypatch)
    assert [c["common_name"] for c in res["certificates"]] == ["hit"]
    assert len(hub.calls) == 2


def make_archive():
    buf = io.BytesIO()
    payload = b"#!/bin/sh\necho agent\n"
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("kryptkeeper-agent")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def test_agent_mints_token_without_install(capsys, monkeypatch):
    hub = FakeHub({("POST", "/agent/enrollment-tokens"): (201, {"data": {"id": "aet-1", "token": "kkenr_x", "expires_at": "t"}})})
    res = run(agent, {"label": "farm", "ttl_seconds": 600}, hub, capsys, monkeypatch)
    assert res["changed"] and res["token_id"] == "aet-1" and res["enrollment_token"] == "kkenr_x"
    assert hub.calls[0][2] == {"label": "farm", "ttl_seconds": 600}


def test_agent_sha_mismatch_fails_before_any_token_is_minted(monkeypatch, capsys):
    archive = make_archive()
    hub = FakeHub({("POST", "/agent/enrollment-tokens"): (201, {"data": {"id": "x", "token": "t"}})})

    def fetch(module, url, **kw):
        if url.startswith("https://dl.test/"):
            return io.BytesIO(archive), {"status": 200}
        return hub(module, url, **kw)

    monkeypatch.setattr(agent.os, "geteuid", lambda: 0)
    monkeypatch.setattr(agent.platform, "system", lambda: "Linux")
    monkeypatch.setattr(agent.os.path, "exists", lambda p: False)
    monkeypatch.setattr(utils, "fetch_url", fetch)
    monkeypatch.setattr(agent, "fetch_url", fetch)
    with module_args(dict(BASE, install=True, package_url="https://dl.test/a.tar.gz", package_sha256="0" * 64)):
        with pytest.raises(SystemExit):
            agent.main()
    res = json.loads(capsys.readouterr().out)
    assert res["failed"] and "sha256 mismatch" in res["msg"] and "Nothing was extracted" in res["msg"]
    assert hub.calls == []


def test_agent_verified_archive_yields_binary(monkeypatch):
    archive = make_archive()
    monkeypatch.setattr(agent, "fetch_url", lambda m, u, **kw: (io.BytesIO(archive), {"status": 200}))

    class M(object):
        params = {"timeout": 1, "ca_path": None}

        def fail_json(self, **kw):
            raise AssertionError(kw)

    data = agent.download_verified(M(), "https://dl.test/a", hashlib.sha256(archive).hexdigest().upper())
    assert agent.extract_agent_binary(M(), data).startswith(b"#!/bin/sh")


def test_agent_check_mode(monkeypatch, capsys):
    hub = FakeHub()
    res = run(agent, {"_ansible_check_mode": True}, hub, capsys, monkeypatch)
    assert res["changed"] and hub.calls == []
