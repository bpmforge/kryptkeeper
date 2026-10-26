# -*- coding: utf-8 -*-
# Copyright 2026 Kryptkeeper Authors
# SPDX-License-Identifier: Apache-2.0
"""Small Kryptkeeper hub API client shared by the kryptkeeper.pki modules."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json

from ansible.module_utils.basic import env_fallback
from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.urls import fetch_url
from ansible.module_utils.six.moves.urllib.parse import quote, urlencode

API_PREFIX = "/api/v1"


def connection_argument_spec():
    """Argument spec fragment every module merges in."""
    return dict(
        hub_url=dict(type="str", required=True, fallback=(env_fallback, ["KRYPTKEEPER_URL"])),
        token=dict(type="str", no_log=True, fallback=(env_fallback, ["KRYPTKEEPER_TOKEN"])),
        ca_path=dict(type="path", fallback=(env_fallback, ["KRYPTKEEPER_CA_BUNDLE"])),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
    )


class KryptkeeperError(Exception):
    def __init__(self, message, status=None):
        super(KryptkeeperError, self).__init__(message)
        self.status = status


class KryptkeeperClient(object):
    def __init__(self, module):
        self.module = module
        self.base = module.params["hub_url"].rstrip("/") + API_PREFIX
        self._token = module.params.get("token")
        if not self._token:
            module.fail_json(msg="a hub API token is required: set the token option or KRYPTKEEPER_TOKEN")
        self.ca_path = module.params.get("ca_path")
        self.timeout = module.params["timeout"]

    def request(self, method, path, body=None, query=None, raw=False, ok_statuses=()):
        """Call the hub. Returns (status, parsed JSON | bytes | None).

        Statuses below 400 and any in ok_statuses are returned; other statuses
        raise KryptkeeperError carrying the hub's own message. The bearer token
        is only ever placed in the request header.
        """
        url = self.base + path
        if query:
            url += "?" + urlencode(query)
        headers = {
            "Authorization": "Bearer " + self._token,
            "Accept": "application/octet-stream" if raw else "application/json",
        }
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body)
        resp, info = fetch_url(
            self.module, url, data=data, headers=headers, method=method,
            timeout=self.timeout, ca_path=self.ca_path,
        )
        status = info.get("status", -1)
        payload = None
        if resp is not None:
            payload = resp.read()
        elif info.get("body") is not None:
            payload = info["body"]
        if status == -1:
            raise KryptkeeperError("cannot reach hub at %s: %s" % (self.module.params["hub_url"], info.get("msg")))
        if status >= 400 and status not in ok_statuses:
            raise KryptkeeperError(self._describe(method, path, status, payload), status=status)
        if raw:
            return status, payload
        if not payload:
            return status, None
        try:
            return status, json.loads(to_native(payload))
        except ValueError:
            raise KryptkeeperError("hub returned a non-JSON body for %s %s (HTTP %s)" % (method, path, status), status=status)

    @staticmethod
    def _describe(method, path, status, payload):
        detail = ""
        if payload:
            text = to_native(payload, errors="replace")
            try:
                doc = json.loads(text)
                parts = []
                if isinstance(doc, dict):
                    parts = [str(doc[k]) for k in ("message", "error") if doc.get(k)]
                    if doc.get("error_code"):
                        parts.append("(%s)" % doc["error_code"])
                detail = " ".join(parts) or text[:300]
            except ValueError:
                detail = text[:300]
        return "hub refused %s %s: HTTP %s %s" % (method, path, status, detail)

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body=body if body is not None else {}, **kw)

    def get_certificate(self, fingerprint):
        """Return the certificate item, or None when the hub has no such certificate."""
        status, doc = self.get("/certificates/" + quote(fingerprint, safe=""), ok_statuses=(404,))
        if status == 404:
            return None
        return doc.get("data", doc)

    def list_certificates(self, query, limit=None):
        """Walk the cursor pagination of GET /certificates."""
        items = []
        params = dict(query)
        params["limit"] = 200
        while True:
            _, doc = self.get("/certificates", query=params)
            items.extend(doc.get("data") or [])
            nxt = (doc.get("meta") or {}).get("next_cursor") or doc.get("next_cursor")
            if limit and len(items) >= limit:
                return items[:limit]
            if not nxt:
                return items
            params["cursor"] = nxt
