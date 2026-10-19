#!/usr/bin/env python3
"""W32-18 STAND-IN for the ServiceNow Table API and the Jira Cloud REST v3 API.

This is NOT ServiceNow and NOT Jira. It implements only the calls the
Kryptkeeper connectors make (internal/notifications/itsm/{servicenow,jira}),
with the response shapes documented for those APIs, so the harness can drive a
real hub end to end without a ServiceNow instance or a Jira Cloud site. Every
result obtained against it is labelled "stand-in" and proves the hub's side of
the conversation only.

One process, one JSON state file, two route families:

  ServiceNow  POST/GET/PATCH /api/now/table/{incident,change_request}[/{sys_id}]
              (incident.approval / change_request.approval start at "not requested")
              GET /api/now/table/sysapproval_approver   (rows added by /_ctl/approve)
              GET /api/now/table/cmdb_ci
  Jira        POST /rest/api/3/issue            GET /rest/api/3/issue/{key}
              GET|POST /rest/api/3/issue/{key}/transitions
              POST /rest/api/3/issue/{key}/comment
              GET /rest/api/3/search/jql

Control endpoints (no auth, fixture only):
  POST /_ctl/approve?system=snow|jira&id=<sys_id|KEY>[&approver=<accountId|sys_user sys_id>]
  POST /_ctl/outage?on=1|0          API routes answer 503 while on
  POST /_ctl/cmdb                   body: JSON list of CI rows (replaces the table)
  GET  /_ctl/state                  counts and full records
  GET  /_ctl/health

F5 BIG-IP iControl REST (install_mode f5), only what internal/agentinstall/f5.go calls:
  POST /mgmt/shared/file-transfer/uploads/{file}   POST /mgmt/tm/sys/crypto/{cert,key}
  GET|PATCH /mgmt/tm/ltm/profile/client-ssl/{name}
After the profile is re-pointed at an uploaded cert+key, a TLS listener on
--f5-verify-port serves that certificate, which is what the hub's verify-after-
push dials. /_ctl/state reports f5_served_fingerprint.

The server speaks HTTPS: the connectors accept plain http only for loopback
and the hub's egress guard refuses loopback, so the only reachable address is
a private LAN IP over TLS (run.sh points SSL_CERT_FILE at this cert).
"""
import argparse
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()
STATE = {"snow": {"incidents": {}, "changes": {}, "approvers": [], "cmdb_ci": [], "seq": 0}, "jira": {"issues": {}, "seq": 0},
         "outage": False, "auth_failures": 0, "requests": 0}
# F5 stand-in state is in memory only (the verify listener cannot be restored from a file).
F5 = {"uploads": {}, "certs": {}, "keys": {}, "profile": {"cert": "/Common/default.crt", "key": "/Common/default.key"}, "served_fp": ""}
VERIFY = {"ctx": None}
STATE_FILE = None
CREDS = {"snow": None, "jira": None, "f5": None}  # (user, password) when enforced

DONE_STATUS = {"name": "Done", "statusCategory": {"key": "done"}}
TODO_STATUS = {"name": "To Do", "statusCategory": {"key": "new"}}


def save():
    if STATE_FILE:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(STATE, f)
        os.replace(tmp, STATE_FILE)


def project(rec, fields):
    """sysparm_fields projection: only the named fields, as the Table API does."""
    if not fields:
        return rec
    return {k: rec.get(k, "") for k in fields.split(",")}


TABLES = {"incident": ("incidents", "INC"), "change_request": ("changes", "CHG")}


def pem_first_fp(pem):
    m = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(m.group(0).decode())).hexdigest() if m else ""


def verify_listener(bind, port):
    """TLS-handshake-only listener standing in for the F5 virtual server."""
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))
    sock.listen(16)
    while True:
        conn, _ = sock.accept()
        conn.settimeout(5)
        try:
            ctx = VERIFY["ctx"]
            if ctx is not None:
                ctx.wrap_socket(conn, server_side=True).close()
            else:
                conn.close()
        except Exception:
            conn.close()


def jira_ts():
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03d+0000" % int((t % 1) * 1000)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # keep run output quiet
        pass

    # ---- plumbing ---------------------------------------------------------
    def send(self, code, obj=None):
        body = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def raw(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def body(self):
        raw = self.raw()
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            return {}

    def basic(self):
        h = self.headers.get("Authorization", "")
        if not h.startswith("Basic "):
            return None
        try:
            u, _, p = base64.b64decode(h[6:]).decode().partition(":")
        except Exception:
            return None
        return u, p

    def authorized(self, system):
        got = self.basic()
        want = CREDS[system]
        if got is None or (want is not None and got != want):
            STATE["auth_failures"] += 1
            self.send(401, {"error": {"message": "User Not Authenticated"}} if system == "snow"
                      else {"errorMessages": ["Client must be authenticated"]})
            return False
        return True

    def route(self):
        u = urllib.parse.urlparse(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        with LOCK:
            STATE["requests"] += 1
            self.dispatch(u.path, q)
            save()

    def dispatch(self, path, q):
        if path.startswith("/_ctl/"):
            return self.ctl(path, q)
        if STATE["outage"]:
            return self.send(503, {"error": {"message": "stand-in outage"}})
        if path.startswith("/api/now/table/"):
            if self.authorized("snow"):
                self.snow(path, q)
            return
        if path.startswith("/rest/api/3/"):
            if self.authorized("jira"):
                self.jira(path, q)
            return
        if path.startswith("/mgmt/"):
            if self.authorized("f5"):
                self.f5(path)
            return
        self.send(404, {"error": "not found"})

    do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = route

    # ---- control ----------------------------------------------------------
    def ctl(self, path, q):
        if path == "/_ctl/health":
            return self.send(200, {"ok": True, "stand_in": True})
        if path == "/_ctl/state":
            s = STATE
            return self.send(200, {
                "stand_in": True, "outage": s["outage"], "requests": s["requests"], "auth_failures": s["auth_failures"],
                "incident_count": len(s["snow"]["incidents"]), "change_count": len(s["snow"]["changes"]),
                "issue_count": len(s["jira"]["issues"]), "cmdb_ci_count": len(s["snow"]["cmdb_ci"]),
                "incidents": s["snow"]["incidents"], "changes": s["snow"]["changes"], "issues": s["jira"]["issues"],
                "approver_rows": s["snow"]["approvers"], "f5_served_fingerprint": F5["served_fp"]})
        if path == "/_ctl/outage":
            STATE["outage"] = q.get("on") == "1"
            save()
            return self.send(200, {"outage": STATE["outage"]})
        if path == "/_ctl/cmdb":
            rows = self.body()
            STATE["snow"]["cmdb_ci"] = rows if isinstance(rows, list) else []
            save()
            return self.send(200, {"cmdb_ci_count": len(STATE["snow"]["cmdb_ci"])})
        if path == "/_ctl/approve":
            system, ident = q.get("system"), q.get("id", "")
            if system == "jira":
                iss = STATE["jira"]["issues"].get(ident)
                if not iss:
                    return self.send(404, {"error": "no such issue"})
                who = q.get("approver", "acct-approver")
                iss["status"] = {"name": "Approved", "statusCategory": {"key": "indeterminate"}}
                iss["history"].append({"created": jira_ts(), "author": {"accountId": who},
                                       "items": [{"field": "status", "fromString": "To Do", "toString": "Approved"}]})
            elif system == "snow":
                inc = STATE["snow"]["incidents"].get(ident) or STATE["snow"]["changes"].get(ident)
                if not inc:
                    return self.send(404, {"error": "no such incident or change_request"})
                inc["approval"] = "approved"
                STATE["snow"]["approvers"].append({"sysapproval": ident, "state": "approved", "approver": q.get("approver", "snow-approver"),
                                                   "sys_updated_on": jira_ts()})
            else:
                return self.send(400, {"error": "system must be snow or jira"})
            save()
            return self.send(200, {"approved": ident})
        self.send(404, {"error": "unknown control"})

    # ---- ServiceNow -------------------------------------------------------
    def snow(self, path, q):
        s = STATE["snow"]
        m = re.fullmatch(r"/api/now/table/(incident|change_request)(?:/([0-9a-f]+))?", path)
        if m:
            bucket, prefix = TABLES[m.group(1)]
            rows, sys_id = s[bucket], m.group(2)
            if self.command == "POST" and not sys_id:
                b = self.body()
                s["seq"] += 1
                sid = uuid.uuid4().hex
                rows[sid] = dict(b, sys_id=sid, number="%s%07d" % (prefix, 1000 + s["seq"]), state="1", approval="not requested",
                                 sys_class_name=m.group(1))
                return self.send(201, {"result": {"sys_id": sid, "number": rows[sid]["number"], "state": "1"}})
            if self.command == "GET" and not sys_id:
                mm = re.fullmatch(r"correlation_id=(.*)", q.get("sysparm_query", ""))
                found = [i for i in rows.values() if mm and i.get("correlation_id") == mm.group(1)]
                found = found[: int(q.get("sysparm_limit", "10"))]
                return self.send(200, {"result": [project(i, q.get("sysparm_fields")) for i in found]})
            inc = rows.get(sys_id or "")
            if sys_id and inc is None:
                return self.send(404, {"error": {"message": "No Record found"}, "status": "failure"})
            if self.command == "GET":
                return self.send(200, {"result": project(inc, q.get("sysparm_fields"))})
            if self.command == "PATCH":
                inc.update(self.body())
                return self.send(200, {"result": {"sys_id": sys_id, "state": inc["state"]}})
        if path == "/api/now/table/sysapproval_approver" and self.command == "GET":
            mm = re.fullmatch(r"sysapproval=([0-9a-f]+)\^state=approved\^ORDERBYDESCsys_updated_on", q.get("sysparm_query", ""))
            rows = [r for r in reversed(s["approvers"]) if mm and r["sysapproval"] == mm.group(1) and r["state"] == "approved"]
            # a reference field comes back as {link, value}
            out = [{"approver": {"link": "https://stand-in/api/now/table/sys_user/" + r["approver"], "value": r["approver"]}} for r in rows]
            return self.send(200, {"result": out[: int(q.get("sysparm_limit", "10"))]})
        if path == "/api/now/table/cmdb_ci" and self.command == "GET":
            mm = re.fullmatch(r"fqdn=(.*?)\^ORname=(.*)", q.get("sysparm_query", ""))
            host = mm.group(1) if mm else None
            for ci in s["cmdb_ci"]:
                if host and host in (ci.get("fqdn"), ci.get("name")):
                    return self.send(200, {"result": [{"owned_by.email": ci.get("owned_by", ""),
                                                      "support_group.name": ci.get("support_group", "")}]})
            return self.send(200, {"result": []})
        self.send(404, {"error": {"message": "not found"}})

    # ---- F5 iControl REST (only what agentinstall/f5.go calls) -------------
    def f5(self, path):
        m = re.fullmatch(r"/mgmt/shared/file-transfer/uploads/([A-Za-z0-9._-]+)", path)
        if m and self.command == "POST":
            F5["uploads"][m.group(1)] = self.raw()
            return self.send(200, {"remainingByteCount": 0})
        m = re.fullmatch(r"/mgmt/tm/sys/crypto/(cert|key)", path)
        if m and self.command == "POST":
            b = self.body()
            f = os.path.basename(b.get("fromLocalFile", ""))
            if f not in F5["uploads"] or not b.get("name"):
                return self.send(400, {"message": "no such uploaded file"})
            F5["certs" if m.group(1) == "cert" else "keys"][b["name"]] = F5["uploads"][f]
            return self.send(200, {"name": b["name"]})
        m = re.fullmatch(r"/mgmt/tm/ltm/profile/client-ssl/([A-Za-z0-9._-]+)", path)
        if m and self.command == "GET":
            return self.send(200, dict(F5["profile"], name=m.group(1)))
        if m and self.command == "PATCH":
            b = self.body()
            cert, key = b.get("cert", ""), b.get("key", "")
            if cert in F5["certs"] and key in F5["keys"]:
                d = tempfile.mkdtemp(prefix="f5-", dir=os.path.dirname(os.path.abspath(STATE_FILE)))
                cf, kf = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
                with open(cf, "wb") as f:
                    f.write(F5["certs"][cert])
                with open(kf, "wb") as f:
                    f.write(F5["keys"][key])
                os.chmod(kf, 0o600)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                try:
                    ctx.load_cert_chain(cf, kf)
                except ssl.SSLError as e:
                    return self.send(400, {"message": "cert/key do not load: %s" % e.reason})
                VERIFY["ctx"], F5["served_fp"] = ctx, pem_first_fp(F5["certs"][cert])
            F5["profile"] = {"cert": cert, "key": key}
            return self.send(200, dict(F5["profile"], name=m.group(1)))
        self.send(404, {"message": "not found"})

    # ---- Jira -------------------------------------------------------------
    def jira(self, path, q):
        j = STATE["jira"]
        if path == "/rest/api/3/issue" and self.command == "POST":
            f = self.body().get("fields", {})
            if not f.get("summary") or not f.get("project", {}).get("key"):
                return self.send(400, {"errorMessages": [], "errors": {"summary": "You must specify a summary of the issue."}})
            j["seq"] += 1
            key = "%s-%d" % (f["project"]["key"], j["seq"])
            j["issues"][key] = {"key": key, "id": str(10000 + j["seq"]), "summary": f["summary"], "description": f.get("description"),
                                "labels": f.get("labels", []), "status": dict(TODO_STATUS), "history": [], "comments": []}
            return self.send(201, {"id": j["issues"][key]["id"], "key": key, "self": "/rest/api/3/issue/" + key})
        if path == "/rest/api/3/search/jql" and self.command == "GET":
            mm = re.search(r'labels\s*=\s*"([^"]+)"', q.get("jql", ""))
            want = [x for x in q.get("fields", "key").split(",") if x and x != "key"]
            rows = [{"key": i["key"], "fields": {k: i["status"] if k == "status" else i.get(k) for k in want}}
                    for i in j["issues"].values() if mm and mm.group(1) in i["labels"]]
            return self.send(200, {"issues": rows[: int(q.get("maxResults", "50"))]})
        m = re.fullmatch(r"/rest/api/3/issue/([A-Z][A-Z0-9_]*-\d+)(/transitions|/comment)?", path)
        if m:
            key, sub = m.group(1), m.group(2)
            iss = j["issues"].get(key)
            if iss is None:
                return self.send(404, {"errorMessages": ["Issue does not exist or you do not have permission to see it."], "errors": {}})
            if sub is None and self.command == "GET":
                out = {"key": key, "fields": {"status": iss["status"]}}
                if "changelog" in q.get("expand", ""):
                    out["changelog"] = {"histories": iss["history"]}
                return self.send(200, out)
            if sub == "/comment" and self.command == "GET":
                return self.send(200, {"comments": [{"body": b} for b in iss["comments"]]})
            if sub == "/comment" and self.command == "POST":
                iss["comments"].append(self.body().get("body"))
                return self.send(201, {"id": str(len(iss["comments"]))})
            if sub == "/transitions" and self.command == "GET":
                return self.send(200, {"transitions": [{"id": "31", "name": "Done", "to": DONE_STATUS}]})
            if sub == "/transitions" and self.command == "POST":
                if self.body().get("transition", {}).get("id") != "31":
                    return self.send(400, {"errorMessages": ["Invalid transition"], "errors": {}})
                iss["status"] = dict(DONE_STATUS)
                return self.send(204)
        self.send(404, {"errorMessages": ["not found"], "errors": {}})


def main():
    global STATE_FILE
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bind", required=True, help="private (RFC1918) address; the hub egress guard refuses loopback")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--state", required=True, help="JSON state file")
    ap.add_argument("--f5-verify-port", type=int, default=0, help="TLS listener the hub dials after an f5 push (0 = off)")
    ap.add_argument("--snow-user")
    ap.add_argument("--snow-pass")
    ap.add_argument("--jira-user")
    ap.add_argument("--jira-pass")
    a = ap.parse_args()
    STATE_FILE = a.state
    if a.snow_user:
        CREDS["snow"] = (a.snow_user, a.snow_pass or "")
    if a.jira_user:
        CREDS["jira"] = (a.jira_user, a.jira_pass or "")
    save()
    if a.f5_verify_port:
        threading.Thread(target=verify_listener, args=(a.bind, a.f5_verify_port), daemon=True).start()
    srv = ThreadingHTTPServer((a.bind, a.port), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print("stand-in ITSM on https://%s:%d (NOT a real ServiceNow or Jira)" % (a.bind, a.port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
