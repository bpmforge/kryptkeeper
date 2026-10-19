#!/usr/bin/env python3
"""Minimal real HTTP receiver for the W19-07 notifications UAT fixture.

Stands in for a generic webhook/Slack-incoming-webhook/SIEM-webhook target:
records every request's method, path, headers and body as one JSON line,
flushed and fsync'd immediately.

Why this instead of a container image (e.g. mendhak/http-https-echo): that
image's Node process block-buffers stdout when it isn't attached to a TTY, so
`podman logs` can lag the actual HTTP response by several requests -- caught
live during this fixture's development (a webhook POST that echoed a 200
immediately had its logged body only surface once *later* slack/siem
requests pushed enough output to flush the buffer). This process fsyncs
after every request, so the fixture's poll loop never races a buffer. It is
still a real, separate HTTP server process -- not an in-process httptest
double -- satisfying the same "real receiver" requirement as a container.
"""
import http.server
import json
import os
import sys
import time

# Positional args stay backward compatible: [log_path] [port]. Optional flags
# (W32-09): --bind <ip> (default 127.0.0.1) and --fail-path <path>, which makes
# requests to that exact path answer 500 (still recorded) so retry/failure
# behaviour can be observed against a real failing receiver.
_args = sys.argv[1:]
BIND = "127.0.0.1"
FAIL_PATH = None
_pos = []
_i = 0
while _i < len(_args):
    if _args[_i] == "--bind":
        BIND = _args[_i + 1]
        _i += 2
    elif _args[_i] == "--fail-path":
        FAIL_PATH = _args[_i + 1]
        _i += 2
    else:
        _pos.append(_args[_i])
        _i += 1
LOG_PATH = _pos[0] if len(_pos) > 0 else "echo-requests.jsonl"
PORT = int(_pos[1]) if len(_pos) > 1 else 9094
# W30-19 callers pass the bind address as a third positional argument.
if len(_pos) > 2:
    BIND = _pos[2]


class Handler(http.server.BaseHTTPRequestHandler):
    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        record = {
            "ts": time.time(),
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body,
        }
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(record) + "\n")
            f.flush()
            os.fsync(f.fileno())
        if FAIL_PATH is not None and self.path.split("?")[0] == FAIL_PATH:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":false}')
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def do_POST(self):
        self._handle()

    def do_GET(self):
        self._handle()

    def log_message(self, fmt, *args):
        pass  # the JSONL file is the record; don't also spam stderr.


if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer((BIND, PORT), Handler)
    server.serve_forever()
