#!/usr/bin/env python3
"""W30-20 tripwire sink. Runs inside the egress pod's shared netns.

Every hostname the hub or agent looks up (DNS :53), presents as SNI (TCP :443)
or sends as a Host header (TCP :80) is appended to /out/observed.jsonl. All
names resolve to loopback, so nothing can leave the pod.
"""
import json, os, socket, socketserver, ssl, struct, subprocess, threading, time

OUT = "/out/observed.jsonl"
LOCK = threading.Lock()


def record(kind, host):
    if not host:
        return
    with LOCK, open(OUT, "a") as fh:
        fh.write(json.dumps({"t": time.time(), "kind": kind, "host": host}) + "\n")


def parse_qname(msg):
    labels, i = [], 12
    while i < len(msg) and msg[i] != 0:
        n = msg[i]
        labels.append(msg[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += n + 1
    return ".".join(labels), i + 1


def dns_answer(msg):
    if len(msg) < 17:
        return None
    qname, end = parse_qname(msg)
    qtype = struct.unpack("!H", msg[end:end + 2])[0]
    record("dns", qname)
    question = msg[12:end + 4]
    head = msg[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0)
    if qtype == 1:
        rdata = socket.inet_aton("127.0.0.1")
    elif qtype == 28:
        rdata = socket.inet_pton(socket.AF_INET6, "::1")
    else:  # empty NOERROR for every other type
        return head + question
    head = msg[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    rr = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 30, len(rdata)) + rdata
    return head + question + rr


class UDPDNS(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        resp = dns_answer(data)
        if resp:
            sock.sendto(resp, self.client_address)


class TCPDNS(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            raw = self.rfile.read(2)
            if len(raw) < 2:
                return
            msg = self.rfile.read(struct.unpack("!H", raw)[0])
            resp = dns_answer(msg)
            if not resp:
                return
            self.wfile.write(struct.pack("!H", len(resp)) + resp)


class HTTP80(socketserver.StreamRequestHandler):
    def handle(self):
        host = None
        for _ in range(64):
            line = self.rfile.readline(4096)
            if line in (b"", b"\r\n", b"\n"):
                break
            if line.lower().startswith(b"host:"):
                host = line.split(b":", 1)[1].strip().decode("ascii", "replace")
        if host:
            record("host", host.split(":")[0])
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


def tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/tmp/sink.crt", "/tmp/sink.key")

    def sni(_sock, name, _ctx):
        record("sni", name)

    ctx.sni_callback = sni
    return ctx


class TLS443(socketserver.BaseRequestHandler):
    ctx = None

    def handle(self):
        try:
            with TLS443.ctx.wrap_socket(self.request, server_side=True) as s:
                s.recv(1)
        except (ssl.SSLError, OSError):
            pass  # the client rejecting the throwaway cert is expected; SNI is already logged


class Threaded(socketserver.ThreadingMixIn):
    daemon_threads = True
    allow_reuse_address = True


class TUDP(Threaded, socketserver.UDPServer): pass
class TTCP(Threaded, socketserver.TCPServer): pass


def main():
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-keyout", "/tmp/sink.key", "-out", "/tmp/sink.crt", "-days", "1", "-nodes",
                    "-subj", "/CN=kk-egress-sink"], check=True, capture_output=True)
    TLS443.ctx = tls_context()
    servers = [("127.0.0.1", 53, TUDP, UDPDNS), ("127.0.0.1", 53, TTCP, TCPDNS),
               ("127.0.0.1", 80, TTCP, HTTP80), ("127.0.0.1", 443, TTCP, TLS443)]
    for host, port, srv, handler in servers:
        threading.Thread(target=srv((host, port), handler).serve_forever, daemon=True).start()
    open("/out/sink.ready", "w").close()
    threading.Event().wait()


main()
