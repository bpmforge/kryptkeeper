#!/usr/bin/env python3
"""Strict CEF 0 parser fixture (W32-09). Reads lines on stdin (or file args).

Grammar: CEF:0|vendor|product|version|signatureId|name|severity|extension
Header fields are '|'-delimited; '\\|' and '\\\\' are the only legal header
escapes. Severity must be an integer 0-10. Extension is space-separated
key=value pairs; values may contain spaces (they run until the next ` key=`),
and '\\=', '\\\\', '\\n', '\\r' are the legal extension escapes. A bare '=' or
'\\' that is not a legal escape is an error. Exit non-zero on ANY error;
prints `CEF parse errors: N` and `CEF lines ok: M`.
"""
import re
import sys

KEY = r"[A-Za-z0-9_.\[\]]+"


def split_header(line):
    fields, cur, i = [], [], 0
    while i < len(line) and len(fields) < 7:
        c = line[i]
        if c == "\\":
            if i + 1 >= len(line) or line[i + 1] not in "|\\":
                raise ValueError("illegal header escape at col %d" % i)
            cur.append(line[i + 1])
            i += 2
            continue
        if c == "|":
            fields.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    if len(fields) != 7:
        raise ValueError("expected 7 header pipes, got %d" % len(fields))
    return fields, line[i:]


def parse_ext(ext):
    pairs = {}
    if ext == "":
        return pairs
    # Keys start at beginning or after a space, followed by an unescaped '='.
    starts = [m for m in re.finditer(r"(?:(?<=^)|(?<= ))(" + KEY + r")=", ext)]
    if not starts or starts[0].start() != 0:
        raise ValueError("extension does not begin with key=value")
    for n, m in enumerate(starts):
        end = starts[n + 1].start() - 1 if n + 1 < len(starts) else len(ext)
        raw = ext[m.end():end]
        out, i = [], 0
        while i < len(raw):
            c = raw[i]
            if c == "\\":
                if i + 1 >= len(raw) or raw[i + 1] not in "=\\nr":
                    raise ValueError("illegal extension escape in %s" % m.group(1))
                out.append({"n": "\n", "r": "\r"}.get(raw[i + 1], raw[i + 1]))
                i += 2
                continue
            if c == "=":
                raise ValueError("unescaped '=' in value of %s" % m.group(1))
            out.append(c)
            i += 1
        pairs[m.group(1)] = "".join(out)
    return pairs


def parse(line):
    if not line.startswith("CEF:0|"):
        raise ValueError("missing CEF:0 prefix")
    fields, ext = split_header(line[len("CEF:"):])
    ver, vendor, product, devver, sig, name, sev = fields
    if ver != "0":
        raise ValueError("CEF version %r" % ver)
    for label, v in (("vendor", vendor), ("product", product), ("signatureId", sig), ("name", name)):
        if not v:
            raise ValueError("empty %s" % label)
    if not re.fullmatch(r"(10|[0-9])", sev):
        raise ValueError("severity %r not an integer 0-10" % sev)
    pairs = parse_ext(ext)
    for k in list(pairs):
        if re.fullmatch(r"cs[1-6]Label", k):
            if k[:-5] not in pairs:
                raise ValueError("%s without matching %s" % (k, k[:-5]))
        if re.fullmatch(r"cs[1-6]", k) and k + "Label" not in pairs:
            raise ValueError("%s without required %sLabel" % (k, k))
    if "rt" in pairs and not pairs["rt"].isdigit():
        raise ValueError("rt not epoch millis: %r" % pairs["rt"])
    return fields, pairs


def main():
    lines = []
    if len(sys.argv) > 1:
        for p in sys.argv[1:]:
            lines += open(p).read().splitlines()
    else:
        lines = sys.stdin.read().splitlines()
    errs = ok = 0
    for n, l in enumerate(x for x in lines if x.strip()):
        try:
            parse(l)
            ok += 1
        except ValueError as e:
            errs += 1
            print("line %d: %s: %s" % (n + 1, e, l), file=sys.stderr)
    print("CEF lines ok: %d" % ok)
    print("CEF parse errors: %d" % errs)
    return 1 if errs or ok == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
