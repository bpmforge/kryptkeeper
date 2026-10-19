#!/usr/bin/env bash
# D-210: flow-style `{ description: Text, with, commas }` parses as extra keys,
# which openapi-generator rejects. Quote any unquoted flow description that
# contains a comma. Idempotent. usage: quote-openapi-descriptions.sh <spec.yaml>
set -euo pipefail
f="${1:?usage: $0 <spec.yaml>}"
python3 - "$f" <<'PY'
import re, sys
p = sys.argv[1]
out, n = [], 0
for line in open(p).read().split("\n"):
    m = re.match(r'^(\s+"?\d{3}"?: \{ description: )([^"\'][^}]*?)( \}\s*)$', line)
    if m and "," in m.group(2):
        line = f'{m.group(1)}"{m.group(2)}"{m.group(3)}'
        n += 1
    out.append(line)
open(p, "w").write("\n".join(out))
print(f"[quote-openapi-descriptions] quoted {n}")
PY
