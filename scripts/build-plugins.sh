#!/usr/bin/env bash
# Build every delivery plugin under plugins/ into dist/plugins/<name>/:
# plugin.wasm plus manifest.json with artifact.sha256 pinned to it. These
# are what an operator installs at /api/v1/delivery-plugins (W20-22).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/dist/plugins"
mkdir -p "$OUT"
for dir in "$ROOT"/plugins/*/; do
  name="$(basename "$dir")"
  mkdir -p "$OUT/$name"
  (cd "$dir" && GOOS=wasip1 GOARCH=wasm go build -trimpath -buildmode=c-shared -o "$OUT/$name/plugin.wasm" .)
  python3 - "$dir/manifest.json" "$OUT/$name" <<'PY'
import hashlib, json, sys
src, out = sys.argv[1], sys.argv[2]
m = json.load(open(src))
m["artifact"]["sha256"] = hashlib.sha256(open(f"{out}/plugin.wasm", "rb").read()).hexdigest()
json.dump(m, open(f"{out}/manifest.json", "w"), indent=2)
print(f"{m['id']} {m['version']} sha256={m['artifact']['sha256']}")
PY
done
