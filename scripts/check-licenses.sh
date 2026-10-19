#!/usr/bin/env bash
set -euo pipefail

# filename: scripts/check-licenses.sh
# W25-21: dependency licence gate for the Go binary (./cmd/...) and the npm UI.
#
#   check         fail on any denied or unclassifiable licence
#   generate      rewrite THIRD_PARTY_LICENSES.md (regenerate on every dependency bump)
#   verify-count  assert the inventory lists every Go and npm dependency, and has not drifted
#
# Denylist: GPL, AGPL, SSPL (any version, case-insensitive). LGPL is allowed; if that
# changes, docs/LICENSING_AND_SUPPORT.md must change with it. An SPDX "A OR B" passes if
# either side passes; "A AND B" fails if either side is denied. Anything go-licenses or the
# lockfile cannot classify fails closed unless it is in ALLOWLIST below.
#
# Options (the overrides exist so the fixture test runs offline):
#   --go-csv FILE       use this go-licenses CSV instead of running go-licenses
#   --go-modules FILE   use this `path@version` list instead of `go list`
#   --npm-lock FILE     lockfile (default ui/package-lock.json)
#   --inventory FILE    inventory to write/verify (default THIRD_PARTY_LICENSES.md)
#   --skip-go | --skip-npm
#   --no-drift          verify-count: skip the regenerate-and-diff step
#
# Exit: 0 ok, 1 policy/count failure, 2 usage, 3 tooling could not resolve a package.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Pinned: go-licenses v2.0.1 resolves this module on Go 1.26+, verified 2026-10-15.
GO_LICENSES="github.com/google/go-licenses/v2@v2.0.1"

# module-or-package <TAB> SPDX <TAB> reason. Applies only to licences the tools report as
# unknown; it never overrides a denied licence. Prefix match on path boundaries.
ALLOWLIST=$'kryptkeeper\tApache-2.0\tfirst-party main module (repo LICENSE)
github.com/bpmforge/kryptkeeper/sdk/delivery-go\tApache-2.0\tfirst-party module in this repo (repo LICENSE)
modernc.org/mathutil\tBSD-3-Clause\tLICENSE is the standard modernc.org text go-licenses may not match; hand-confirmed (docs/THIRD_PARTY_LICENSES.md)'

usage() { sed -n '5,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

CMD="${1:-}"
[[ -n "$CMD" ]] || { usage >&2; exit 2; }
shift || true
case "$CMD" in -h|--help|help) usage; exit 0 ;; check|generate|verify-count) ;; *) usage >&2; exit 2 ;; esac

GO_CSV="" GO_MODULES="" NPM_LOCK="$ROOT_DIR/ui/package-lock.json" INVENTORY="$ROOT_DIR/THIRD_PARTY_LICENSES.md"
SKIP_GO="" SKIP_NPM="" NO_DRIFT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --go-csv) GO_CSV="$2"; shift 2 ;;
    --go-modules) GO_MODULES="$2"; shift 2 ;;
    --npm-lock) NPM_LOCK="$2"; shift 2 ;;
    --inventory) INVENTORY="$2"; shift 2 ;;
    --skip-go) SKIP_GO=1; shift ;;
    --skip-npm) SKIP_NPM=1; shift ;;
    --no-drift) NO_DRIFT=1; shift ;;
    *) echo "[licenses] unknown option: $1" >&2; exit 2 ;;
  esac
done

command -v node >/dev/null || { echo "[licenses] FAIL node is required" >&2; exit 3; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Scope matches what ships: the hub binaries under ./cmd, transitive deps included. The
# dependency graph differs by GOOS (darwin pulls go-isatty and go-strftime, linux does not)
# and releases ship all three, so the inventory is the union; a single-host run would
# disagree with CI depending on where it ran.
SHIPPED_GOOS="linux darwin windows"
go_modules_list() {
  if [[ -n "$GO_MODULES" ]]; then cat "$GO_MODULES"; return; fi
  local goos
  for goos in $SHIPPED_GOOS; do
    (cd "$ROOT_DIR" && GOOS="$goos" go list -deps -f '{{with .Module}}{{.Path}}@{{.Version}}{{end}}' ./cmd/...)
  done | LC_ALL=C sort -u
}

go_csv_into() {
  if [[ -n "$GO_CSV" ]]; then cp "$GO_CSV" "$1"; return; fi
  # go-licenses logs "no license found" for first-party packages and still exits 0, so
  # only a non-zero exit is a tooling failure; first-party rows are classified by ALLOWLIST.
  # Installed for the host once, then pointed at each shipped GOOS: `GOOS=x go run` would
  # build the tool itself for x.
  if ! GOBIN="$WORK/bin" go install "$GO_LICENSES" 2> "$WORK/go-licenses.err"; then
    echo "[licenses] FAIL could not build go-licenses:" >&2
    tail -n 20 "$WORK/go-licenses.err" >&2
    exit 3
  fi
  local goos
  for goos in $SHIPPED_GOOS; do
    if ! (cd "$ROOT_DIR" && GOOS="$goos" "$WORK/bin/go-licenses" csv ./cmd/...) >> "$WORK/go-all.csv" 2> "$WORK/go-licenses.err"; then
      echo "[licenses] FAIL go-licenses could not resolve the module graph (GOOS=$goos):" >&2
      tail -n 20 "$WORK/go-licenses.err" >&2
      exit 3
    fi
  done
  LC_ALL=C sort -u "$WORK/go-all.csv" > "$1"
  rm -f "$WORK/go-all.csv"
}

# One node program for classification and table rendering so the SPDX logic exists once.
read -r -d '' JS <<'EOF' || true
const fs = require('fs');
const [mode, csvPath, modsPath, lockPath] = process.argv.slice(1);
const allow = (process.env.ALLOWLIST || '').split('\n').filter(Boolean).map(l => { const [name, spdx, reason] = l.split('\t'); return { name, spdx, reason }; });
const allowFor = n => allow.find(a => n === a.name || n.startsWith(a.name + '/'));
const DENIED = /^(A?GPL|SSPL)(-|\+|$)/i;
const UNKNOWN = /^(unknown|unlicensed|)$/i;

// Returns 'ok' | 'denied' | 'unknown' for an SPDX expression.
function classify(expr) {
  const raw = String(expr || '').trim();
  if (/^see license/i.test(raw)) return 'unknown';
  const toks = raw.match(/\(|\)|[^\s()]+/g) || [];
  let i = 0;
  const atom = () => {
    const t = toks[i++];
    if (t === undefined) return 'unknown';
    if (t === '(') { const r = or(); if (toks[i] === ')') i++; else return 'unknown'; return r; }
    if (/^with$/i.test(toks[i])) i += 2;
    if (DENIED.test(t)) return 'denied';
    return UNKNOWN.test(t) ? 'unknown' : 'ok';
  };
  const and = () => {
    let r = atom();
    while (/^and$/i.test(toks[i] || '')) { i++; const n = atom(); r = (r === 'denied' || n === 'denied') ? 'denied' : (r === 'unknown' || n === 'unknown') ? 'unknown' : 'ok'; }
    return r;
  };
  const or = () => {
    let r = and();
    while (/^or$/i.test(toks[i] || '')) { i++; const n = and(); r = (r === 'ok' || n === 'ok') ? 'ok' : (r === 'unknown' || n === 'unknown') ? 'unknown' : 'denied'; }
    return r;
  };
  const r = or();
  return i < toks.length ? 'unknown' : r;
}

function resolve(name, expr) {
  const c = classify(expr);
  if (c !== 'unknown') return { c, license: expr };
  const a = allowFor(name);
  return a ? { c: 'ok', license: a.spdx } : { c: 'unknown', license: expr || 'Unknown' };
}

const goRows = () => {
  if (!csvPath || csvPath === '-') return [];
  const mods = (modsPath && modsPath !== '-' ? fs.readFileSync(modsPath, 'utf8').split('\n').filter(Boolean) : [])
    .map(m => { const at = m.lastIndexOf('@'); return { path: m.slice(0, at), version: m.slice(at + 1) }; })
    .filter(m => m.version !== '');
  const byLen = [...mods].sort((a, b) => b.path.length - a.path.length);
  const pkgs = fs.readFileSync(csvPath, 'utf8').split('\n').filter(Boolean).map(l => {
    const f = l.split(','); return { pkg: f[0], license: f.slice(2).join(',') };
  });
  return { mods, byLen, pkgs };
};

const npmRows = () => {
  if (!lockPath || lockPath === '-') return [];
  const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  return Object.entries(lock.packages || {}).filter(([k]) => k !== '').map(([k, v]) => {
    const name = v.name || k.slice(k.lastIndexOf('node_modules/') + 'node_modules/'.length);
    const lic = typeof v.license === 'string' ? v.license : (v.license && v.license.type) || '';
    return { key: k, name, version: v.version || '', license: lic };
  });
};

const problems = [];
const note = (kind, name, license) => problems.push(`${kind} ${name} (${license || 'no license'})`);

if (mode === 'check') {
  const g = goRows();
  for (const p of g.pkgs || []) {
    const r = resolve(p.pkg, p.license);
    if (r.c === 'denied') note('DENIED go', p.pkg, p.license);
    else if (r.c === 'unknown') note('UNKNOWN go', p.pkg, p.license);
  }
  for (const n of npmRows()) {
    const r = resolve(n.name, n.license);
    if (r.c === 'denied') note('DENIED npm', n.name, n.license);
    else if (r.c === 'unknown') note('UNKNOWN npm', n.name, n.license);
  }
  if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
} else if (mode === 'go-rows' || mode === 'npm-rows') {
  const lines = [];
  if (mode === 'go-rows') {
    const g = goRows();
    const lic = new Map(g.mods.map(m => [m.path, new Set()]));
    for (const p of g.pkgs) {
      const m = g.byLen.find(m => p.pkg === m.path || p.pkg.startsWith(m.path + '/'));
      if (m) lic.get(m.path).add(p.license);
    }
    for (const m of g.mods) {
      const set = [...lic.get(m.path)].filter(l => l && !/^unknown$/i.test(l));
      const expr = set.length ? [...new Set(set)].sort().join(', ') : 'Unknown';
      const r = resolve(m.path, expr);
      lines.push([m.path, m.version, r.license]);
    }
  } else {
    for (const n of npmRows()) lines.push([n.name, n.version, resolve(n.name, n.license).license, n.key]);
  }
  lines.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : String(a[3]) < String(b[3]) ? -1 : 1);
  for (const l of lines) console.log(`| ${l[0]} | ${l[1]} | ${l[2]} |`);
}
EOF

run_node() { ALLOWLIST="$ALLOWLIST" node -e "$JS" "$@"; }

do_check() {
  local csv="-" mods="-" lock="-"
  if [[ -z "$SKIP_GO" ]]; then csv="$WORK/go.csv"; go_csv_into "$csv"; fi
  if [[ -z "$SKIP_NPM" ]]; then
    [[ -f "$NPM_LOCK" ]] || { echo "[licenses] FAIL $NPM_LOCK not found" >&2; exit 3; }
    lock="$NPM_LOCK"
  fi
  if run_node check "$csv" "$mods" "$lock" 2> "$WORK/problems"; then
    echo "[licenses] PASS no denied or unclassified licences"
  else
    echo "[licenses] FAIL licence policy violations (deny: GPL, AGPL, SSPL; unknown fails closed):" >&2
    cat "$WORK/problems" >&2
    exit 1
  fi
}

# Writes the inventory to $1. Date line is the only non-deterministic content.
render_inventory() {
  local out="$1" csv="$WORK/go.csv" mods="$WORK/go.mods"
  go_csv_into "$csv"
  go_modules_list > "$mods"
  {
    echo "# Third-party licenses"
    echo
    echo "Generated: $(date -u +%F) by \`scripts/check-licenses.sh generate\` (go-licenses ${GO_LICENSES##*@}, \`go list -deps -m\`, \`ui/package-lock.json\`)."
    echo "Do not edit by hand; regenerate on every dependency change. CI fails if this file lags the dependencies."
    echo "Go scope is the shipped binaries (\`./cmd/...\`), transitive dependencies included. Policy: [docs/LICENSING_AND_SUPPORT.md](docs/LICENSING_AND_SUPPORT.md)."
    echo
    echo "## Go modules"
    echo
    echo "| Module | Version | License |"
    echo "|---|---|---|"
    run_node go-rows "$csv" "$mods" "-"
    echo
    echo "## npm packages"
    echo
    echo "| Package | Version | License |"
    echo "|---|---|---|"
    run_node npm-rows "-" "-" "$NPM_LOCK"
  } > "$out"
}

section_rows() { # $1 inventory, $2 section heading
  awk -v h="## $2" '$0==h{s=1;next} /^## /{s=0} s && /^\| / && !/^\| (Module|Package) \|/ && !/^\|---/{n++} END{print n+0}' "$1"
}

do_verify_count() {
  [[ -f "$INVENTORY" ]] || { echo "[licenses] FAIL $INVENTORY not found; run generate" >&2; exit 1; }
  local rc=0 go_want go_have npm_want npm_have
  go_want="$(go_modules_list | grep -vc '@$' || true)"
  go_have="$(section_rows "$INVENTORY" "Go modules")"
  npm_want="$(jq '[.packages|keys[]|select(.!="")]|length' "$NPM_LOCK")"
  npm_have="$(section_rows "$INVENTORY" "npm packages")"
  echo "go: $go_have/$go_want npm: $npm_have/$npm_want"
  [[ "$go_have" == "$go_want" && "$npm_have" == "$npm_want" ]] || rc=1
  if [[ "$rc" == 0 && -z "$NO_DRIFT" && -z "$GO_CSV" && -z "$GO_MODULES" ]]; then
    render_inventory "$WORK/regenerated.md"
    if ! diff <(grep -v '^Generated: ' "$INVENTORY") <(grep -v '^Generated: ' "$WORK/regenerated.md") > "$WORK/drift.diff"; then
      echo "[licenses] FAIL $INVENTORY is stale; run: bash scripts/check-licenses.sh generate" >&2
      head -n 20 "$WORK/drift.diff" >&2
      rc=1
    fi
  fi
  [[ "$rc" == 0 ]] || { echo "[licenses] FAIL inventory does not list every dependency" >&2; exit 1; }
  echo "[licenses] PASS inventory is complete and current"
}

case "$CMD" in
  check) do_check ;;
  generate)
    # Never write an inventory that would hide a policy failure.
    do_check
    render_inventory "$INVENTORY"
    echo "[licenses] wrote $INVENTORY"
    ;;
  verify-count) do_verify_count ;;
esac
