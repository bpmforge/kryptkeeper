#!/usr/bin/env bash
# fresh.sh NAME HUBPORT UIPORT DATADIR : wipe DATADIR, start a hub and seed the demo data.
# Needs RUN and BIN env (see hub.sh). Stops only the PIDs recorded under $RUN.
set -euo pipefail
H="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; REPO="$H/../../.."
name=$1; hp=$2; up=$3; data=$4
bash "$H/hub.sh" stop "$name" hub || true
[ -f "$RUN/$name.seed.pids" ] && { kill $(cat "$RUN/$name.seed.pids") 2>/dev/null || true; }
sleep 1; rm -rf "$data" "$data.cwd"
bash "$H/hub.sh" start "$name" "$hp" "$up" "$data"
BASE_URL="http://127.0.0.1:$hp" TOKEN=dev-token PIDFILE="$RUN/$name.seed.pids" bash "$REPO/scripts/dev/seed-demo.sh" >"$RUN/$name.seed.log" 2>&1 || { tail -20 "$RUN/$name.seed.log"; exit 1; }
tail -3 "$RUN/$name.seed.log" | head -1
