#!/usr/bin/env bash
# tokens.sh HUBPORT EMAIL OUTFILE  -- API login (not the UI form) so specs reuse one session per persona
curl -s -X POST "http://127.0.0.1:$1/api/v1/auth/login" -H 'content-type: application/json' \
  -d "{\"email\":\"$2\",\"password\":\"${KK_PASSWORD:-GuideDemo!2026}\"}" | jq '.data|{access_token,refresh_token}' >"$3"
