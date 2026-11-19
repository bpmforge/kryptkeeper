# shellcheck shell=bash
# Sourced by tests/live/*/run.sh legs selected with KK_AWS_EMULATOR=aws.
# Starts AWS's own emulator (aws-emulator, https://github.com/aws/aws-emulator)
# and exports the environment from its "point the SDK at the emulator" page,
# so aws-sdk-go-v2 and the AWS CLI reach it with SigV4 on and its per-run CA
# trusted. Against AWS's emulator, not real AWS: IAM, key policies, quotas and
# HSM tiers are not emulated.
#
#   kk_aws_emulator_start   host process on 127.0.0.1 (Go tests, host hubs)
#   kk_aws_emulator_netns C  same binary inside container C's network namespace
#                            (its certificate names only localhost and
#                            127.0.0.1, so whatever dials it must share that
#                            loopback; the hub's egress guard refuses loopback,
#                            so containerised hubs go through a TLS pass-through
#                            in C, see tests/live/upstream-cas)
#   kk_aws_emulator_stop     stop whichever was started (call from the trap)
#
# Both return 2 after printing a named SKIP when aws-emulator is not
# installed (KK_AWS_EMULATOR_BIN names another binary); callers turn that
# into a skip, never a failure.

KK_AWS_EMU_PID=""
KK_AWS_EMU_CTR=""
KK_AWS_EMU_BIN="${KK_AWS_EMULATOR_BIN:-aws-emulator}"

kk_aws_emulator_installed() {
  if command -v "$KK_AWS_EMU_BIN" >/dev/null 2>&1; then return 0; fi
  echo "SKIP: aws-emulator not installed (KK_AWS_EMULATOR=aws needs the aws-emulator package; see https://docs.aws.amazon.com/emulator/latest/userguide/getting-started-linux.html)"
  return 2
}

# _kk_aws_emu_env DIR PORT: the point-the-SDK environment for files in DIR.
_kk_aws_emu_env() {
  local dir="$1" port="$2"
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE
  export AWS_ENDPOINT_URL="https://127.0.0.1:${port}" \
    AWS_SHARED_CREDENTIALS_FILE="$dir/emulator_credentials" \
    AWS_CONFIG_FILE="$dir/config" \
    AWS_CA_BUNDLE="$dir/ca.pem" \
    AWS_EC2_METADATA_DISABLED=true \
    AWS_DISABLE_HOST_PREFIX_INJECTION=true \
    AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
  KK_AWS_EMULATOR_VERSION="$("$KK_AWS_EMU_BIN" -v 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')"
  export KK_AWS_EMULATOR_VERSION
  echo "aws-emulator: $KK_AWS_EMULATOR_VERSION"
}

# _kk_aws_emu_wait CA PORT: wait for /__admin/health (the files appear first).
_kk_aws_emu_wait() {
  local ca="$1" port="$2"
  for _ in $(seq 1 120); do
    [ -s "$ca" ] && curl -fsS --cacert "$ca" "https://127.0.0.1:${port}/__admin/health" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

# kk_aws_emulator_start: telemetry off, SigV4 on, 2 GiB cap (systemd user
# scope when one is available). KK_AWS_EMULATOR_PORT overrides the port.
# --idle-timeout reaps an emulator a crashed harness failed to stop.
kk_aws_emulator_start() {
  kk_aws_emulator_installed || return 2
  local port="${KK_AWS_EMULATOR_PORT:-$(kk_free_port)}"
  local dir="$HOME/.aws/emulator/$port"
  local args=("$KK_AWS_EMU_BIN" --telemetry off -p "$port" --idle-timeout "${KK_AWS_EMULATOR_IDLE:-900}")
  if command -v systemd-run >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
    systemd-run --user --scope --quiet -p MemoryMax=2G -p MemorySwapMax=0 "${args[@]}" >"${KK_AWS_EMULATOR_LOG:-/dev/null}" 2>&1 &
  else
    "${args[@]}" >"${KK_AWS_EMULATOR_LOG:-/dev/null}" 2>&1 &
  fi
  KK_AWS_EMU_PID=$!
  if ! _kk_aws_emu_wait "$dir/ca.pem" "$port"; then
    echo "FAIL: aws-emulator did not answer /__admin/health on :$port"
    kk_aws_emulator_stop
    return 1
  fi
  _kk_aws_emu_env "$dir" "$port"
  echo "PASS: aws-emulator answering on https://127.0.0.1:${port} (SigV4 on, telemetry off)"
}

# kk_aws_emulator_netns CONTAINER DIR: run the installed binary in a glibc
# container that shares CONTAINER's network namespace, with its home (and so
# its credentials, config and CA) in DIR on the host. The environment exported
# here names DIR's files; clients in CONTAINER's namespace reach the emulator
# at https://127.0.0.1:<port>. --init lets SIGTERM reach it as PID 1.
kk_aws_emulator_netns() {
  kk_aws_emulator_installed || return 2
  local ctr="$1" dir="$2" port="${KK_AWS_EMULATOR_PORT:-9297}"
  local bin; bin="$(readlink -f "$(command -v "$KK_AWS_EMU_BIN")")"
  local root="${bin%/bin/aws-emulator}"
  mkdir -p "$dir"
  KK_AWS_EMU_CTR="$ctr-awsemu"
  podman rm -f "$KK_AWS_EMU_CTR" >/dev/null 2>&1 || true
  podman run -d --name "$KK_AWS_EMU_CTR" --network "container:$ctr" --memory 2g --memory-swap 2g \
    --init -e HOME=/emuhome -v "$dir:/emuhome" -v "$root:/opt/aws-emulator:ro" \
    "${KK_AWS_EMULATOR_BASE_IMAGE:-docker.io/library/debian:13-slim}" \
    /opt/aws-emulator/bin/aws-emulator --telemetry off -p "$port" --idle-timeout "${KK_AWS_EMULATOR_IDLE:-900}" >/dev/null \
    || { echo "FAIL: could not start aws-emulator in $ctr's network namespace"; return 1; }
  for _ in $(seq 1 120); do
    [ -s "$dir/.aws/emulator/$port/ca.pem" ] && podman exec "$ctr" true >/dev/null 2>&1 && break
    sleep 0.5
  done
  [ -s "$dir/.aws/emulator/$port/ca.pem" ] || { echo "FAIL: aws-emulator in $ctr wrote no CA"; return 1; }
  _kk_aws_emu_env "$dir/.aws/emulator/$port" "$port"
  echo "PASS: aws-emulator answering inside $ctr at https://127.0.0.1:${port} (SigV4 on, telemetry off)"
}

kk_aws_emulator_stop() {
  if [ -n "$KK_AWS_EMU_PID" ]; then
    kill -TERM "$KK_AWS_EMU_PID" 2>/dev/null || true
    wait "$KK_AWS_EMU_PID" 2>/dev/null || true
    KK_AWS_EMU_PID=""
  fi
  if [ -n "$KK_AWS_EMU_CTR" ]; then
    podman rm -f -t 5 "$KK_AWS_EMU_CTR" >/dev/null 2>&1 || true
    KK_AWS_EMU_CTR=""
  fi
}
