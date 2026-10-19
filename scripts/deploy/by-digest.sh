#!/usr/bin/env bash
set -euo pipefail

# Deploy Kryptkeeper by immutable image digest.
#
# Usage:
#   scripts/deploy/by-digest.sh <target_env> <image_digest> [change_ticket]
#
# Deploy driver (in priority order):
#   1. DEPLOY_CMD_STAGING / DEPLOY_CMD_PRODUCTION, if set — an explicit override,
#      executed with TARGET_ENV/IMAGE_DIGEST/CHANGE_TICKET/INCIDENT_ID exported.
#   2. Otherwise DEPLOY_METHOD (helm|kubectl, default helm) drives a real deploy:
#        helm:    helm upgrade --install $RELEASE $CHART_DIR -n $NAMESPACE
#                   --reset-then-reuse-values [-f $HELM_VALUES_FILE]
#                   --set image.repository=<repo> --set image.digest=<digest> --wait
#                 (image.digest is reconciled into the chart's values schema by W10-05)
#        kubectl: kubectl -n $NAMESPACE set image deployment/$RELEASE
#                   kryptkeeper=$IMAGE_DIGEST && kubectl rollout status ...
#      Runtime configuration for this path: RELEASE, NAMESPACE (required),
#      CHART_DIR (default charts/kryptkeeper, helm only), HELM_VALUES_FILE
#      (optional values file for the first install, helm only).
#
# --wait / rollout status gate success on the pods becoming genuinely ready,
# which is a real readiness check as of W10-02 (previously /readyz was a
# static 200, so this gate was cosmetic even before this script's own fix).

TARGET_ENV="${1:-}"
IMAGE_DIGEST="${2:-}"
CHANGE_TICKET="${3:-}"

if [[ -z "$TARGET_ENV" || -z "$IMAGE_DIGEST" ]]; then
  echo "Usage: $0 <target_env> <image_digest> [change_ticket]" >&2
  exit 2
fi

if [[ ! "$IMAGE_DIGEST" =~ ^[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{40,64}$ ]]; then
  echo "ERROR: invalid image digest format: $IMAGE_DIGEST" >&2
  exit 2
fi

case "$TARGET_ENV" in
  staging)
    DEPLOY_CMD="${DEPLOY_CMD_STAGING:-}"
    ;;
  production)
    DEPLOY_CMD="${DEPLOY_CMD_PRODUCTION:-}"
    ;;
  *)
    echo "ERROR: unsupported target_env '$TARGET_ENV' (expected staging|production)" >&2
    exit 2
    ;;
esac

if [[ -z "$DEPLOY_CMD" ]]; then
  DEPLOY_METHOD="${DEPLOY_METHOD:-helm}"
  RELEASE="${RELEASE:-}"
  NAMESPACE="${NAMESPACE:-}"
  CHART_DIR="${CHART_DIR:-charts/kryptkeeper}"

  if [[ -z "$RELEASE" || -z "$NAMESPACE" ]]; then
    echo "ERROR: RELEASE and NAMESPACE must be set to use the default $DEPLOY_METHOD deploy driver" >&2
    echo "(or set DEPLOY_CMD_STAGING / DEPLOY_CMD_PRODUCTION to override the driver entirely)" >&2
    exit 3
  fi

  IMAGE_REPO="${IMAGE_DIGEST%@*}"
  DIGEST="${IMAGE_DIGEST#*@}"

  case "$DEPLOY_METHOD" in
    helm)
      # Without --reset-then-reuse-values an upgrade drops every value the
      # release was installed with (secrets, dbMode, replicaCount) and the chart
      # then refuses to render; HELM_VALUES_FILE supplies them on a first install.
      VALUES_ARG=""
      if [[ -n "${HELM_VALUES_FILE:-}" ]]; then
        VALUES_ARG="-f \"$HELM_VALUES_FILE\""
      fi
      DEPLOY_CMD="helm upgrade --install \"$RELEASE\" \"$CHART_DIR\" -n \"$NAMESPACE\" \
        --reset-then-reuse-values $VALUES_ARG \
        --set image.repository=\"$IMAGE_REPO\" --set image.digest=\"$DIGEST\" --wait"
      ;;
    kubectl)
      DEPLOY_CMD="kubectl -n \"$NAMESPACE\" set image deployment/\"$RELEASE\" kryptkeeper=\"$IMAGE_DIGEST\" \
        && kubectl -n \"$NAMESPACE\" rollout status deployment/\"$RELEASE\""
      ;;
    *)
      echo "ERROR: unknown DEPLOY_METHOD '$DEPLOY_METHOD' (expected helm|kubectl)" >&2
      exit 2
      ;;
  esac
fi

echo "[deploy] env=$TARGET_ENV digest=$IMAGE_DIGEST ticket=${CHANGE_TICKET:-n/a}"
echo "[deploy] command configured; executing deployment driver"

export TARGET_ENV IMAGE_DIGEST CHANGE_TICKET

bash -lc "$DEPLOY_CMD"

echo "[deploy] deployment command completed"
