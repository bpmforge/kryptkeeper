#!/usr/bin/env bash
# W27-32 live proof: drive the hub's real delivery-plugin API (install, second-
# admin approval, credential, target, renewal/execute) against real secret
# stores and cloud load balancers / CDNs.
#
#   bash run.sh [leg ...]   legs: vault akv gcpsm aws-sm aws-alb aws-cloudfront
#                                 azure-appgw azure-frontdoor cloudflare | all (default)
#
# vault runs locally (HashiCorp Vault dev server, -dev-tls, in podman) with no
# account. Every other leg needs operator credentials: SKIP lines name the
# missing variable and the leg is recorded SKIPPED, never PASS. Every secret
# env var is a FILE PATH, read by Python and sent only to the hub.
#
# Per leg: build + install + enable the plugin (second admin approves) ->
# credential -> target -> issue a leaf at the hub CA -> renewal/execute must
# return installed_verified -> secret stores: the store read DIRECTLY holds a
# new version whose certificate fingerprint == new_fingerprint (+1 version);
# LB/CDN: the public endpoint serves the new serial within 900 s -> forced
# failure (install.verify_host_port at a TLS server presenting another cert)
# must give verify_failed, a rolled_back=true audit row, and the previous
# certificate current/served again -> secrets absent from hub log + audit.
#
# Exit: 0 every leg that ran PASSED, 1 a leg FAILED, 2 nothing was runnable.
set -u
set -o pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ALL="vault akv gcpsm aws-sm aws-alb aws-cloudfront azure-appgw azure-frontdoor cloudflare"
SEL="${*:-all}"
WANT=""
for a in $SEL; do
  case "$a" in
    all) WANT="$WANT $ALL" ;;
    vault|akv|gcpsm|aws-sm|aws-alb|aws-cloudfront|azure-appgw|azure-frontdoor|cloudflare) WANT="$WANT $a" ;;
    *) echo "usage: $0 [leg ...]   legs: $ALL | all"; exit 64 ;;
  esac
done

RUN=""; SKIPROWS=""
for leg in $WANT; do
  fn="leg_need_$(echo "$leg" | tr - _)"
  if msg="$("$fn")"; then RUN="$RUN $leg"
  else echo "$msg"; SKIPROWS="${SKIPROWS}$leg	SKIPPED	-	-	-	-	-	${msg#SKIP: }
"; fi
done
if [ -z "$RUN" ]; then
  echo "nothing runnable: every selected leg was skipped"
  RESULTS="$SKIPROWS"; print_results; exit 2
fi

kk_init
start_hub
case " $RUN " in *" vault "*) start_vault ;; esac
for leg in $RUN; do run_leg "$leg"; done
RESULTS="${RESULTS}${SKIPROWS}"
print_results
echo
[ "$FAILED" = 0 ] && { echo "ALL LEGS THAT RAN PASSED"; exit 0; }
echo "ONE OR MORE LEGS FAILED"; exit 1
