#!/usr/bin/env bash
# W27-26 live proof: renew a throwaway certificate through the hub, at a real
# ACME CA (Let's Encrypt STAGING by default), solving dns-01 in a real DNS
# provider, for each of Route53, Azure DNS, GCP Cloud DNS, RFC2136 and CNAME
# delegation (acme-dns), plus a wildcard. Cloudflare is W20-29
# (tests/live/acme-upstream/run.sh), not repeated here.
#
#   bash run.sh [leg ...]   legs: route53 azure gcp rfc2136 cname wildcard route53-long-wait
#                           rfc2136-long-wait (opt-in local stand-in) | all (default)
#
# Per leg: unmanaged cert -> provider credential -> ACME connector -> takeover
# -> SSH nginx target -> renewal/execute (CURL_MAX=900) -> served fingerprint ==
# new_fingerprint, issuer, SAN -> provider-side proof no _acme-challenge TXT is
# left -> secrets found 0 times in hub log + audit.
#
# Exit: 0 every selected leg PASSED, 1 a leg FAILED, 2 something was SKIPPED
# (missing prerequisite, named on a "SKIP: <leg> needs <VAR>" line) and nothing
# failed. A skipped leg is never reported as PASS. Every secret env var is a
# FILE PATH, read by Python and sent only to the hub. See README.md.
set -u
set -o pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SEL="${*:-all}"
for a in $SEL; do
  case "$a" in
    route53|azure|gcp|rfc2136|cname|wildcard|route53-long-wait|rfc2136-long-wait|all) ;;
    *) echo "usage: $0 [leg ...]   legs: route53 azure gcp rfc2136 cname wildcard route53-long-wait rfc2136-long-wait | all"; exit 64 ;;
  esac
done

# Which legs are wanted, and which can run (prerequisites present). rfc2136-long-wait is
# opt-in (it is the local stand-in for the route53 long wait, not a spec leg).
WANT=""
for a in $SEL; do case "$a" in all) WANT="$WANT route53 azure gcp rfc2136 cname wildcard route53-long-wait" ;; *) WANT="$WANT $a" ;; esac; done
RUN=""; SKIPPED=0; SKIPROWS=""
add_skip() { SKIPPED=1; SKIPROWS="${SKIPROWS}$1	SKIPPED	-	-	-	-	-	$2
"; }
first_runnable_provider() {
  local p
  for p in ${KK_WILDCARD_LEG:-route53 azure gcp rfc2136}; do
    "leg_need_$p" "wildcard" >/dev/null 2>&1 && { echo "$p"; return 0; }
  done
  return 1
}
for leg in $WANT; do
  case "$leg" in
    route53|azure|gcp|rfc2136|cname)
      if msg="$("leg_need_$leg" "$leg")"; then RUN="$RUN $leg:$leg:normal"; else echo "$msg"; add_skip "$leg" "${msg#SKIP: }"; fi ;;
    wildcard)
      if p="$(first_runnable_provider)"; then RUN="$RUN wildcard:$p:wildcard"
      else echo "SKIP: wildcard needs prerequisites of at least one provider leg (route53, azure, gcp or rfc2136)"; add_skip wildcard "needs prerequisites of at least one provider leg"; fi ;;
    route53-long-wait)
      if msg="$(leg_need_route53 route53-long-wait)"; then RUN="$RUN route53-long-wait:route53:longwait"; else echo "$msg"; add_skip route53-long-wait "${msg#SKIP: }"; fi ;;
    rfc2136-long-wait)
      if msg="$(leg_need_rfc2136 rfc2136-long-wait)"; then RUN="$RUN rfc2136-long-wait:rfc2136:longwait"; else echo "$msg"; add_skip rfc2136-long-wait "${msg#SKIP: }"; fi ;;
  esac
done

if [ -z "$RUN" ]; then
  echo "nothing runnable: every selected leg was skipped"
  RESULTS="$SKIPROWS"; print_results
  exit 2
fi

kk_init
for spec in $RUN; do
  # shellcheck disable=SC2034  # read by build_and_start in lib.sh
  case "$spec" in *:rfc2136:*) use_local_rfc2136 && KK_NEED_LOCAL=1 ;; esac
done
build_and_start
for spec in $RUN; do
  IFS=: read -r label prov mode <<<"$spec"
  run_leg "$label" "$prov" "$mode"
done
RESULTS="${RESULTS}${SKIPROWS}"
print_results
echo
if [ "$FAILED" != 0 ]; then echo "ONE OR MORE LEGS FAILED"; exit 1; fi
if [ "$SKIPPED" != 0 ]; then echo "ALL RUN LEGS PASSED; some legs were SKIPPED (see SKIP lines)"; exit 2; fi
echo "ALL LEGS PASSED"; exit 0
