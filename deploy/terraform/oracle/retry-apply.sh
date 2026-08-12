#!/usr/bin/env bash
# retry-apply.sh - drives `terraform apply` through Oracle's chronic
# "Out of host capacity" on free-tier A1 instances: retries with backoff,
# cycling every availability domain of the region.
#
#   ./retry-apply.sh [max_attempts]
#
# Tip: upgrading the account to Pay As You Go (still free within the
# Always Free limits) usually makes capacity appear immediately.
set -uo pipefail
cd "$(dirname "$0")"

MAX=${1:-120}
BACKOFF=60

# Discover the region's ADs (requires terraform init + valid credentials).
mapfile -t AD_LIST < <(terraform console <<< 'join("\n", [for ad in data.oci_identity_availability_domains.ads.availability_domains : ad.name])' 2>/dev/null | tr -d '"' | grep -v '^$' || true)
[ ${#AD_LIST[@]} -eq 0 ] && AD_LIST=("")

attempt=1
while [ "$attempt" -le "$MAX" ]; do
    AD=${AD_LIST[$(( (attempt - 1) % ${#AD_LIST[@]} ))]}
    echo "=== attempt $attempt/$MAX (AD: ${AD:-default}) ==="
    if terraform apply -auto-approve ${AD:+-var "availability_domain=$AD"}; then
        echo "=== apply succeeded ==="
        terraform output
        exit 0
    fi
    sleep_for=$(( BACKOFF + RANDOM % 240 ))
    echo "--- retrying in ${sleep_for}s ---"
    sleep "$sleep_for"
    attempt=$(( attempt + 1 ))
done
echo "gave up after $MAX attempts; consider upgrading to PAYG or another region" >&2
exit 1
