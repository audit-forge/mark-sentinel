#!/usr/bin/env bash
# Read-only migration checks. --iap is the only path that contacts a live host.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
iap=false
project=""
zone=""
instance=""
https_host=""
cohort_file=""

usage() {
  printf '%s\n' "Usage: $0 [--iap --project ID --zone ZONE --instance NAME --https-host HOST [--cohort-file FILE]]"
}

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }

while (($#)); do
  case "$1" in
    --iap) iap=true ;;
    --project|--zone|--instance|--https-host|--cohort-file)
      (($# >= 2)) || fail "$1 requires a value"
      case "$1" in
        --project) project=$2 ;;
        --zone) zone=$2 ;;
        --instance) instance=$2 ;;
        --https-host) https_host=$2 ;;
        --cohort-file) cohort_file=$2 ;;
      esac
      shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift
done

[[ -f "$repo_root/deploy/gcp/docker-compose.yml" ]] || fail "run from a Sentinel checkout"
grep -q '"80:80"' "$repo_root/deploy/gcp/docker-compose.yml" || fail "port 80 listener was not found"
grep -q '7001' "$repo_root/deploy/gcp/docker-compose.yml" && fail "stale port 7001 reference still present" || true
grep -q "RELEASE_DIR = ROOT / 'releases' / 'current'" "$repo_root/server.py" || fail "release serving root was not found"
grep -q "refusing non-HTTPS" "$repo_root/agent.py" || fail "agent HTTPS refusal was not found"
grep -q "_validate_update_manifest" "$repo_root/agent.py" || fail "agent signed-manifest validation was not found"
pass "source preserves current public ports and contains HTTPS signed-update checks"

if [[ -n "$cohort_file" ]]; then
  [[ -r "$cohort_file" ]] || fail "cannot read cohort file"
  grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$' "$cohort_file" || fail "cohort file contains an invalid customer ID"
  [[ $(sort -u "$cohort_file" | wc -l | tr -d ' ') -eq $(wc -l < "$cohort_file" | tr -d ' ') ]] || fail "cohort file contains duplicate customer IDs"
  cohort_count=$(wc -l < "$cohort_file" | tr -d ' ')
  cohort_digest=$(LC_ALL=C sort "$cohort_file" | shasum -a 256 | awk '{print $1}')
  pass "cohort file has ${cohort_count} unique customer IDs (digest ${cohort_digest})"
fi

if ! "$iap"; then
  printf '%s\n' 'INFO: local-only checks complete; use --iap for approved read-only live checks.'
  exit 0
fi

[[ -n "$project" && -n "$zone" && -n "$instance" && -n "$https_host" ]] || fail "--iap requires --project, --zone, --instance, and --https-host"
[[ "$https_host" =~ ^[A-Za-z0-9.-]+$ ]] || fail "--https-host must be a hostname only"
command -v gcloud >/dev/null || fail "gcloud is required for --iap"

# Arguments contain IDs/digests only. The remote program neither reads nor emits token contents.
remote_command='set -euo pipefail
release=/opt/sentinel/releases/current
data_root=/opt/sentinel-data
test -d "$release" && test ! -L "$release"
test "$(stat -c %U "$release")" = root
test "$(stat -c %G "$release")" = nginx
test "$(stat -c %a "$release")" = 750
for name in manifest.json manifest.sig; do test -s "$release/$name" && test ! -L "$release/$name"; done
test -z "$(find "$release" -maxdepth 1 -type f -perm /022 -print -quit)"
test -z "$(find "$release" -maxdepth 1 -type f \( ! -user root -o ! -group nginx -o ! -perm 0640 \) -print -quit)"
nginx -t >/dev/null
test "$(curl --silent --show-error --output /dev/null --write-out "%{http_code}" --max-time 15 "https://$1/releases/current/manifest.json")" = 401
actual=$(find "$data_root" -mindepth 1 -maxdepth 1 -type d -printf "%f\n" | LC_ALL=C sort)
actual_count=$(printf "%s\n" "$actual" | sed "/^$/d" | wc -l | tr -d " ")
actual_digest=$(printf "%s\n" "$actual" | sed "/^$/d" | shasum -a 256 | awk "{print \$1}")
token_count=0
while IFS= read -r customer; do
  [ -z "$customer" ] && continue
  token="$data_root/$customer/agent_token.txt"
  test -s "$token" && test ! -L "$token"
  test "$(stat -c %U "$token")" = root && test "$(stat -c %G "$token")" = root && test "$(stat -c %a "$token")" = 600
  token_count=$((token_count + 1))
done <<EOF
$actual
EOF
if [ -n "$2" ]; then test "$actual_count" = "$2" && test "$actual_digest" = "$3"; fi
printf "PASS: remote TLS, nginx, release metadata, and token-presence checks (customers=%s tokens=%s)\n" "$actual_count" "$token_count"
ss -ltn | grep -Eq ":(80)[[:space:]]"'

gcloud compute ssh "$instance" --project="$project" --zone="$zone" --tunnel-through-iap \
  --command="bash -s -- '$https_host' '${cohort_count:-}' '${cohort_digest:-}'" <<< "$remote_command"
pass "IAP-only remote preflight completed; retain its output as evidence"
