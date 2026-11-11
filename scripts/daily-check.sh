#!/bin/sh
# Daily check from outside the database: sign in as the read-only AUDITOR and confirm
# the control tests ran recently. It proves the daily schedule is alive ("who watches
# the watcher"), and the sign-in and query are real project activity.
#
# Reads from the environment (never from arguments, so nothing lands in logs):
#   SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY   public values
#   AUDITOR_EMAIL, AUDITOR_PASSWORD          the auditor account: read-only by design
#   MAX_AGE_HOURS                            optional, default 26
set -eu
: "${SUPABASE_URL:?missing}" "${SUPABASE_PUBLISHABLE_KEY:?missing}"
if [ -z "${AUDITOR_EMAIL:-}" ] || [ -z "${AUDITOR_PASSWORD:-}" ]; then
  echo "AUDITOR_EMAIL and AUDITOR_PASSWORD are not set. Add them under the repository's Settings > Secrets and variables > Actions." >&2
  exit 2
fi
case "$SUPABASE_PUBLISHABLE_KEY" in sb_secret_*|eyJ*) echo "Refusing: use the publishable key, never a secret key." >&2; exit 2;; esac
MAX_AGE_HOURS="${MAX_AGE_HOURS:-26}"

body=$(jq -n --arg e "$AUDITOR_EMAIL" --arg p "$AUDITOR_PASSWORD" '{email:$e,password:$p}')
token=$(printf '%s' "$body" | curl -sS --fail-with-body -X POST "$SUPABASE_URL/auth/v1/token?grant_type=password" \
          -H "apikey: $SUPABASE_PUBLISHABLE_KEY" -H "Content-Type: application/json" --data-binary @- | jq -r '.access_token // empty') || true
if [ -z "$token" ]; then echo "Sign-in as the auditor failed. Check the two secrets." >&2; exit 1; fi

get() { curl -sS --fail-with-body "$SUPABASE_URL/rest/v1/$1" -H "apikey: $SUPABASE_PUBLISHABLE_KEY" -H "Authorization: Bearer $token"; }

last=$(get "test_runs?select=started_at&order=started_at.desc&limit=1" | jq -r '.[0].started_at // empty')
if [ -z "$last" ]; then echo "No test run found." >&2; exit 1; fi
age_hours=$(( ( $(date -u +%s) - $(date -u -d "$last" +%s) ) / 3600 ))

summary=$(get "control_status?select=id,status,last_result" | jq -r '
  [.[] | select(.status=="active")] as $a
  | "\($a | map(select(.last_result=="pass")) | length) of \($a | length) controls passing; not passing: \([$a[] | select(.last_result!="pass") | .id] | join(", ") | if .=="" then "none" else . end)"')

# Sign out so the token can't be reused
curl -sS -o /dev/null -X POST "$SUPABASE_URL/auth/v1/logout" -H "apikey: $SUPABASE_PUBLISHABLE_KEY" -H "Authorization: Bearer $token" || true

echo "Last test run: $last ($age_hours h ago)"
echo "$summary"
if [ "$age_hours" -gt "$MAX_AGE_HOURS" ]; then
  echo "The control tests have not run in over $MAX_AGE_HOURS hours. Check the daily schedule (cron.job) in Supabase." >&2
  exit 1
fi
echo "OK: the daily schedule is running."
