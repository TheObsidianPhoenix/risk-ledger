#!/bin/sh
# Attack your own Risk Ledger from the outside, the way the CVE-2025-48757 scans did:
# use only the public (publishable) key that every web page ships, and try to read
# every table and call every function as an anonymous visitor.
#
#   sh scripts/anonymous-probe.sh https://YOUR-PROJECT.supabase.co sb_publishable_...
#
# A pass means the request was refused or returned no rows. Never use a secret or
# service_role key here: those bypass Row Level Security by design.
URL="$1"; KEY="$2"
if [ -z "$URL" ] || [ -z "$KEY" ]; then echo "Usage: sh $0 <project URL> <publishable key>"; exit 2; fi
case "$KEY" in sb_secret_*|*service_role*) echo "Refusing: that's a secret key. Use the publishable key."; exit 2;; esac

fails=0
probe() {  # $1 label, $2 method, $3 path, $4 body
  if [ "$2" = "GET" ]; then
    out=$(curl -s -w '\n%{http_code}' "$URL/rest/v1/$3" -H "apikey: $KEY")
  else
    out=$(curl -s -w '\n%{http_code}' -X POST "$URL/rest/v1/$3" -H "apikey: $KEY" -H "Content-Type: application/json" -d "$4")
  fi
  code=$(printf '%s' "$out" | tail -n 1); body=$(printf '%s' "$out" | sed '$d')
  if [ "$code" = "401" ] || [ "$code" = "403" ] || [ "$code" = "404" ] || [ "$body" = "[]" ]; then
    printf 'PASS  %-34s refused or empty (HTTP %s)\n' "$1" "$code"
  else
    printf 'FAIL  %-34s HTTP %s: %.80s\n' "$1" "$code" "$body"; fails=$((fails + 1))
  fi
}

echo "Anonymous probe of $URL"
for t in profiles systems source_snapshots risks controls test_runs evidence remediation audit_log control_status risk_trend; do
  probe "read $t" GET "$t?select=*&limit=5"
done
probe "insert a risk" POST "risks" '{"id":"R-99","title":"x","likelihood":1,"impact":1}'
probe "run the control tests" POST "rpc/run_control_tests" '{}'
probe "approve a control" POST "rpc/approve_control" '{"p_id":"CC-01"}'
probe "verify the audit chain" POST "rpc/verify_audit_chain" '{}'
echo
if [ "$fails" = "0" ]; then echo "Every request was refused: nothing is readable or writable without signing in."; else echo "$fails request(s) got through. Investigate before sharing this project."; exit 1; fi
