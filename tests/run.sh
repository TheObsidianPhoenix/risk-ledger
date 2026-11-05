#!/bin/sh
# Build setup.sql and test it on a fresh local Postgres database.
#   PGHOST=/tmp PGPORT=54329 PGUSER=postgres ./tests/run.sh
set -e
cd "$(dirname "$0")/.."
./build.sh >/dev/null
psql -q -c "drop database if exists risk_ledger_test" -c "create database risk_ledger_test" >/dev/null 2>&1
psql -q -d risk_ledger_test -v ON_ERROR_STOP=1 -f tests/sql/00_mock_supabase.sql >/dev/null
psql -q -d risk_ledger_test -v ON_ERROR_STOP=1 -f supabase/setup.sql >/dev/null
psql -q -d risk_ledger_test -v ON_ERROR_STOP=1 -f tests/sql/10_security_and_engine.sql >/dev/null
psql -d risk_ledger_test -c "select case when ok then 'PASS' else 'FAIL' end as result, name, nullif(info, '') as info from t.results order by n" | tee tests/last-run.txt
failed=$(psql -d risk_ledger_test -Atc "select count(*) from t.results where not ok")
total=$(psql -d risk_ledger_test -Atc "select count(*) from t.results")
echo "$((total - failed)) of $total passed"
[ "$failed" = "0" ]
