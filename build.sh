#!/bin/sh
# Combine the four parts into one script to paste into the Supabase SQL Editor.
set -e
cd "$(dirname "$0")"
{
  echo "-- Risk Ledger setup: paste this whole file into the Supabase SQL Editor and click Run."
  echo "-- Built from supabase/01_schema.sql to 04_seed.sql. Runs as one transaction: all or nothing."
  echo "begin;"
  for f in supabase/01_schema.sql supabase/02_engine.sql supabase/03_security.sql supabase/04_seed.sql; do
    echo; echo "-- ===== $f ====="; cat "$f"
  done
  echo; echo "commit;"
} > supabase/setup.sql
echo "Wrote supabase/setup.sql ($(wc -l < supabase/setup.sql) lines)"
