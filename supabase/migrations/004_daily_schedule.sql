-- Risk Ledger upgrade 004: run the control tests every day, automatically.
-- Paste into the Supabase SQL Editor and click Run. Safe to run more than once.
--
-- Uses pg_cron, the scheduler built into Supabase's Postgres. Scheduled runs have no
-- user, so test_runs.run_by is empty and the audit log shows "system via engine".

create extension if not exists pg_cron with schema pg_catalog;

-- 15:00 UTC every day (7am Pacific in winter, 8am in summer)
select cron.schedule('risk-ledger-daily', '0 15 * * *', $$select public.run_control_tests()$$);

-- Check: one row named risk-ledger-daily, active = true
select jobname, schedule, active from cron.job where jobname = 'risk-ledger-daily';
