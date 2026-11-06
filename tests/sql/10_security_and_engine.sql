-- Risk Ledger tests: run on local Postgres after 00_mock_supabase.sql and setup.sql.
-- Each block acts as a specific user (role + JWT subject), exactly as Supabase's API would.
\set ON_ERROR_STOP 1
set client_min_messages = warning;

create schema t;
create table t.results (n serial, name text, ok boolean, info text);

create function t.check(name text, ok boolean, info text default '') returns void language sql as $$
  insert into t.results (name, ok, info) values (name, coalesce(ok, false), info);
$$;
-- Run a statement and report whether it was refused
create function t.refused(stmt text) returns boolean language plpgsql as $$
begin
  execute stmt;
  return false;
exception when others then
  return true;
end $$;
grant usage on schema t to anon, authenticated;
grant all on all tables in schema t to anon, authenticated;
grant all on all sequences in schema t to anon, authenticated;
grant execute on all functions in schema t to anon, authenticated;

-- Users: one per role
insert into auth.users (id, email) values
  ('00000000-0000-0000-0000-0000000000a1', 'jasmine@example.com'),
  ('00000000-0000-0000-0000-0000000000b2', 'priya@example.com'),
  ('00000000-0000-0000-0000-0000000000c3', 'auditor@example.com'),
  ('00000000-0000-0000-0000-0000000000d4', 'newcomer@example.com'),
  ('00000000-0000-0000-0000-0000000000e5', 'marco@example.com');
update public.profiles set role = 'grc_analyst', display_name = 'Jasmine' where id = '00000000-0000-0000-0000-0000000000a1';
update public.profiles set role = 'control_owner', display_name = 'Priya' where id = '00000000-0000-0000-0000-0000000000b2';
update public.profiles set role = 'auditor', display_name = 'Avery' where id = '00000000-0000-0000-0000-0000000000c3';
update public.profiles set role = 'control_owner', display_name = 'Marco' where id = '00000000-0000-0000-0000-0000000000e5';
update public.controls set owner_id = '00000000-0000-0000-0000-0000000000b2', owner_name = 'Priya' where id = 'CC-04';
update public.controls set owner_id = '00000000-0000-0000-0000-0000000000e5', owner_name = 'Marco' where id = 'CC-07';

select t.check('setup: 12 active controls', (select count(*) = 12 from public.controls where status = 'active'));
select t.check('setup: new sign-up gets no access', (select role = 'pending' from public.profiles where id = '00000000-0000-0000-0000-0000000000d4'));
select t.check('setup: every table has RLS', not exists (select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
                                                          where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity));

-- ---------------- Anonymous visitor ----------------
set role anon;
select t.check('anon: can''t read controls', t.refused('select * from public.controls'));
select t.check('anon: can''t read the audit log', t.refused('select * from public.audit_log'));
select t.check('anon: can''t run tests', t.refused('select public.run_control_tests()'));
reset role;

-- ---------------- Pending user ----------------
set role authenticated; select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-0000000000d4', false);
select t.check('pending: sees no controls', (select count(*) = 0 from public.controls));
select t.check('pending: sees no risks', (select count(*) = 0 from public.risks));
select t.check('pending: can''t run tests', t.refused('select public.run_control_tests()'));
select t.check('pending: can''t give themselves a role', t.refused('update public.profiles set role = ''grc_analyst'' where id = auth.uid()'));
reset role;

-- ---------------- GRC analyst runs the tests ----------------
set role authenticated; select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-0000000000a1', false);
select public.run_control_tests();
select t.check('run 1: expected passes', (select array_agg(id order by id) = '{CC-01,CC-03,CC-05,CC-08,SB-01,SB-02,SB-04}'
                                            from public.control_status where last_result = 'pass'),
               (select string_agg(id || '=' || last_result, ' ' order by id) from public.control_status));
select t.check('run 1: expected failures', (select array_agg(id order by id) = '{CC-02,CC-04,CC-06,CC-07,SB-03}'
                                              from public.control_status where last_result = 'fail'));
select t.check('run 1: failing items are named', (select failing @> '["meridian-marketing-assets"]' from public.evidence where control_id = 'CC-04'));
select t.check('run 1: percentage reported', (select detail like '92%% (46 of 50)%' from public.evidence where control_id = 'CC-07'),
               (select detail from public.evidence where control_id = 'CC-07'));
select t.check('run 1: one remediation item per failure', (select count(*) = 5 from public.remediation where status = 'open'));
select t.check('run 1: critical failures due within 7 days', (select due_date = current_date + 7 from public.remediation where control_id = 'CC-04'));
select t.check('run 1: risks with all controls passing are ready to close',
               (select array_agg(id order by id) = '{R-04,R-06,R-07}' from public.risks where status = 'ready_to_close'));
select t.check('run 1: live evidence is marked live', (select bool_and(not is_mock) from public.source_snapshots where system_id = 'supabase'));
select t.check('GRC: can''t mark a fix done by hand', t.refused('update public.remediation set status = ''evidenced'' where control_id = ''CC-02'''));
select t.check('GRC: can''t close a risk that isn''t ready', t.refused('select public.close_risk(''R-02'', ''looks fine to me'')'));
select t.check('GRC: can''t close a risk directly', t.refused('update public.risks set status = ''closed'' where id = ''R-04'''));
select t.check('GRC: can''t edit evidence', t.refused('update public.evidence set result = ''pass'''));
select t.check('GRC: risk acceptance needs an end date', t.refused('update public.remediation set status = ''risk_accepted'', owner_note = ''Accepted for the pilot'' where control_id = ''CC-06'''));
select t.check('GRC: risk acceptance capped at 180 days', t.refused(format('update public.remediation set status = ''risk_accepted'', accepted_until = %L, owner_note = ''Accepted for the pilot'' where control_id = ''CC-06''', current_date + 200)));
update public.remediation set status = 'risk_accepted', accepted_until = current_date + 60,
       owner_note = 'Billing review moved to Q1 with the new system' where control_id = 'CC-06';
select t.check('GRC: risk acceptance with end date and reason works', (select status = 'risk_accepted' from public.remediation where control_id = 'CC-06'));
select public.close_risk('R-04', 'Logging and the protected audit trail are both evidenced.');
select t.check('GRC: closes a ready risk with a note', (select status = 'closed' and closed_at is not null from public.risks where id = 'R-04'));
reset role;

-- ---------------- Control owner ----------------
set role authenticated; select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-0000000000b2', false);
select t.check('owner: sees only their own remediation', (select count(*) = 1 and bool_and(control_id = 'CC-04') from public.remediation));
select t.check('owner: sees evidence for their control only', (select bool_and(control_id = 'CC-04') from public.evidence));
select t.check('owner: can''t read the audit log', (select count(*) = 0 from public.audit_log));
update public.remediation set status = 'in_progress', owner_note = 'Removing public access today' where control_id = 'CC-04';
select t.check('owner: updates progress on their item', (select status = 'in_progress' from public.remediation where control_id = 'CC-04'));
select t.check('owner: can''t mark it fixed', t.refused('update public.remediation set status = ''evidenced'' where control_id = ''CC-04'''));
select t.check('owner: can''t accept the risk', t.refused(format('update public.remediation set status = ''risk_accepted'', accepted_until = %L, owner_note = ''not my problem now'' where control_id = ''CC-04''', current_date + 30)));
select t.check('owner: can''t change the due date', t.refused('update public.remediation set due_date = current_date + 90'));
select t.check('owner: can''t run tests', t.refused('select public.run_control_tests()'));
select t.check('owner: can''t touch others'' items', (select count(*) = 0 from (select 1 from public.remediation where control_id = 'CC-02') x));
reset role;

-- ---------------- A second owner can't see the first owner's work (horizontal isolation) ----------------
set role authenticated; select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-0000000000e5', false);
select t.check('second owner: sees only their own remediation', (select count(*) = 1 and bool_and(control_id = 'CC-07') from public.remediation));
select t.check('second owner: can''t see Priya''s item or note', not exists (select 1 from public.remediation where control_id = 'CC-04' or owner_note like '%public access%'));
select t.check('second owner: can''t see Priya''s evidence', not exists (select 1 from public.evidence where control_id = 'CC-04'));
update public.remediation set owner_note = 'Marco was here' where control_id = 'CC-04';
reset role;
select t.check('second owner: update to Priya''s item had no effect', not exists (select 1 from public.remediation where owner_note = 'Marco was here'));

-- ---------------- Auditor ----------------
set role authenticated; select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-0000000000c3', false);
select t.check('auditor: reads all remediation', (select count(*) = 5 from public.remediation));
select t.check('auditor: reads the audit log', (select count(*) > 20 from public.audit_log));
select t.check('auditor: audit chain verifies', (select first_broken_id is null and rows_checked > 20 from public.verify_audit_chain()));
update public.remediation set owner_note = 'auditor was here';   -- silently matches no rows under RLS
select t.check('auditor: update had no effect', not exists (select 1 from public.remediation where owner_note = 'auditor was here'));
select t.check('auditor: can''t run tests', t.refused('select public.run_control_tests()'));
select t.check('auditor: can''t approve controls', t.refused('select public.approve_control(''CC-01'')'));
reset role;

-- ---------------- Audit log can't be changed, even by the database owner ----------------
select t.check('owner role: can''t update the audit log', t.refused('update public.audit_log set action = ''x'''));
select t.check('owner role: can''t delete the audit log', t.refused('delete from public.audit_log'));
select t.check('owner role: can''t truncate the audit log', t.refused('truncate public.audit_log'));
select t.check('owner role: can''t delete evidence', t.refused('delete from public.evidence'));
begin;
  alter table public.audit_log disable trigger audit_log_no_change;
  update public.audit_log set changes = '{"tampered": true}' where id = 5;
  set role authenticated; select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-0000000000c3', true);
  select t.check('tampering: chain verification finds the edited row', (select first_broken_id = 5 from public.verify_audit_chain()));
  reset role;
rollback;

-- ---------------- Fixes are proven by evidence, and the register shrinks ----------------
insert into auth.mfa_factors (user_id, status) values ('00000000-0000-0000-0000-0000000000a1', 'verified');
set role authenticated; select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-0000000000a1', false);
select public.load_mock_snapshot('gcp', '{"buckets":[{"name":"meridian-analytics-exports","public":false},{"name":"meridian-marketing-assets","public":false},{"name":"meridian-ml-training","public":false}]}');
select t.check('GRC: can''t fake live evidence', t.refused('select public.load_mock_snapshot(''supabase'', ''{}'')'));
select public.run_control_tests();
select t.check('run 2: MFA fix evidenced', (select status = 'evidenced' and resolved_evidence_id is not null from public.remediation where control_id = 'SB-03'));
select t.check('run 2: bucket fix evidenced', (select status = 'evidenced' from public.remediation where control_id = 'CC-04'));
select t.check('run 2: R-01 and R-03 now ready to close', (select array_agg(id order by id) @> '{R-01,R-03}' from public.risks where status = 'ready_to_close'));
select t.check('run 2: accepted risk stays accepted', (select status = 'risk_accepted' from public.remediation where control_id = 'CC-06'));
select public.close_risk('R-01', 'MFA verified for all privileged and GRC accounts.');
select t.check('trend: open risks fell today', (select open_risks from public.risk_trend where day = current_date)
                                              < (select open_risks from public.risk_trend where day = current_date - 1),
               (select string_agg(day || ':' || open_risks, ' ') from public.risk_trend where day >= current_date - 2));
reset role;

-- ---------------- An expired exception turns back into open work ----------------
select set_config('risk_ledger.engine', 'on', false);
update public.remediation set accepted_until = current_date - 1 where control_id = 'CC-06';
select set_config('risk_ledger.engine', 'off', false);
set role authenticated; select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-0000000000a1', false);
select public.run_control_tests();
select t.check('expired acceptance reopens', (select status = 'open' and owner_note like '%Exception expired%' from public.remediation where control_id = 'CC-06'));

-- ---------------- AI-drafted controls: validated, then a human approves ----------------
select t.check('draft: unknown rule type rejected', t.refused($$select public.propose_control('AI-01','x','x','okta','{"type":"sql","query":"drop table risks"}','x')$$));
select t.check('draft: extra keys rejected', t.refused($$select public.propose_control('AI-01','x','x','okta','{"type":"all_match","collection":"users","field":"mfa_enabled","equals":true,"code":"x"}','x')$$));
select t.check('draft: invented collection rejected', t.refused($$select public.propose_control('AI-01','x','x','okta','{"type":"all_match","collection":"service_accounts","field":"mfa_enabled","equals":true}','x')$$));
select t.check('draft: unsafe field name rejected', t.refused($$select public.propose_control('AI-01','x','x','okta','{"type":"all_match","collection":"users","field":"x); drop table risks;--","equals":true}','x')$$));
select public.propose_control('AI-01', 'All Okta users have MFA', 'Any account, not just admins, resists password theft.', 'okta',
  '{"type":"percent_match","collection":"users","field":"mfa_enabled","equals":true,"threshold":1}', 'Every Okta user has MFA enabled',
  'R-01', 'high', 7, '{CC6.1}', '{A.8.5}', 'ai');
select t.check('draft: valid AI draft saved as draft', (select status = 'draft' and drafted_by = 'ai' from public.controls where id = 'AI-01'));
select public.run_control_tests();
select t.check('draft: drafts are never run', not exists (select 1 from public.evidence where control_id = 'AI-01'));
select t.check('draft: can''t activate by editing', t.refused('update public.controls set status = ''active'' where id = ''AI-01'''));
select public.approve_control('AI-01');
select t.check('draft: approval records who approved', (select status = 'active' and approved_by = '00000000-0000-0000-0000-0000000000a1' from public.controls where id = 'AI-01'));
select public.run_control_tests();
select t.check('draft: approved control runs and finds the gap', (select result = 'fail' and failing @> '["okta-004"]' from public.evidence where control_id = 'AI-01' order by id desc limit 1));
reset role;

-- ---------------- Bad data is an error, never a pass ----------------
select t.check('engine: bad date is an error', (select result = 'error' from public.evaluate_rule(
  '{"type":"max_age_days","collection":"x","field":"d","max_days":90}', '{"x":[{"d":"not a date"}]}', now())));
select t.check('engine: empty scope is an error', (select result = 'error' from public.evaluate_rule(
  '{"type":"all_match","collection":"x","where":{"privileged":true},"field":"mfa","equals":true}', '{"x":[{"privileged":false}]}', now())));
select t.check('engine: missing field counts as failing', (select result = 'fail' from public.evaluate_rule(
  '{"type":"all_match","collection":"x","field":"mfa","equals":true}', '{"x":[{"id":"a"}]}', now())));

-- ---------------- The live check catches the CVE-2025-48757 pattern ----------------
create policy "everyone reads risks" on public.risks for select to authenticated using (true);
select t.check('live: a "true" policy fails SB-04', (select result = 'fail' and failing::text like '%allows every row%' from public.live_check('no_open_policies')));
drop policy "everyone reads risks" on public.risks;
create policy "any signed-in user" on public.remediation for select to authenticated using (auth.uid() is not null);
select t.check('live: an "any signed-in user" policy fails SB-04', (select result = 'fail' and failing::text like '%only checks that someone is signed in%' from public.live_check('no_open_policies')));
drop policy "any signed-in user" on public.remediation;
create policy "visitors" on public.controls for select to anon using (status = 'active');
select t.check('live: a policy for anonymous visitors fails SB-04', (select result = 'fail' and failing::text like '%anonymous visitors%' from public.live_check('no_open_policies')));
drop policy "visitors" on public.controls;
grant select on public.evidence to anon;
select t.check('live: table rights for anonymous visitors fail SB-04', (select result = 'fail' and failing::text like '%evidence: anonymous visitors have select%' from public.live_check('no_open_policies')));
revoke select on public.evidence from anon;
select t.check('live: SB-04 passes again once fixed', (select result = 'pass' from public.live_check('no_open_policies')));

-- ---------------- The live check catches a new table without RLS ----------------
create table public.forgot_rls (id int);
select t.check('live: new table without RLS fails SB-01', (select result = 'fail' and failing @> '["forgot_rls"]' from public.live_check('rls_on_all_tables')));
drop table public.forgot_rls;

-- Results are in t.results; tests/run.sh prints them.
