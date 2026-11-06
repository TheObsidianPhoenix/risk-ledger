-- Risk Ledger upgrade 002: live check SB-04, "No policy opens a table to everyone".
-- For a project already set up with an earlier setup.sql. (A new project just runs setup.sql.)
-- Paste into the Supabase SQL Editor and click Run. One transaction: all or nothing.
begin;

alter table public.controls drop constraint if exists controls_live_check_check;
alter table public.controls add constraint controls_live_check_check
  check (live_check in ('rls_on_all_tables', 'no_open_policies', 'audit_log_protected', 'grc_analysts_have_mfa'));

create or replace function public.live_check(check_name text, out result text, out detail text, out failing jsonb, out snapshot jsonb)
language plpgsql stable security definer set search_path = public as $$
declare
  missing jsonb;
  total int;
begin
  if check_name = 'rls_on_all_tables' then
    select coalesce(jsonb_agg(c.relname order by c.relname) filter (where not c.relrowsecurity), '[]'), count(*)
      into missing, total
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relkind = 'r';
    snapshot := jsonb_build_object('tables_checked', total, 'without_rls', missing);
    detail := format('%s of %s tables have Row Level Security on', total - jsonb_array_length(missing), total);
  elsif check_name = 'no_open_policies' then
    -- The pattern behind CVE-2025-48757 and the 2026 UpGuard findings: Row Level Security is on,
    -- but a policy lets anyone, or any signed-in user, read every row
    select coalesce(jsonb_agg(problem order by problem), '[]'), (select count(*) from pg_policies where schemaname = 'public')
      into missing, total
      from (
        select tablename || ': policy "' || policyname || '" allows every row (true)' as problem
          from pg_policies where schemaname = 'public'
           and (btrim(coalesce(qual, ''), '() ') = 'true' or btrim(coalesce(with_check, ''), '() ') = 'true')
        union all
        select tablename || ': policy "' || policyname || '" only checks that someone is signed in'
          from pg_policies where schemaname = 'public'
           and (coalesce(qual, '') ~* '^\(*\s*auth\.uid\(\)\s+is\s+not\s+null\s*\)*$'
                or coalesce(qual, '') ~* 'auth\.role\(\)\s*=\s*''authenticated''')
        union all
        select tablename || ': policy "' || policyname || '" applies to anonymous visitors'
          from pg_policies where schemaname = 'public' and roles && array['anon', 'public']::name[]
        union all
        select c.relname || ': anonymous visitors have ' || lower(p) || ' rights'
          from pg_class c join pg_namespace n on n.oid = c.relnamespace,
               unnest(array['SELECT', 'INSERT', 'UPDATE', 'DELETE']) p
         where n.nspname = 'public' and c.relkind in ('r', 'v') and has_table_privilege('anon', c.oid, p)
      ) problems;
    snapshot := jsonb_build_object('policies_checked', total, 'problems', missing);
    detail := case when jsonb_array_length(missing) = 0
                   then format('%s policies checked: none opens a table to everyone or to any signed-in user', total)
                   else jsonb_array_length(missing) || ' over-broad access rule(s)' end;
  elsif check_name = 'audit_log_protected' then
    select coalesce(jsonb_agg(problem), '[]') into missing from (
      select 'no-change trigger missing or disabled' as problem
       where not exists (select 1 from pg_trigger where tgname = 'audit_log_no_change' and tgenabled = 'O')
      union all
      select 'truncate trigger missing or disabled'
       where not exists (select 1 from pg_trigger where tgname = 'audit_log_no_truncate' and tgenabled = 'O')
      union all
      select r || ' can ' || p || ' the audit log'
        from unnest(array['anon','authenticated']) r, unnest(array['INSERT','UPDATE','DELETE']) p
       where has_table_privilege(r, 'public.audit_log', p)
    ) problems;
    total := 3;
    snapshot := jsonb_build_object('problems', missing);
    detail := case when jsonb_array_length(missing) = 0 then 'Updates, deletes and truncation are blocked; no client can write to it'
                   else jsonb_array_length(missing) || ' protection gap(s)' end;
  elsif check_name = 'grc_analysts_have_mfa' then
    select coalesce(jsonb_agg(p.display_name order by p.display_name)
                    filter (where not exists (select 1 from auth.mfa_factors f where f.user_id = p.id and f.status = 'verified')), '[]'),
           count(*)
      into missing, total
      from public.profiles p where p.role = 'grc_analyst';
    snapshot := jsonb_build_object('grc_analysts', total, 'without_verified_mfa', missing);
    detail := format('%s of %s GRC analysts have verified MFA', total - jsonb_array_length(missing), total);
  else
    result := 'error'; detail := 'Unknown live check'; failing := '[]'; snapshot := '{}'; return;
  end if;
  failing := missing;
  result := case when total = 0 then 'error' when jsonb_array_length(missing) = 0 then 'pass' else 'fail' end;
  if total = 0 then detail := 'Nothing in scope to check'; end if;
end $$;


insert into public.controls (id, title, risk_reduced, risk_id, source_system, test_kind, rule, live_check, test_logic,
                             frequency_days, severity, owner_name, soc2, iso27001, status, approved_by_name, approved_at) values
  ('SB-04', 'No policy opens a table to everyone',
   'Turning RLS on isn''t enough: a policy of "true" or "any signed-in user" would still expose every row, the pattern behind CVE-2025-48757.', 'R-07', 'supabase', 'live', null, 'no_open_policies',
   'Live: no policy allows every row, only checks that someone is signed in, or applies to anonymous visitors, and anonymous visitors have no table rights', 1, 'critical', 'GRC', '{CC6.1,CC6.3}', '{A.5.15,A.8.3}', 'active', 'Jasmine Alexander (setup)', now());

commit;
