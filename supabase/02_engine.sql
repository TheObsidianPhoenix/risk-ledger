-- Risk Ledger, part 2 of 4: the test engine.
-- Control tests are declarative rules (JSON) evaluated by fixed, tested code.
-- A rule can only compare fields in collected evidence; it can never run SQL or
-- code. That's what makes it safe for an AI to draft one: the worst a bad draft
-- can do is fail validation or test the wrong thing, and a person approves every
-- rule before it runs.

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------
create function public.my_role() returns public.app_role
language sql stable security definer set search_path = public as $$
  select coalesce((select role from public.profiles where id = auth.uid()), 'pending'::public.app_role)
$$;

create function public.require_role(allowed public.app_role[]) returns void
language plpgsql stable security definer set search_path = public as $$
begin
  -- auth.uid() is null only for the database owner or the scheduler, never for a signed-in or anonymous API caller
  if auth.uid() is not null and not (public.my_role() = any(allowed)) then
    raise exception 'Your role (%) is not allowed to do this', public.my_role() using errcode = '42501';
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- Rule validation: the only rule shapes the engine accepts
-- ---------------------------------------------------------------------------
create function public.validate_rule(rule jsonb, source text) returns text
language plpgsql stable security definer set search_path = public as $$
declare
  t text := rule->>'type';
  allowed text[];
  k text;
  latest jsonb;
begin
  if rule is null or jsonb_typeof(rule) <> 'object' then return 'Rule must be a JSON object'; end if;
  allowed := case t
    when 'all_match'     then array['type','collection','where','field','equals']
    when 'none_match'    then array['type','collection','where','field','equals']
    when 'percent_match' then array['type','collection','where','field','equals','threshold']
    when 'within_days'   then array['type','collection','where','from_field','to_field','max_days']
    when 'max_age_days'  then array['type','collection','where','field','max_days']
    when 'before_date'   then array['type','collection','where','field','before_field']
  end;
  if allowed is null then return format('Unknown rule type "%s"', coalesce(t, 'missing')); end if;
  for k in select jsonb_object_keys(rule) loop
    if not k = any(allowed) then return format('Unexpected key "%s" for a %s rule', k, t); end if;
  end loop;
  if coalesce(rule->>'collection', '') !~ '^[a-z_]{1,40}$' then return 'collection must be a simple name'; end if;
  foreach k in array array['field','from_field','to_field','before_field'] loop
    if rule ? k and (rule->>k) !~ '^[a-z_]{1,40}$' then return format('%s must be a simple field name', k); end if;
  end loop;
  if t in ('all_match','none_match','percent_match','max_age_days','before_date') and not rule ? 'field' then return 'field is required'; end if;
  if t in ('all_match','none_match','percent_match') and not rule ? 'equals' then return 'equals is required'; end if;
  if rule ? 'equals' and jsonb_typeof(rule->'equals') not in ('string','number','boolean') then return 'equals must be a single value'; end if;
  if rule ? 'where' then
    if jsonb_typeof(rule->'where') <> 'object' then return 'where must be an object of field: value'; end if;
    for k in select jsonb_object_keys(rule->'where') loop
      if k !~ '^[a-z_]{1,40}$' or jsonb_typeof(rule->'where'->k) not in ('string','number','boolean') then
        return 'where may only match simple fields to single values';
      end if;
    end loop;
  end if;
  if t = 'percent_match' and not (jsonb_typeof(rule->'threshold') = 'number' and (rule->>'threshold')::numeric between 0 and 1) then
    return 'threshold must be a number between 0 and 1';
  end if;
  if t in ('within_days','max_age_days') and not (jsonb_typeof(rule->'max_days') = 'number' and (rule->>'max_days')::numeric between 0 and 3650) then
    return 'max_days must be a number of days between 0 and 3650';
  end if;
  if t = 'within_days' and not (rule ? 'from_field' and rule ? 'to_field') then return 'from_field and to_field are required'; end if;
  if t = 'before_date' and not rule ? 'before_field' then return 'before_field is required'; end if;
  -- The collection must exist in the latest evidence from that source: a draft can't invent data
  select data into latest from public.source_snapshots where system_id = source order by collected_at desc, id desc limit 1;
  if latest is null then return format('No evidence has been collected from %s yet', source); end if;
  if jsonb_typeof(latest -> (rule->>'collection')) is distinct from 'array' then
    return format('%s evidence has no collection called "%s"', source, rule->>'collection');
  end if;
  return null;   -- valid
end $$;

-- ---------------------------------------------------------------------------
-- Rule evaluation
-- ---------------------------------------------------------------------------
create function public.item_label(item jsonb) returns text
language sql immutable set search_path = public as $$
  select coalesce(item->>'id', item->>'name', item->>'email', item->>'app', left(item::text, 60))
$$;

create function public.evaluate_rule(rule jsonb, data jsonb, as_of timestamptz,
                                     out result text, out detail text, out failing jsonb)
language plpgsql stable set search_path = public as $$
declare
  items jsonb;
  bad jsonb;
  total int;
  ok int;
  t text := rule->>'type';
begin
  items := data -> (rule->>'collection');
  if items is null or jsonb_typeof(items) <> 'array' then
    result := 'error'; detail := 'The evidence has no collection called ' || coalesce(rule->>'collection', '?'); failing := '[]'; return;
  end if;
  select coalesce(jsonb_agg(i), '[]') into items
    from jsonb_array_elements(items) i where i @> coalesce(rule->'where', '{}'::jsonb);
  total := jsonb_array_length(items);

  if t = 'all_match' then
    select coalesce(jsonb_agg(public.item_label(i)), '[]') into bad
      from jsonb_array_elements(items) i where (i -> (rule->>'field')) is distinct from (rule->'equals');
  elsif t = 'none_match' then
    select coalesce(jsonb_agg(public.item_label(i)), '[]') into bad
      from jsonb_array_elements(items) i where (i -> (rule->>'field')) = (rule->'equals');
  elsif t = 'percent_match' then
    select coalesce(jsonb_agg(public.item_label(i)), '[]') into bad
      from jsonb_array_elements(items) i where (i -> (rule->>'field')) is distinct from (rule->'equals');
  elsif t = 'within_days' then
    select coalesce(jsonb_agg(public.item_label(i)), '[]') into bad
      from jsonb_array_elements(items) i
     where i->>(rule->>'to_field') is null
        or (i->>(rule->>'to_field'))::timestamptz - (i->>(rule->>'from_field'))::timestamptz
           > make_interval(days => (rule->>'max_days')::int);
  elsif t = 'max_age_days' then
    select coalesce(jsonb_agg(public.item_label(i)), '[]') into bad
      from jsonb_array_elements(items) i
     where i->>(rule->>'field') is null
        or (i->>(rule->>'field'))::timestamptz < as_of - make_interval(days => (rule->>'max_days')::int);
  elsif t = 'before_date' then
    select coalesce(jsonb_agg(public.item_label(i)), '[]') into bad
      from jsonb_array_elements(items) i
     where i->>(rule->>'field') is null
        or (i->>(rule->>'field'))::timestamptz > (i->>(rule->>'before_field'))::timestamptz;
  else
    result := 'error'; detail := 'Unknown rule type'; failing := '[]'; return;
  end if;

  failing := bad;
  ok := total - jsonb_array_length(bad);
  if total = 0 then
    -- Nothing in scope is suspicious: an empty population can hide a broken collector
    result := 'error'; detail := 'No items in scope; check that the collector is working'; return;
  end if;
  if t = 'percent_match' then
    result := case when ok::numeric / total >= (rule->>'threshold')::numeric then 'pass' else 'fail' end;
    detail := format('%s%% (%s of %s); threshold %s%%', round(100.0 * ok / total), ok, total,
                     round(100 * (rule->>'threshold')::numeric));
  else
    result := case when jsonb_array_length(bad) = 0 then 'pass' else 'fail' end;
    detail := format('%s of %s in scope meet the rule', ok, total);
  end if;
exception when others then
  -- Bad data (for example a date that isn't a date) is an error, never a pass
  result := 'error'; detail := 'The evidence could not be evaluated: ' || left(sqlerrm, 120); failing := '[]';
end $$;

-- ---------------------------------------------------------------------------
-- Live checks: read this Supabase database itself
-- ---------------------------------------------------------------------------
create function public.live_check(check_name text, out result text, out detail text, out failing jsonb, out snapshot jsonb)
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

-- ---------------------------------------------------------------------------
-- Running the tests
-- ---------------------------------------------------------------------------
create function public.sla_days(severity text) returns int
language sql immutable set search_path = public as $$
  select case severity when 'critical' then 7 when 'high' then 14 when 'medium' then 30 else 60 end
$$;

create function public.run_control_tests() returns bigint
language plpgsql volatile security definer set search_path = public as $$
declare
  run_id bigint;
  c record;
  snap record;
  live record;
  ev_id bigint;
  v_result text;
  v_detail text;
  v_failing jsonb;
  open_item record;
  n_pass int := 0; n_fail int := 0; n_err int := 0;
begin
  perform public.require_role(array['grc_analyst']::public.app_role[]);
  perform set_config('risk_ledger.engine', 'on', true);   -- lets the guards tell the engine from a person

  insert into public.test_runs (run_by) values (auth.uid()) returning id into run_id;

  for c in select * from public.controls where status = 'active' order by id loop
    if c.test_kind = 'rule' then
      select * into snap from public.source_snapshots
       where system_id = c.source_system order by collected_at desc, id desc limit 1;
      if snap.id is null then
        v_result := 'error'; v_detail := 'No evidence collected from this source yet'; v_failing := '[]';
      else
        select e.result, e.detail, e.failing into v_result, v_detail, v_failing
          from public.evaluate_rule(c.rule, snap.data, now()) e;
      end if;
      insert into public.evidence (control_id, test_run_id, source_system, snapshot_id, collected_at, result, detail, failing, rule, test_logic)
      values (c.id, run_id, c.source_system, snap.id, coalesce(snap.collected_at, now()), v_result, v_detail,
              coalesce(v_failing, '[]'), c.rule, c.test_logic)
      returning id into ev_id;
    else
      select * into live from public.live_check(c.live_check);
      insert into public.source_snapshots (system_id, data, is_mock) values (c.source_system, live.snapshot, false)
      returning * into snap;
      v_result := live.result; v_detail := live.detail; v_failing := live.failing;
      insert into public.evidence (control_id, test_run_id, source_system, snapshot_id, collected_at, result, detail, failing, test_logic)
      values (c.id, run_id, c.source_system, snap.id, snap.collected_at, v_result, v_detail, v_failing, c.test_logic)
      returning id into ev_id;
    end if;

    if v_result = 'pass' then n_pass := n_pass + 1;
    elsif v_result = 'fail' then n_fail := n_fail + 1;
    else n_err := n_err + 1; end if;

    select * into open_item from public.remediation
     where control_id = c.id and status in ('open', 'in_progress', 'risk_accepted')
     order by opened_at desc limit 1;

    if v_result = 'pass' and open_item.id is not null then
      -- Only evidence closes a remediation item
      update public.remediation
         set status = 'evidenced', resolved_at = now(), resolved_evidence_id = ev_id
       where id = open_item.id;
    elsif v_result = 'fail' then
      if open_item.id is null then
        insert into public.remediation (control_id, risk_id, failure_reason, severity, owner_id, owner_name, due_date, opened_evidence_id)
        values (c.id, c.risk_id, v_detail, c.severity, c.owner_id, c.owner_name,
                current_date + public.sla_days(c.severity), ev_id);
      elsif open_item.status = 'risk_accepted' and open_item.accepted_until < current_date then
        -- An expired exception turns back into open work
        update public.remediation set status = 'open', owner_note = owner_note || ' [Exception expired; reopened by test run ' || run_id || ']'
         where id = open_item.id;
      end if;
    end if;
  end loop;

  -- Risks follow their controls' latest results: ready to close only when every linked
  -- control's latest evidence passes. Closing a risk stays a human decision (close_risk).
  with latest as (
    select distinct on (control_id) control_id, result
      from public.evidence order by control_id, tested_at desc, id desc
  ), per_risk as (
    select k.risk_id, coalesce(bool_and(l.result = 'pass'), false) as all_pass
      from public.controls k left join latest l on l.control_id = k.id
     where k.status = 'active' and k.risk_id is not null
     group by k.risk_id
  )
  update public.risks r
     set status = case when p.all_pass then case when r.status in ('open', 'mitigating') then 'ready_to_close' else r.status end
                       else case when r.status in ('ready_to_close', 'closed') then 'open' else r.status end end,
         closed_at = case when not p.all_pass and r.status = 'closed' then null else r.closed_at end
    from per_risk p
   where p.risk_id = r.id and r.status <> 'accepted';

  update public.test_runs set tested = n_pass + n_fail + n_err, passed = n_pass, failed = n_fail, errors = n_err where id = run_id;
  return run_id;
end $$;

-- ---------------------------------------------------------------------------
-- Human decisions
-- ---------------------------------------------------------------------------
create function public.propose_control(
  p_id text, p_title text, p_risk_reduced text, p_source_system text, p_rule jsonb, p_test_logic text,
  p_risk_id text default null, p_severity text default 'medium', p_frequency_days int default 30,
  p_soc2 text[] default '{}', p_iso27001 text[] default '{}', p_drafted_by text default 'human')
returns text
language plpgsql volatile security definer set search_path = public as $$
declare problem text;
begin
  perform public.require_role(array['grc_analyst']::public.app_role[]);
  problem := public.validate_rule(p_rule, p_source_system);
  if problem is not null then raise exception 'Rule rejected: %', problem using errcode = '22023'; end if;
  insert into public.controls (id, title, risk_reduced, risk_id, source_system, test_kind, rule, test_logic,
                               severity, frequency_days, soc2, iso27001, status, drafted_by)
  values (p_id, p_title, p_risk_reduced, p_risk_id, p_source_system, 'rule', p_rule, p_test_logic,
          p_severity, p_frequency_days, p_soc2, p_iso27001, 'draft', p_drafted_by);
  return p_id;
end $$;

create function public.approve_control(p_id text) returns void
language plpgsql volatile security definer set search_path = public as $$
declare c record; problem text;
begin
  perform public.require_role(array['grc_analyst']::public.app_role[]);
  select * into c from public.controls where id = p_id for update;
  if c is null then raise exception 'No control %', p_id; end if;
  if c.status <> 'draft' then raise exception 'Only a draft can be approved (this one is %)', c.status; end if;
  if c.test_kind = 'rule' then
    problem := public.validate_rule(c.rule, c.source_system);
    if problem is not null then raise exception 'Rule rejected: %', problem using errcode = '22023'; end if;
  end if;
  perform set_config('risk_ledger.engine', 'on', true);
  update public.controls
     set status = 'active', approved_by = auth.uid(), approved_at = now(),
         approved_by_name = coalesce((select display_name from public.profiles where id = auth.uid()), 'system owner')
   where id = p_id;
end $$;

create function public.close_risk(p_id text, p_note text) returns void
language plpgsql volatile security definer set search_path = public as $$
declare r record;
begin
  perform public.require_role(array['grc_analyst']::public.app_role[]);
  select * into r from public.risks where id = p_id for update;
  if r is null then raise exception 'No risk %', p_id; end if;
  if r.status <> 'ready_to_close' then
    raise exception 'A risk can only be closed when its controls pass (it is %)', r.status;
  end if;
  if length(coalesce(trim(p_note), '')) < 10 then raise exception 'Write a closing note of at least 10 characters'; end if;
  perform set_config('risk_ledger.engine', 'on', true);
  update public.risks set status = 'closed', closed_at = now(), close_note = p_note where id = p_id;
end $$;

create function public.load_mock_snapshot(p_system text, p_data jsonb) returns bigint
language plpgsql volatile security definer set search_path = public as $$
declare new_id bigint;
begin
  perform public.require_role(array['grc_analyst']::public.app_role[]);
  if (select live from public.systems where id = p_system) is distinct from false then
    raise exception 'Mock evidence can only be loaded for mock systems';
  end if;
  insert into public.source_snapshots (system_id, data, is_mock) values (p_system, p_data, true) returning id into new_id;
  return new_id;
end $$;

-- Anyone allowed to read the audit log can check that nobody has altered it
create function public.verify_audit_chain(out rows_checked bigint, out first_broken_id bigint)
language plpgsql stable security definer set search_path = public as $$
declare a record; expected text := 'genesis';
begin
  perform public.require_role(array['grc_analyst', 'auditor']::public.app_role[]);
  rows_checked := 0;
  for a in select * from public.audit_log order by id loop
    rows_checked := rows_checked + 1;
    if a.prev_hash <> expected
       or a.hash <> encode(sha256(convert_to(a.prev_hash || '|' || a.id || '|' || extract(epoch from a.at) || '|' || coalesce(a.actor::text, '') || '|'
                                             || a.action || '|' || a.table_name || '|' || a.row_id || '|' || a.changes::text, 'UTF8')), 'hex') then
      first_broken_id := a.id;
      return;
    end if;
    expected := a.hash;
  end loop;
end $$;

-- Writes one row to the activity log: a sign-in, sign-out, page view or a record
-- opened. The only way the browser can write here; there is no insert grant on
-- the table itself, so a signed-in user can log their own activity and nothing else.
create function public.log_activity(p_action text, p_view text default null, p_detail text default null) returns void
language plpgsql volatile security definer set search_path = public as $$
begin
  if auth.uid() is null then return; end if;
  insert into public.activity_log (actor, actor_role, action, view, detail)
  values (auth.uid(), public.my_role()::text, p_action, p_view, p_detail);
end $$;

-- ---------------------------------------------------------------------------
-- Compliance agent: scans the HR/training roster for lapses within 30 days
-- and drafts a reminder (never sends anything on its own)
-- ---------------------------------------------------------------------------
create function public.draft_reminder_text(p_name text, p_reason text, p_due date, p_manager text)
returns table (subject text, body text)
language sql immutable set search_path = public as $$
  select
    case p_reason when 'security_training' then 'Action needed: your annual security training is due ' || p_due
                  else 'Action needed: your policy acknowledgment is due ' || p_due end,
    'Hi ' || p_name || ', our records show your '
      || case p_reason when 'security_training' then 'annual security training' else 'policy acknowledgment' end
      || ' is due on ' || p_due || '. Please complete it soon to stay in compliance. I''ve copied ' || p_manager
      || ' so they''re aware.' || E'\n\n' || '— Automated compliance reminder, drafted by Risk Ledger''s compliance agent. '
      || 'Nothing is sent until a GRC analyst reviews and approves it.'
$$;

create function public.scan_compliance_lapses() returns int
language plpgsql volatile security definer set search_path = public as $$
declare
  e record; t record; drafted int := 0;
begin
  perform public.require_role(array['grc_analyst', 'auditor']::public.app_role[]);
  for e in select * from public.employees where training_due_at <= current_date + 30 loop
    select * into t from public.draft_reminder_text(e.name, 'security_training', e.training_due_at, e.manager_name);
    insert into public.compliance_reminders (employee_id, reason, due_date, subject, body)
    values (e.id, 'security_training', e.training_due_at, t.subject, t.body)
    on conflict (employee_id, reason, due_date) do nothing;
    if found then drafted := drafted + 1; end if;
  end loop;
  for e in select * from public.employees where policy_ack_due_at <= current_date + 30 loop
    select * into t from public.draft_reminder_text(e.name, 'policy_ack', e.policy_ack_due_at, e.manager_name);
    insert into public.compliance_reminders (employee_id, reason, due_date, subject, body)
    values (e.id, 'policy_ack', e.policy_ack_due_at, t.subject, t.body)
    on conflict (employee_id, reason, due_date) do nothing;
    if found then drafted := drafted + 1; end if;
  end loop;
  -- The scan itself is logged (hash-chained) even when it drafts nothing, so there's
  -- audit evidence the check ran, not just evidence of what it found.
  perform public.log_activity('scan', 'compliance_agent', drafted || ' new reminder(s) drafted');
  return drafted;
end $$;

create function public.edit_compliance_reminder(p_id bigint, p_subject text, p_body text) returns void
language plpgsql volatile security definer set search_path = public as $$
declare r record;
begin
  perform public.require_role(array['grc_analyst', 'auditor']::public.app_role[]);
  select * into r from public.compliance_reminders where id = p_id for update;
  if r is null then raise exception 'No reminder %', p_id; end if;
  if r.status in ('sent', 'dismissed') then raise exception 'This reminder is already %, and can''t be edited', r.status; end if;
  update public.compliance_reminders
     set subject = p_subject, body = p_body, status = 'edited', updated_at = now()
   where id = p_id;
end $$;

create function public.send_compliance_reminder(p_id bigint) returns void
language plpgsql volatile security definer set search_path = public as $$
declare r record;
begin
  perform public.require_role(array['grc_analyst', 'auditor']::public.app_role[]);
  select * into r from public.compliance_reminders where id = p_id for update;
  if r is null then raise exception 'No reminder %', p_id; end if;
  if r.status in ('sent', 'dismissed') then raise exception 'This reminder is already %', r.status; end if;
  -- No email service is wired up: this is a simulated send, recorded as such, not a real email.
  update public.compliance_reminders set status = 'sent', sent_at = now(), sent_simulated = true where id = p_id;
end $$;

create function public.dismiss_compliance_reminder(p_id bigint) returns void
language plpgsql volatile security definer set search_path = public as $$
declare r record;
begin
  perform public.require_role(array['grc_analyst', 'auditor']::public.app_role[]);
  select * into r from public.compliance_reminders where id = p_id for update;
  if r is null then raise exception 'No reminder %', p_id; end if;
  if r.status in ('sent', 'dismissed') then raise exception 'This reminder is already %', r.status; end if;
  update public.compliance_reminders set status = 'dismissed', updated_at = now() where id = p_id;
end $$;

-- Anyone allowed to read the activity log can check that nobody has altered it
create function public.verify_activity_chain(out rows_checked bigint, out first_broken_id bigint)
language plpgsql stable security definer set search_path = public as $$
declare a record; expected text := 'genesis';
begin
  perform public.require_role(array['grc_analyst', 'auditor']::public.app_role[]);
  rows_checked := 0;
  for a in select * from public.activity_log order by id loop
    rows_checked := rows_checked + 1;
    if a.prev_hash <> expected
       or a.hash <> encode(sha256(convert_to(a.prev_hash || '|' || a.id || '|' || extract(epoch from a.at) || '|'
                                             || a.actor::text || '|' || a.action || '|' || coalesce(a.view, '')
                                             || '|' || coalesce(a.detail, ''), 'UTF8')), 'hex') then
      first_broken_id := a.id;
      return;
    end if;
    expected := a.hash;
  end loop;
end $$;
