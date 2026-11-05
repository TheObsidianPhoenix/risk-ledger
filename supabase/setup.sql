-- Risk Ledger setup: paste this whole file into the Supabase SQL Editor and click Run.
-- Built from supabase/01_schema.sql to 04_seed.sql. Runs as one transaction: all or nothing.
begin;

-- ===== supabase/01_schema.sql =====
-- Risk Ledger, part 1 of 4: tables.
-- Continuous control monitoring for Meridian Trust Labs (a fictional company).
-- Every row of source data is mock data, except the "supabase" system, whose
-- checks read this database itself.

-- ---------------------------------------------------------------------------
-- People and roles
-- ---------------------------------------------------------------------------
create type public.app_role as enum ('pending', 'grc_analyst', 'control_owner', 'auditor');

create table public.profiles (
  id           uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '',
  role         public.app_role not null default 'pending',   -- new sign-ups get no access
  created_at   timestamptz not null default now()
);
comment on table public.profiles is 'One row per signed-in user. Roles are assigned by the system owner in the SQL editor, never by the user.';

-- ---------------------------------------------------------------------------
-- Source systems and the evidence collected from them
-- ---------------------------------------------------------------------------
create table public.systems (
  id       text primary key check (id ~ '^[a-z_]{2,30}$'),
  name     text not null,
  category text not null,
  live     boolean not null default false,
  note     text not null default ''
);

create table public.source_snapshots (
  id           bigint generated always as identity primary key,
  system_id    text not null references public.systems(id),
  collected_at timestamptz not null default now(),
  data         jsonb not null check (jsonb_typeof(data) = 'object'),
  is_mock      boolean not null default true
);
comment on table public.source_snapshots is 'What a collector pulled from a source system at a point in time. Mock data for every system except supabase.';

-- ---------------------------------------------------------------------------
-- Risks, controls, evidence, remediation
-- ---------------------------------------------------------------------------
create table public.risks (
  id          text primary key check (id ~ '^R-[0-9]{2,3}$'),
  title       text not null,
  description text not null default '',
  likelihood  int  not null check (likelihood between 1 and 5),
  impact      int  not null check (impact between 1 and 5),
  score       int  generated always as (likelihood * impact) stored,
  owner_name  text not null default '',
  status      text not null default 'open'
              check (status in ('open', 'mitigating', 'ready_to_close', 'accepted', 'closed')),
  treatment   text not null default '',
  due_date    date,
  opened_at   timestamptz not null default now(),
  closed_at   timestamptz,
  close_note  text not null default '',
  sample_history boolean not null default false
);
comment on column public.risks.sample_history is 'True for the fictional closed risks that give the trend chart a past. Shown as sample history.';

create table public.controls (
  id             text primary key check (id ~ '^[A-Z]{2,4}-[0-9]{2,3}$'),
  title          text not null,
  risk_reduced   text not null,                       -- "how does this actually lower risk?"
  risk_id        text references public.risks(id),
  source_system  text not null references public.systems(id),
  test_kind      text not null check (test_kind in ('rule', 'live')),
  rule           jsonb,                               -- a declarative rule, never code
  live_check     text check (live_check in ('rls_on_all_tables', 'audit_log_protected', 'grc_analysts_have_mfa')),
  test_logic     text not null default '',            -- the rule in plain English, for the evidence viewer
  frequency_days int  not null default 30 check (frequency_days between 1 and 365),
  severity       text not null default 'medium' check (severity in ('low', 'medium', 'high', 'critical')),
  owner_id       uuid references public.profiles(id),
  owner_name     text not null default '',
  soc2           text[] not null default '{}',
  iso27001       text[] not null default '{}',
  status         text not null default 'draft' check (status in ('draft', 'active', 'retired')),
  drafted_by     text not null default 'human' check (drafted_by in ('human', 'ai')),
  approved_by    uuid references public.profiles(id),
  approved_by_name text not null default '',
  approved_at    timestamptz,
  created_at     timestamptz not null default now(),
  check ((test_kind = 'rule' and rule is not null and live_check is null)
      or (test_kind = 'live' and live_check is not null and rule is null)),
  check (status <> 'active' or approved_at is not null)   -- nothing runs without a person's approval
);

create table public.test_runs (
  id          bigint generated always as identity primary key,
  started_at  timestamptz not null default now(),
  run_by      uuid references public.profiles(id),     -- null when run by the scheduler
  tested      int not null default 0,
  passed      int not null default 0,
  failed      int not null default 0,
  errors      int not null default 0
);

create table public.evidence (
  id            bigint generated always as identity primary key,
  control_id    text not null references public.controls(id),
  test_run_id   bigint not null references public.test_runs(id),
  source_system text not null references public.systems(id),
  snapshot_id   bigint references public.source_snapshots(id),
  collected_at  timestamptz not null,
  tested_at     timestamptz not null default now(),
  result        text not null check (result in ('pass', 'fail', 'error')),
  detail        text not null,
  failing       jsonb not null default '[]'::jsonb,   -- identifiers of the items that failed
  rule          jsonb,                                -- the exact rule that was run
  test_logic    text not null default ''
);
comment on table public.evidence is 'Written only by the test engine, never edited or deleted.';

create table public.remediation (
  id                   bigint generated always as identity primary key,
  control_id           text not null references public.controls(id),
  risk_id              text references public.risks(id),
  failure_reason       text not null,
  severity             text not null check (severity in ('low', 'medium', 'high', 'critical')),
  owner_id             uuid references public.profiles(id),
  owner_name           text not null default '',
  due_date             date not null,
  status               text not null default 'open'
                       check (status in ('open', 'in_progress', 'evidenced', 'risk_accepted')),
  accepted_until       date,
  owner_note           text not null default '' check (length(owner_note) <= 1000),
  opened_at            timestamptz not null default now(),
  opened_evidence_id   bigint references public.evidence(id),
  resolved_at          timestamptz,
  resolved_evidence_id bigint references public.evidence(id),
  check (status <> 'risk_accepted' or accepted_until is not null)
);
comment on column public.remediation.status is 'Only passing evidence can set "evidenced": nobody can mark a fix done by hand.';

-- ---------------------------------------------------------------------------
-- Audit log: append-only, hash-chained
-- ---------------------------------------------------------------------------
create table public.audit_log (
  id         bigint generated always as identity primary key,
  at         timestamptz not null default clock_timestamp(),
  actor      uuid,
  actor_role text not null,
  action     text not null,
  table_name text not null,
  row_id     text not null,
  changes    jsonb not null default '{}'::jsonb,
  prev_hash  text not null,
  hash       text not null
);
comment on table public.audit_log is 'Every change to the ledger. Triggers block updates, deletes and truncation; each row carries a hash of the one before it.';

create index on public.evidence (control_id, tested_at desc);
create index on public.remediation (control_id) where status in ('open', 'in_progress', 'risk_accepted');
create index on public.source_snapshots (system_id, collected_at desc);

-- ===== supabase/02_engine.sql =====
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

-- ===== supabase/03_security.sql =====
-- Risk Ledger, part 3 of 4: security.
-- Row Level Security on every table, least-privilege grants, guard triggers that
-- enforce the workflow rules, and the append-only audit log.

-- ---------------------------------------------------------------------------
-- New users get a profile with no access until the system owner assigns a role
-- ---------------------------------------------------------------------------
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, display_name)
  values (new.id, coalesce(nullif(new.raw_user_meta_data->>'display_name', ''), split_part(coalesce(new.email, ''), '@', 1)));
  return new;
end $$;

create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------------------------------------------------------------------------
-- Audit log: every change, hash-chained, impossible to edit
-- ---------------------------------------------------------------------------
create function public.audit_chain() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  perform pg_advisory_xact_lock(424242);   -- one writer at a time, so the chain has no forks
  new.prev_hash := coalesce((select hash from public.audit_log order by id desc limit 1), 'genesis');
  new.hash := encode(sha256(convert_to(new.prev_hash || '|' || new.id || '|' || extract(epoch from new.at) || '|'
                                       || coalesce(new.actor::text, '') || '|' || new.action || '|' || new.table_name
                                       || '|' || new.row_id || '|' || new.changes::text, 'UTF8')), 'hex');
  return new;
end $$;

create trigger audit_log_chain before insert on public.audit_log
  for each row execute function public.audit_chain();

create function public.audit_log_block() returns trigger
language plpgsql set search_path = public as $$
begin
  raise exception 'The audit log is append-only: % is not allowed', tg_op using errcode = '42501';
end $$;

create trigger audit_log_no_change before update or delete on public.audit_log
  for each row execute function public.audit_log_block();
create trigger audit_log_no_truncate before truncate on public.audit_log
  for each statement execute function public.audit_log_block();

create function public.audit() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  diff jsonb := '{}'::jsonb;
  k text;
  rec jsonb;
begin
  if tg_op = 'UPDATE' then
    for k in select jsonb_object_keys(to_jsonb(new)) loop
      if to_jsonb(new) -> k is distinct from to_jsonb(old) -> k then
        diff := diff || jsonb_build_object(k, jsonb_build_object('from', to_jsonb(old) -> k, 'to', to_jsonb(new) -> k));
      end if;
    end loop;
    if diff = '{}'::jsonb then return new; end if;
    rec := to_jsonb(new);
  elsif tg_op = 'INSERT' then
    rec := to_jsonb(new);
    diff := rec - array['data', 'failing', 'rule'];   -- keep the log readable; the full rows live in their tables
  else
    rec := to_jsonb(old);
    diff := rec;
  end if;
  insert into public.audit_log (actor, actor_role, action, table_name, row_id, changes)
  values (auth.uid(),
          case when auth.uid() is null then 'system' else public.my_role()::text end
            || case when current_setting('risk_ledger.engine', true) = 'on' then ' via engine' else '' end,
          lower(tg_op), tg_table_name, rec ->> 'id', diff);
  return coalesce(new, old);
end $$;

create trigger audit_risks after insert or update or delete on public.risks for each row execute function public.audit();
create trigger audit_controls after insert or update or delete on public.controls for each row execute function public.audit();
create trigger audit_remediation after insert or update or delete on public.remediation for each row execute function public.audit();
create trigger audit_profiles after insert or update or delete on public.profiles for each row execute function public.audit();
create trigger audit_evidence after insert on public.evidence for each row execute function public.audit();
create trigger audit_test_runs after insert on public.test_runs for each row execute function public.audit();

-- ---------------------------------------------------------------------------
-- Evidence and snapshots can't be changed once written
-- ---------------------------------------------------------------------------
create function public.block_change() returns trigger
language plpgsql set search_path = public as $$
begin
  raise exception '% rows are permanent: % is not allowed', tg_table_name, tg_op using errcode = '42501';
end $$;

create trigger evidence_permanent before update or delete on public.evidence
  for each row execute function public.block_change();
create trigger snapshots_permanent before update or delete on public.source_snapshots
  for each row execute function public.block_change();

-- ---------------------------------------------------------------------------
-- Workflow guards
-- ---------------------------------------------------------------------------
create function public.remediation_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare engine boolean := current_setting('risk_ledger.engine', true) = 'on';
begin
  if engine then return new; end if;
  if new.status = 'evidenced' and old.status <> 'evidenced' then
    raise exception 'Only passing evidence can close a remediation item' using errcode = '42501';
  end if;
  if old.status = 'evidenced' then
    raise exception 'This item was closed by evidence and can''t be reopened by hand' using errcode = '42501';
  end if;
  if public.my_role() = 'control_owner' then
    if new.status not in ('open', 'in_progress') or new.accepted_until is distinct from old.accepted_until then
      raise exception 'Control owners can update progress and notes only' using errcode = '42501';
    end if;
  end if;
  if new.status = 'risk_accepted' then
    if new.accepted_until is null or new.accepted_until > current_date + 180 then
      raise exception 'A risk acceptance needs an end date within 180 days' using errcode = '22023';
    end if;
    if length(coalesce(trim(new.owner_note), '')) < 10 then
      raise exception 'Write why the risk is accepted (at least 10 characters)' using errcode = '22023';
    end if;
  end if;
  return new;
end $$;

create trigger remediation_rules before update on public.remediation
  for each row execute function public.remediation_guard();

create function public.risks_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if current_setting('risk_ledger.engine', true) = 'on' then return new; end if;
  if new.status in ('closed', 'ready_to_close') and new.status is distinct from old.status then
    raise exception 'Use close_risk: a risk closes only after its controls pass' using errcode = '42501';
  end if;
  if new.status = 'accepted' and length(coalesce(trim(new.treatment), '')) < 10 then
    raise exception 'Describe the acceptance in treatment (at least 10 characters)' using errcode = '22023';
  end if;
  return new;
end $$;

create trigger risks_rules before update on public.risks
  for each row execute function public.risks_guard();

create function public.controls_guard() returns trigger
language plpgsql set search_path = public as $$
begin
  if current_setting('risk_ledger.engine', true) = 'on' then return new; end if;
  if tg_op = 'INSERT' and new.status <> 'draft' and auth.uid() is not null then
    raise exception 'New controls start as drafts' using errcode = '42501';
  end if;
  if tg_op = 'UPDATE' and new.status = 'active' and old.status <> 'active' then
    raise exception 'Use approve_control to activate a control' using errcode = '42501';
  end if;
  if tg_op = 'UPDATE' and old.status = 'active' and new.rule is distinct from old.rule then
    raise exception 'An active control''s rule can''t change; retire it and approve a new draft' using errcode = '42501';
  end if;
  return new;
end $$;

create trigger controls_rules before insert or update on public.controls
  for each row execute function public.controls_guard();

-- ---------------------------------------------------------------------------
-- Views (run with the caller's permissions, so Row Level Security applies)
-- ---------------------------------------------------------------------------
create view public.control_status with (security_invoker = true) as
select c.id, c.title, c.risk_reduced, c.risk_id, c.source_system, s.name as source_name, s.live as source_live,
       c.test_kind, c.test_logic, c.severity, c.owner_name, c.soc2, c.iso27001, c.status, c.drafted_by,
       c.approved_by_name, c.approved_at, c.frequency_days,
       e.result as last_result, e.detail as last_detail, e.tested_at as last_tested,
       e.tested_at + make_interval(days => c.frequency_days) as next_test_due
  from public.controls c
  join public.systems s on s.id = c.source_system
  left join lateral (select * from public.evidence v where v.control_id = c.id order by v.tested_at desc, v.id desc limit 1) e on true;

create view public.risk_trend with (security_invoker = true) as
select d::date as day,
       (select count(*) from public.risks r
         where r.opened_at::date <= d::date and (r.closed_at is null or r.closed_at::date > d::date)) as open_risks
  from generate_series(current_date - 29, current_date, interval '1 day') d;

-- ---------------------------------------------------------------------------
-- Row Level Security: every table, deny by default
-- ---------------------------------------------------------------------------
alter table public.profiles enable row level security;
alter table public.systems enable row level security;
alter table public.source_snapshots enable row level security;
alter table public.risks enable row level security;
alter table public.controls enable row level security;
alter table public.test_runs enable row level security;
alter table public.evidence enable row level security;
alter table public.remediation enable row level security;
alter table public.audit_log enable row level security;

create policy "see yourself; GRC and auditors see everyone" on public.profiles for select to authenticated
  using (id = auth.uid() or public.my_role() in ('grc_analyst', 'auditor'));

create policy "signed-in members read systems" on public.systems for select to authenticated
  using (public.my_role() <> 'pending');
create policy "GRC and auditors read raw evidence" on public.source_snapshots for select to authenticated
  using (public.my_role() in ('grc_analyst', 'auditor'));
create policy "members read risks" on public.risks for select to authenticated
  using (public.my_role() <> 'pending');
create policy "GRC updates risks" on public.risks for update to authenticated
  using (public.my_role() = 'grc_analyst') with check (public.my_role() = 'grc_analyst');
create policy "members read controls" on public.controls for select to authenticated
  using (public.my_role() <> 'pending');
create policy "members read test runs" on public.test_runs for select to authenticated
  using (public.my_role() <> 'pending');
create policy "GRC and auditors read evidence; owners read their own" on public.evidence for select to authenticated
  using (public.my_role() in ('grc_analyst', 'auditor')
         or exists (select 1 from public.controls c where c.id = control_id and c.owner_id = auth.uid()));
create policy "GRC and auditors read remediation; owners read their own" on public.remediation for select to authenticated
  using (public.my_role() in ('grc_analyst', 'auditor') or owner_id = auth.uid());
create policy "GRC updates remediation; owners update their own" on public.remediation for update to authenticated
  using (public.my_role() = 'grc_analyst' or (public.my_role() = 'control_owner' and owner_id = auth.uid()))
  with check (public.my_role() = 'grc_analyst' or (public.my_role() = 'control_owner' and owner_id = auth.uid()));
create policy "GRC and auditors read the audit log" on public.audit_log for select to authenticated
  using (public.my_role() in ('grc_analyst', 'auditor'));

-- ---------------------------------------------------------------------------
-- Grants: nothing for anonymous visitors; read-only for signed-in users, except
-- the few columns people may change. Every other change goes through a function.
-- ---------------------------------------------------------------------------
revoke all on all tables in schema public from anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;
grant select on all tables in schema public to authenticated;
grant update (status, owner_note, accepted_until) on public.remediation to authenticated;
grant update (status, treatment, due_date, owner_name, likelihood, impact) on public.risks to authenticated;

revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function public.my_role(), public.run_control_tests(), public.approve_control(text),
  public.close_risk(text, text), public.load_mock_snapshot(text, jsonb), public.verify_audit_chain(),
  public.validate_rule(jsonb, text),
  public.propose_control(text, text, text, text, jsonb, text, text, text, int, text[], text[], text)
  to authenticated;

-- Keep future objects closed by default, too
alter default privileges in schema public revoke all on tables from anon, authenticated;
alter default privileges in schema public revoke execute on functions from public, anon, authenticated;

-- ===== supabase/04_seed.sql =====
-- Risk Ledger, part 4 of 4: starting data for Meridian Trust Labs (fictional).
-- Source data is MOCK data shaped like what real collectors return from each
-- system's API. The "supabase" system is LIVE: its checks read this database.
-- Dates are relative to the moment this runs, so the demo stays current.

insert into public.systems (id, name, category, live, note) values
  ('aws',              'Amazon Web Services', 'Cloud',            false, 'Mock: shaped like S3 and CloudTrail API responses'),
  ('gcp',              'Google Cloud',        'Cloud',            false, 'Mock: shaped like Cloud Storage and Cloud Audit Logs responses'),
  ('okta',             'Okta',                'Identity',         false, 'Mock: shaped like the Okta Users and Factors APIs'),
  ('google_workspace', 'Google Workspace',    'Identity',         false, 'Mock: application access review records'),
  ('hris',             'HR system',           'People',           false, 'Mock: terminations with access-removal times'),
  ('lms',              'Security training',   'People',           false, 'Mock: training completion by employee'),
  ('vendor_mgmt',      'Vendor management',   'Third parties',    false, 'Mock: vendor reviews and renewal dates'),
  ('supabase',         'Supabase (this project)', 'Platform',     true,  'Live: read directly from this database');

insert into public.source_snapshots (system_id, collected_at, data) values
('okta', now(), jsonb_build_object('users', jsonb_build_array(
  jsonb_build_object('id', 'okta-001', 'email', 'admin.ops@meridian.example', 'privileged', true,  'mfa_enabled', true),
  jsonb_build_object('id', 'okta-002', 'email', 'it.lead@meridian.example',   'privileged', true,  'mfa_enabled', true),
  jsonb_build_object('id', 'okta-003', 'email', 'sre.oncall@meridian.example','privileged', true,  'mfa_enabled', true),
  jsonb_build_object('id', 'okta-004', 'email', 'analyst@meridian.example',   'privileged', false, 'mfa_enabled', false),
  jsonb_build_object('id', 'okta-005', 'email', 'sales.rep@meridian.example', 'privileged', false, 'mfa_enabled', true)))),
('hris', now(), jsonb_build_object('terminations', jsonb_build_array(
  jsonb_build_object('id', 'term-101', 'name', 'Former employee A', 'terminated_at', now() - interval '40 days', 'access_removed_at', now() - interval '40 days' + interval '3 hours'),
  jsonb_build_object('id', 'term-102', 'name', 'Former employee B', 'terminated_at', now() - interval '21 days', 'access_removed_at', now() - interval '18 days'),
  jsonb_build_object('id', 'term-103', 'name', 'Former contractor C', 'terminated_at', now() - interval '6 days',  'access_removed_at', now() - interval '6 days' + interval '20 hours')))),
('aws', now(), jsonb_build_object(
  'buckets', jsonb_build_array(
    jsonb_build_object('name', 'meridian-prod-customer-data', 'encrypted', true, 'encryption', 'aws:kms'),
    jsonb_build_object('name', 'meridian-prod-backups',       'encrypted', true, 'encryption', 'aws:kms'),
    jsonb_build_object('name', 'meridian-logs',               'encrypted', true, 'encryption', 'AES256')),
  'trails', jsonb_build_array(
    jsonb_build_object('name', 'org-trail', 'critical', true, 'logging_enabled', true),
    jsonb_build_object('name', 'sandbox-trail', 'critical', false, 'logging_enabled', false)))),
('gcp', now(), jsonb_build_object('buckets', jsonb_build_array(
  jsonb_build_object('name', 'meridian-analytics-exports', 'public', false),
  jsonb_build_object('name', 'meridian-marketing-assets',  'public', true),
  jsonb_build_object('name', 'meridian-ml-training',       'public', false)))),
('google_workspace', now(), jsonb_build_object('access_reviews', jsonb_build_array(
  jsonb_build_object('app', 'Production AWS',  'last_reviewed_at', now() - interval '35 days'),
  jsonb_build_object('app', 'Okta admin',      'last_reviewed_at', now() - interval '61 days'),
  jsonb_build_object('app', 'Billing system',  'last_reviewed_at', now() - interval '124 days'),
  jsonb_build_object('app', 'Customer support', 'last_reviewed_at', now() - interval '12 days')))),
('lms', now(), jsonb_build_object('employees',
  (select jsonb_agg(jsonb_build_object('id', 'emp-' || lpad(g::text, 3, '0'), 'active', true, 'training_complete', g > 4))
     from generate_series(1, 50) g))),
('vendor_mgmt', now(), jsonb_build_object('vendors', jsonb_build_array(
  jsonb_build_object('name', 'Payroll provider', 'critical', true,  'review_completed_at', now() - interval '20 days', 'renewal_date', now() + interval '45 days'),
  jsonb_build_object('name', 'Cloud email',      'critical', true,  'review_completed_at', now() - interval '80 days', 'renewal_date', now() - interval '10 days'),
  jsonb_build_object('name', 'Design tool',      'critical', false, 'review_completed_at', null,                       'renewal_date', now() + interval '20 days'))));

-- Risks: each says what could go wrong. sample_history rows give the trend chart a past.
insert into public.risks (id, title, description, likelihood, impact, owner_name, status, treatment, opened_at) values
  ('R-01', 'An administrator account is taken over', 'Stolen credentials on a privileged account would give an attacker control of production and identity systems.', 3, 5, 'IT', 'open', 'Require phishing-resistant MFA for every privileged account', now() - interval '28 days'),
  ('R-02', 'People keep access after they leave or change roles', 'Former staff or stale permissions could be used to reach customer data.', 3, 4, 'IT and HR', 'open', 'Same-day deprovisioning; quarterly access reviews', now() - interval '25 days'),
  ('R-03', 'Customer data is exposed from cloud storage', 'A public or unencrypted bucket could leak data without any attack.', 2, 5, 'Platform Engineering', 'open', 'Block public access; encrypt every bucket', now() - interval '22 days'),
  ('R-04', 'Malicious activity goes unnoticed', 'Without logs on critical systems, an incident can''t be detected or investigated.', 2, 4, 'Security Engineering', 'open', 'Logging on every critical system; protected audit trail', now() - interval '20 days'),
  ('R-05', 'Staff fall for phishing or social engineering', 'Untrained staff are the most common way attackers get in.', 4, 3, 'Security', 'open', 'Annual security training with a 95% completion target', now() - interval '18 days'),
  ('R-06', 'A vendor breach exposes our data', 'A critical vendor renewed without a current security review could carry unknown risk.', 2, 4, 'GRC', 'open', 'Review critical vendors before every renewal', now() - interval '15 days'),
  ('R-07', 'One user reads another team''s records', 'Missing database access rules would let any signed-in user read everything.', 2, 4, 'GRC', 'open', 'Row Level Security on every table', now() - interval '10 days');

insert into public.risks (id, title, description, likelihood, impact, owner_name, status, treatment, opened_at, closed_at, close_note, sample_history) values
  ('R-08', 'Laptops without disk encryption', 'Sample history.', 2, 3, 'IT', 'closed', 'Enforced through device management', now() - interval '29 days', now() - interval '21 days', 'Sample history: evidence showed 100% of laptops encrypted.', true),
  ('R-09', 'Shared admin password in a spreadsheet', 'Sample history.', 3, 4, 'IT', 'closed', 'Moved to the password manager', now() - interval '29 days', now() - interval '16 days', 'Sample history: credential rotated and spreadsheet deleted.', true),
  ('R-10', 'Backups never restore-tested', 'Sample history.', 2, 4, 'Platform Engineering', 'closed', 'Quarterly restore test', now() - interval '27 days', now() - interval '9 days', 'Sample history: restore test passed and documented.', true),
  ('R-11', 'Unreviewed open-source licenses', 'Sample history.', 2, 2, 'Engineering', 'closed', 'License scanning in CI', now() - interval '26 days', now() - interval '5 days', 'Sample history: scanner added to every pull request.', true);

-- Controls: the test, how it lowers risk, and where the evidence comes from.
-- Approved at setup by the system owner; anything added later starts as a draft.
insert into public.controls (id, title, risk_reduced, risk_id, source_system, test_kind, rule, live_check, test_logic,
                             frequency_days, severity, owner_name, soc2, iso27001, status, approved_by_name, approved_at) values
  ('CC-01', 'MFA enforced for privileged users',
   'A stolen password alone can''t take over an admin account.', 'R-01', 'okta', 'rule',
   '{"type":"all_match","collection":"users","where":{"privileged":true},"field":"mfa_enabled","equals":true}', null,
   'Every Okta user marked privileged has MFA enabled', 7, 'critical', 'IT', '{CC6.1}', '{A.8.5}', 'active', 'Jasmine Alexander (setup)', now()),
  ('CC-02', 'Access removed within 1 day of termination',
   'Shrinks the window in which a former employee could still log in.', 'R-02', 'hris', 'rule',
   '{"type":"within_days","collection":"terminations","from_field":"terminated_at","to_field":"access_removed_at","max_days":1}', null,
   'Every termination has access removed no more than 1 day later', 7, 'high', 'IT', '{CC6.2}', '{A.5.18,A.6.5}', 'active', 'Jasmine Alexander (setup)', now()),
  ('CC-03', 'Cloud storage encryption enabled',
   'Stolen storage media or snapshots are unreadable.', 'R-03', 'aws', 'rule',
   '{"type":"all_match","collection":"buckets","field":"encrypted","equals":true}', null,
   'Every AWS bucket has default encryption', 30, 'high', 'Platform Engineering', '{CC6.1}', '{A.8.24}', 'active', 'Jasmine Alexander (setup)', now()),
  ('CC-04', 'Public storage buckets prohibited',
   'Data can''t leak just because someone made a bucket public.', 'R-03', 'gcp', 'rule',
   '{"type":"none_match","collection":"buckets","field":"public","equals":true}', null,
   'No Google Cloud bucket is public', 1, 'critical', 'Platform Engineering', '{CC6.1,CC6.6}', '{A.8.3}', 'active', 'Jasmine Alexander (setup)', now()),
  ('CC-05', 'Logging enabled for critical systems',
   'Incidents on critical systems can be detected and investigated.', 'R-04', 'aws', 'rule',
   '{"type":"all_match","collection":"trails","where":{"critical":true},"field":"logging_enabled","equals":true}', null,
   'Every critical AWS trail is logging', 7, 'high', 'Security Engineering', '{CC7.2}', '{A.8.15}', 'active', 'Jasmine Alexander (setup)', now()),
  ('CC-06', 'User access reviewed every 90 days',
   'Stale access is found and removed before someone misuses it.', 'R-02', 'google_workspace', 'rule',
   '{"type":"max_age_days","collection":"access_reviews","field":"last_reviewed_at","max_days":90}', null,
   'Every in-scope application had an access review in the last 90 days', 30, 'medium', 'IT', '{CC6.2,CC6.3}', '{A.5.18}', 'active', 'Jasmine Alexander (setup)', now()),
  ('CC-07', 'Security training completion at least 95%',
   'Fewer people click the phishing link that starts most breaches.', 'R-05', 'lms', 'rule',
   '{"type":"percent_match","collection":"employees","where":{"active":true},"field":"training_complete","equals":true,"threshold":0.95}', null,
   'At least 95% of active employees completed security training', 30, 'medium', 'People Ops', '{CC1.4,CC2.2}', '{A.6.3}', 'active', 'Jasmine Alexander (setup)', now()),
  ('CC-08', 'Critical vendors reviewed before renewal',
   'We never commit another year to a vendor whose security we haven''t checked.', 'R-06', 'vendor_mgmt', 'rule',
   '{"type":"before_date","collection":"vendors","where":{"critical":true},"field":"review_completed_at","before_field":"renewal_date"}', null,
   'Every critical vendor''s review was completed before its renewal date', 30, 'medium', 'GRC', '{CC9.2}', '{A.5.19,A.5.22}', 'active', 'Jasmine Alexander (setup)', now()),
  ('SB-01', 'Row Level Security on every table',
   'A signed-in user can only reach the rows a policy allows, even if the app has a bug.', 'R-07', 'supabase', 'live', null, 'rls_on_all_tables',
   'Live: every table in the public schema has Row Level Security enabled', 1, 'critical', 'GRC', '{CC6.1}', '{A.8.3}', 'active', 'Jasmine Alexander (setup)', now()),
  ('SB-02', 'Audit log can''t be altered',
   'The record of who did what survives even a mistake or a malicious insider.', 'R-04', 'supabase', 'live', null, 'audit_log_protected',
   'Live: the audit log blocks updates, deletes and truncation, and no client can write to it', 1, 'high', 'GRC', '{CC7.2}', '{A.8.15}', 'active', 'Jasmine Alexander (setup)', now()),
  ('SB-03', 'GRC analysts use MFA',
   'The people who can approve tests and close risks can''t be impersonated with a password alone.', 'R-01', 'supabase', 'live', null, 'grc_analysts_have_mfa',
   'Live: every user with the GRC analyst role has a verified MFA factor', 1, 'critical', 'GRC', '{CC6.1}', '{A.8.5}', 'active', 'Jasmine Alexander (setup)', now());

commit;
