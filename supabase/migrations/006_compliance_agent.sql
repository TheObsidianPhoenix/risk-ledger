-- Risk Ledger upgrade 006: a compliance agent that greets a GRC analyst or auditor
-- when they sign in, scans the HR/training roster for lapses within 30 days, and
-- drafts a reminder (to the employee, copying their manager) for a person to review,
-- edit or send. Nothing is sent automatically. Also: cross-team routing on controls,
-- so remediation that needs engineering or HR can be flagged as such, plus a new
-- vulnerability-scan control and system to demo it with.
--
-- Paste into the Supabase SQL Editor and click Run.
--
-- This project was first set up from supabase/setup.sql, which already creates
-- everything below for anyone installing from scratch today; this migration is
-- only for the already-running project, which needs it added on.

-- ---------------------------------------------------------------------------
-- 1. activity_log gets a new allowed action: 'scan' (the compliance agent's own
--    scan, logged even when it drafts nothing, so there's evidence the check ran)
-- ---------------------------------------------------------------------------
alter table public.activity_log drop constraint if exists activity_log_action_check;
alter table public.activity_log add constraint activity_log_action_check
  check (action in ('sign_in', 'sign_out', 'view', 'view_detail', 'scan'));

-- ---------------------------------------------------------------------------
-- 2. Cross-team routing: who gets looped in when a control's remediation needs
--    a team beyond its owner (shown as a labeled demo in the UI)
-- ---------------------------------------------------------------------------
alter table public.controls add column if not exists routes_to_team text
  check (routes_to_team in ('engineering', 'hr'));

-- A live vulnerability scanner would feed this; seed a mock one so the engineering
-- demo has something to show. Skipped if you already have a system with this id.
insert into public.systems (id, name, category, live, note)
  values ('vuln_mgmt', 'Vulnerability scanner', 'Engineering', false, 'Mock: shaped like a vulnerability scanner''s open-findings API')
  on conflict (id) do nothing;

insert into public.source_snapshots (system_id, collected_at, data)
  select 'vuln_mgmt', now(), jsonb_build_object('findings', jsonb_build_array(
    jsonb_build_object('id', 'VULN-2291', 'title', 'Outdated OpenSSL on web-03', 'severity', 'critical', 'open', true, 'opened_at', now() - interval '45 days'),
    jsonb_build_object('id', 'VULN-2297', 'title', 'Missing patch on build runner', 'severity', 'high', 'open', true, 'opened_at', now() - interval '10 days'),
    jsonb_build_object('id', 'VULN-2301', 'title', 'Deprecated TLS cipher on lb-02', 'severity', 'medium', 'open', false, 'opened_at', now() - interval '60 days')))
  where not exists (select 1 from public.source_snapshots where system_id = 'vuln_mgmt');

insert into public.controls (id, title, risk_reduced, risk_id, source_system, test_kind, rule, test_logic,
                             frequency_days, severity, owner_name, soc2, iso27001, routes_to_team, status, approved_by_name, approved_at)
  select 'ENG-01', 'Open vulnerability findings remediated within 30 days',
    'Known exploitable weaknesses don''t sit open long enough to be used against us.', null, 'vuln_mgmt', 'rule',
    '{"type":"max_age_days","collection":"findings","where":{"open":true},"field":"opened_at","max_days":30}',
    'Every open vulnerability finding is remediated within 30 days of being opened', 7, 'high', 'Platform Engineering', '{CC7.1}', '{A.8.8}', 'engineering', 'active', 'Jasmine Alexander (setup)', now()
  where not exists (select 1 from public.controls where id = 'ENG-01');

update public.controls set routes_to_team = 'hr' where id = 'CC-02' and routes_to_team is null;

-- ---------------------------------------------------------------------------
-- 3. The employee roster and the reminders the agent drafts
-- ---------------------------------------------------------------------------
create table if not exists public.employees (
  id               bigint generated always as identity primary key,
  name             text not null,
  email            text not null,
  manager_name     text not null,
  manager_email    text not null,
  department       text not null default '',
  training_due_at    date not null,
  policy_ack_due_at  date not null
);
comment on table public.employees is 'Mock HR/training roster the compliance agent scans. Fictional, like the other source data.';

create table if not exists public.compliance_reminders (
  id              bigint generated always as identity primary key,
  employee_id     bigint not null references public.employees(id),
  reason          text not null check (reason in ('security_training', 'policy_ack')),
  due_date        date not null,
  subject         text not null,
  body            text not null,
  status          text not null default 'drafted' check (status in ('drafted', 'edited', 'sent', 'dismissed')),
  drafted_by      text not null default 'ai' check (drafted_by in ('ai', 'human')),
  created_at      timestamptz not null default now(),
  updated_at      timestamptz,
  sent_at         timestamptz,
  sent_simulated  boolean not null default true,
  unique (employee_id, reason, due_date)
);
comment on table public.compliance_reminders is 'Drafted by the compliance agent when it signs someone in and finds a lapsing training or policy acknowledgment. A person always reviews before anything is "sent".';

-- Seed the roster only if it's empty, so this migration is safe to re-run.
insert into public.employees (name, email, manager_name, manager_email, department, training_due_at, policy_ack_due_at)
select * from (values
  ('Morgan Reyes',   'morgan.reyes@obsidianphoenix.example',   'Dana Whitfield', 'dana.whitfield@obsidianphoenix.example', 'Sales',       current_date - 4,  current_date + 70),
  ('Priya Natarajan','priya.natarajan@obsidianphoenix.example','Sam Okafor',     'sam.okafor@obsidianphoenix.example',     'Engineering', current_date + 12, current_date + 90),
  ('Diego Fernandez','diego.fernandez@obsidianphoenix.example','Dana Whitfield', 'dana.whitfield@obsidianphoenix.example', 'Sales',       current_date + 95, current_date + 21),
  ('Lena Kowalski',  'lena.kowalski@obsidianphoenix.example',  'Sam Okafor',     'sam.okafor@obsidianphoenix.example',     'Engineering', current_date + 120, current_date + 180),
  ('Theo Marchetti', 'theo.marchetti@obsidianphoenix.example', 'Ruth Abara',     'ruth.abara@obsidianphoenix.example',     'Finance',     current_date + 60, current_date + 150),
  ('Aisha Bello',    'aisha.bello@obsidianphoenix.example',    'Ruth Abara',     'ruth.abara@obsidianphoenix.example',     'Finance',     current_date + 150, current_date + 60)
) as v(name, email, manager_name, manager_email, department, training_due_at, policy_ack_due_at)
where not exists (select 1 from public.employees);

-- ---------------------------------------------------------------------------
-- 4. Functions: scan, draft text, edit, send (simulated), dismiss
-- ---------------------------------------------------------------------------
create or replace function public.draft_reminder_text(p_name text, p_reason text, p_due date, p_manager text)
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

create or replace function public.scan_compliance_lapses() returns int
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
  perform public.log_activity('scan', 'compliance_agent', drafted || ' new reminder(s) drafted');
  return drafted;
end $$;

create or replace function public.edit_compliance_reminder(p_id bigint, p_subject text, p_body text) returns void
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

create or replace function public.send_compliance_reminder(p_id bigint) returns void
language plpgsql volatile security definer set search_path = public as $$
declare r record;
begin
  perform public.require_role(array['grc_analyst', 'auditor']::public.app_role[]);
  select * into r from public.compliance_reminders where id = p_id for update;
  if r is null then raise exception 'No reminder %', p_id; end if;
  if r.status in ('sent', 'dismissed') then raise exception 'This reminder is already %', r.status; end if;
  update public.compliance_reminders set status = 'sent', sent_at = now(), sent_simulated = true where id = p_id;
end $$;

create or replace function public.dismiss_compliance_reminder(p_id bigint) returns void
language plpgsql volatile security definer set search_path = public as $$
declare r record;
begin
  perform public.require_role(array['grc_analyst', 'auditor']::public.app_role[]);
  select * into r from public.compliance_reminders where id = p_id for update;
  if r is null then raise exception 'No reminder %', p_id; end if;
  if r.status in ('sent', 'dismissed') then raise exception 'This reminder is already %', r.status; end if;
  update public.compliance_reminders set status = 'dismissed', updated_at = now() where id = p_id;
end $$;

-- ---------------------------------------------------------------------------
-- 5. Audit trail, RLS, and grants
-- ---------------------------------------------------------------------------
drop trigger if exists audit_compliance_reminders on public.compliance_reminders;
create trigger audit_compliance_reminders after insert or update on public.compliance_reminders
  for each row execute function public.audit();

alter table public.employees enable row level security;
alter table public.compliance_reminders enable row level security;

drop policy if exists "GRC and auditors read the employee roster" on public.employees;
create policy "GRC and auditors read the employee roster" on public.employees for select to authenticated
  using (public.my_role() in ('grc_analyst', 'auditor'));
drop policy if exists "GRC and auditors read compliance reminders" on public.compliance_reminders;
create policy "GRC and auditors read compliance reminders" on public.compliance_reminders for select to authenticated
  using (public.my_role() in ('grc_analyst', 'auditor'));

-- These tables didn't exist when "grant select on all tables" ran at initial setup,
-- and new tables get no default privileges, so these grants have to be explicit.
grant select on public.employees, public.compliance_reminders to authenticated;
grant execute on function
  public.scan_compliance_lapses(), public.edit_compliance_reminder(bigint, text, text),
  public.send_compliance_reminder(bigint), public.dismiss_compliance_reminder(bigint)
  to authenticated;

-- Check: both tables have RLS, the policies exist, and the new control is active
select 'employees RLS is ' || case when relrowsecurity then 'on' else 'OFF — something is wrong' end as check_1
  from pg_class where oid = 'public.employees'::regclass;
select 'compliance_reminders RLS is ' || case when relrowsecurity then 'on' else 'OFF — something is wrong' end as check_2
  from pg_class where oid = 'public.compliance_reminders'::regclass;
select policyname, tablename from pg_policies where tablename in ('employees', 'compliance_reminders');
select id, routes_to_team, status from public.controls where id in ('ENG-01', 'CC-02');
