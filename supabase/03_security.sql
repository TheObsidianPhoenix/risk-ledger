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

-- ---------------------------------------------------------------------------
-- Activity log: its own hash chain, independent of audit_log's, written only
-- through log_activity() below (never a direct insert from the client)
-- ---------------------------------------------------------------------------
create function public.activity_chain() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  perform pg_advisory_xact_lock(424243);   -- a different lock number: its own chain, its own writer lock
  new.prev_hash := coalesce((select hash from public.activity_log order by id desc limit 1), 'genesis');
  new.hash := encode(sha256(convert_to(new.prev_hash || '|' || new.id || '|' || extract(epoch from new.at) || '|'
                                       || new.actor::text || '|' || new.action || '|' || coalesce(new.view, '')
                                       || '|' || coalesce(new.detail, ''), 'UTF8')), 'hex');
  return new;
end $$;

create trigger activity_log_chain before insert on public.activity_log
  for each row execute function public.activity_chain();

create function public.activity_log_block() returns trigger
language plpgsql set search_path = public as $$
begin
  raise exception 'The activity log is append-only: % is not allowed', tg_op using errcode = '42501';
end $$;

create trigger activity_log_no_change before update or delete on public.activity_log
  for each row execute function public.activity_log_block();
create trigger activity_log_no_truncate before truncate on public.activity_log
  for each statement execute function public.activity_log_block();

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
alter table public.activity_log enable row level security;

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

create policy "GRC and auditors read the activity log" on public.activity_log for select to authenticated
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
  public.propose_control(text, text, text, text, jsonb, text, text, text, int, text[], text[], text),
  public.log_activity(text, text, text), public.verify_activity_chain()
  to authenticated;

-- Keep future objects closed by default, too
alter default privileges in schema public revoke all on tables from anon, authenticated;
alter default privileges in schema public revoke execute on functions from public, anon, authenticated;
