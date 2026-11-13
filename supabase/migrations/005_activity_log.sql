-- Risk Ledger upgrade 005: a separate, hash-chained activity log for sign-ins and
-- page views, so someone just logging in and clicking around leaves a trail too,
-- without diluting the audit log's record of actual data changes.
-- Paste into the Supabase SQL Editor and click Run.
--
-- This project was first set up from supabase/setup.sql, which already creates
-- this table and everything below for anyone installing from scratch today; this
-- migration is only for the already-running project, which needs it added on.

create table if not exists public.activity_log (
  id         bigint generated always as identity primary key,
  at         timestamptz not null default clock_timestamp(),
  actor      uuid not null references auth.users(id),
  actor_role text not null,
  action     text not null check (action in ('sign_in', 'sign_out', 'view', 'view_detail')),
  view       text check (char_length(view) <= 40),
  detail     text check (char_length(detail) <= 200),
  prev_hash  text not null,
  hash       text not null
);
comment on table public.activity_log is 'Every sign-in, sign-out, page view and record opened, written by the browser itself. Append-only and hash-chained like audit_log, but kept in its own table and its own chain so session activity never dilutes the record of actual data changes.';

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

drop trigger if exists activity_log_chain on public.activity_log;
create trigger activity_log_chain before insert on public.activity_log
  for each row execute function public.activity_chain();

create function public.activity_log_block() returns trigger
language plpgsql set search_path = public as $$
begin
  raise exception 'The activity log is append-only: % is not allowed', tg_op using errcode = '42501';
end $$;

drop trigger if exists activity_log_no_change on public.activity_log;
create trigger activity_log_no_change before update or delete on public.activity_log
  for each row execute function public.activity_log_block();
drop trigger if exists activity_log_no_truncate on public.activity_log;
create trigger activity_log_no_truncate before truncate on public.activity_log
  for each statement execute function public.activity_log_block();

alter table public.activity_log enable row level security;

drop policy if exists "GRC and auditors read the activity log" on public.activity_log;
create policy "GRC and auditors read the activity log" on public.activity_log for select to authenticated
  using (public.my_role() in ('grc_analyst', 'auditor'));

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

-- This table did not exist when "grant select on all tables" ran at initial setup,
-- and new tables get no default privileges (see the bottom of 03_security.sql) --
-- so, unlike the tables from the original setup, this grant has to be explicit.
grant select on public.activity_log to authenticated;
grant execute on function public.log_activity(text, text, text), public.verify_activity_chain() to authenticated;

-- Check: table has RLS, both guard triggers are enabled, and only grc_analyst/auditor can read it
select 'RLS is ' || case when relrowsecurity then 'on' else 'OFF — something is wrong' end as rls_check
  from pg_class where oid = 'public.activity_log'::regclass;
select tgname, tgenabled from pg_trigger where tgrelid = 'public.activity_log'::regclass and not tgisinternal;
select policyname, roles from pg_policies where tablename = 'activity_log';
