-- Risk Ledger, part 1 of 4: tables.
-- Continuous control monitoring for Obsidian Phoenix Labs (a demo company; all data is fictional).
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
  live_check     text check (live_check in ('rls_on_all_tables', 'no_open_policies', 'audit_log_protected', 'grc_analysts_have_mfa')),
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

-- ---------------------------------------------------------------------------
-- Activity log: a separate hash-chained trail of sign-ins and page views, so
-- someone just clicking around doesn't drown the audit log's real data changes
-- ---------------------------------------------------------------------------
create table public.activity_log (
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

create index on public.evidence (control_id, tested_at desc);
create index on public.remediation (control_id) where status in ('open', 'in_progress', 'risk_accepted');
create index on public.source_snapshots (system_id, collected_at desc);
