# Setting up Risk Ledger on Supabase

## 1. Create the database (once)

In your Supabase project, open **SQL Editor**, click **New query**, paste the whole of [`supabase/setup.sql`](../supabase/setup.sql), and click **Run**. You should see "Success. No rows returned." It runs as one transaction: if anything fails, nothing is changed.

## 2. Create the demo users

Under **Authentication → Users → Add user → Create new user**, create one user per role. Tick **Auto Confirm User**. Use email addresses you control (Gmail's `you+grc@gmail.com` trick works):

| Role | Example display name |
|---|---|
| GRC analyst | You |
| Control owner | Priya Shah (Platform Engineering) |
| Auditor | Avery Lin (external auditor) |

Every new user starts with **no access** (role `pending`).

## 3. Assign roles (SQL Editor)

Replace the emails with the ones you used:

```sql
update public.profiles p set role = 'grc_analyst', display_name = 'Jasmine Alexander'
  from auth.users u where u.id = p.id and u.email = 'YOU+grc@gmail.com';
update public.profiles p set role = 'control_owner', display_name = 'Priya Shah'
  from auth.users u where u.id = p.id and u.email = 'YOU+owner@gmail.com';
update public.profiles p set role = 'auditor', display_name = 'Avery Lin'
  from auth.users u where u.id = p.id and u.email = 'YOU+auditor@gmail.com';

-- Make Priya the owner of the public-bucket control, so she has work to see
update public.controls set owner_id = (select p.id from public.profiles p where p.display_name = 'Priya Shah'),
                           owner_name = 'Priya Shah' where id = 'CC-04';
```

## 4. First test run

Sign in to the web page as the GRC analyst and click **Run tests**, or run this in the SQL Editor:

```sql
select public.run_control_tests();
select id, last_result, last_detail from public.control_status order by id;
```

Expect 7 passes and 5 failures. **SB-03** fails until the GRC analyst sets up MFA; after that, the next run passes, its remediation item closes by evidence, and risk R-01 becomes ready to close.

## Optional: run the tests every day

Supabase includes the `pg_cron` scheduler (**Database → Extensions → pg_cron**). After enabling it:

```sql
select cron.schedule('risk-ledger-daily', '0 15 * * *', $$select public.run_control_tests()$$);
```

Scheduled runs are recorded with no user, and the audit log shows them as `system via engine`.

## Upgrading an existing project

If you set up the database with an earlier `setup.sql`, run the scripts in [`supabase/migrations/`](../supabase/migrations/) in number order instead of running `setup.sql` again.

| Script | Adds |
|---|---|
| `002_open_policy_check.sql` | Live check **SB-04**: no policy opens a table to everyone (see [why RLS matters](why-rls-matters.md)) |
