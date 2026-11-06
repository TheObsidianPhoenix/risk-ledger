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
  ('SB-04', 'No policy opens a table to everyone',
   'Turning RLS on isn''t enough: a policy of "true" or "any signed-in user" would still expose every row, the pattern behind CVE-2025-48757.', 'R-07', 'supabase', 'live', null, 'no_open_policies',
   'Live: no policy allows every row, only checks that someone is signed in, or applies to anonymous visitors, and anonymous visitors have no table rights', 1, 'critical', 'GRC', '{CC6.1,CC6.3}', '{A.5.15,A.8.3}', 'active', 'Jasmine Alexander (setup)', now()),
  ('SB-02', 'Audit log can''t be altered',
   'The record of who did what survives even a mistake or a malicious insider.', 'R-04', 'supabase', 'live', null, 'audit_log_protected',
   'Live: the audit log blocks updates, deletes and truncation, and no client can write to it', 1, 'high', 'GRC', '{CC7.2}', '{A.8.15}', 'active', 'Jasmine Alexander (setup)', now()),
  ('SB-03', 'GRC analysts use MFA',
   'The people who can approve tests and close risks can''t be impersonated with a password alone.', 'R-01', 'supabase', 'live', null, 'grc_analysts_have_mfa',
   'Live: every user with the GRC analyst role has a verified MFA factor', 1, 'critical', 'GRC', '{CC6.1}', '{A.8.5}', 'active', 'Jasmine Alexander (setup)', now());
