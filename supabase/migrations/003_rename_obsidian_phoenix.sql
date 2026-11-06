-- Risk Ledger upgrade 003: the demo company is now Obsidian Phoenix Labs.
-- For a project set up before this change. (A new project just runs setup.sql.)
-- Paste into the Supabase SQL Editor and click Run. One transaction: all or nothing.
--
-- Source snapshots and evidence are permanent, so the old ones are NOT edited.
-- This loads new mock snapshots with the new names; the next test run uses them.
-- Older evidence keeps the old names, the way real evidence keeps its history.
begin;

insert into public.source_snapshots (system_id, collected_at, data)
select system_id, now(),
       replace(replace(data::text, '@meridian.example', '@obsidianphoenix.example'), 'meridian-', 'obsidian-')::jsonb
  from (select distinct on (system_id) system_id, data
          from public.source_snapshots
         where system_id in ('aws', 'gcp', 'okta')
         order by system_id, collected_at desc, id desc) latest
 where data::text like '%meridian%';

-- Check: each of these three should say "renamed"
select distinct on (system_id) system_id,
       case when data::text like '%meridian%' then 'still old' else 'renamed' end as name_check
  from public.source_snapshots
 where system_id in ('aws', 'gcp', 'okta')
 order by system_id, collected_at desc, id desc;

commit;
