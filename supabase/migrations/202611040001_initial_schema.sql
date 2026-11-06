create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text check (char_length(full_name) <= 120),
  avatar_url text,
  preferred_language text not null default 'en' check (preferred_language in ('en', 'bn')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.projects (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 80),
  description text not null default '' check (char_length(description) <= 500),
  primary_language text not null default '' check (char_length(primary_language) <= 40),
  framework text not null default '' check (char_length(framework) <= 80),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, user_id)
);

create table if not exists public.scans (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null,
  user_id uuid not null references auth.users(id) on delete cascade,
  status text not null default 'queued' check (status in ('queued','uploading','scanning','analyzing','completed','failed','cancelled')),
  source_file_path text,
  started_at timestamptz,
  completed_at timestamptz,
  scanner_versions jsonb not null default '{}'::jsonb,
  error_message text,
  created_at timestamptz not null default now(),
  foreign key (project_id, user_id) references public.projects(id, user_id) on delete cascade,
  unique (id, user_id)
);

create table if not exists public.findings (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null,
  project_id uuid not null,
  user_id uuid not null references auth.users(id) on delete cascade,
  scanner text not null check (scanner in ('semgrep','trivy')),
  rule_id text not null,
  title text not null check (char_length(title) <= 240),
  severity text not null check (severity in ('critical','high','medium','low','info','unknown')),
  cwe_id text,
  owasp_category text,
  file_path text not null,
  line_start integer check (line_start is null or line_start > 0),
  line_end integer check (line_end is null or line_end >= line_start),
  description text not null default '',
  evidence_redacted jsonb not null default '{}'::jsonb,
  fingerprint text not null,
  ai_explanation jsonb,
  business_impact text,
  remediation_guidance text,
  status text not null default 'detected' check (status in ('detected','under_review','remediation_proposed','remediated','verified_resolved','reopened','accepted_risk')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (scan_id, user_id) references public.scans(id, user_id) on delete cascade,
  foreign key (project_id, user_id) references public.projects(id, user_id) on delete cascade,
  unique (scan_id, fingerprint)
);

create table if not exists public.remediations (
  id uuid primary key default gen_random_uuid(),
  finding_id uuid not null references public.findings(id) on delete cascade,
  scan_id uuid not null,
  user_id uuid not null references auth.users(id) on delete cascade,
  proposed_diff text not null,
  explanation text not null default '',
  approval_status text not null default 'pending' check (approval_status in ('pending','approved','rejected')),
  verification_scan_id uuid,
  verification_status text check (verification_status in ('verified_resolved','still_detected','verification_failed','inconclusive')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (scan_id, user_id) references public.scans(id, user_id) on delete cascade
);

create table if not exists public.scan_reports (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null,
  user_id uuid not null references auth.users(id) on delete cascade,
  report_storage_path text not null,
  generated_at timestamptz not null default now(),
  foreign key (scan_id, user_id) references public.scans(id, user_id) on delete cascade
);

create table if not exists public.scan_jobs (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null,
  user_id uuid not null references auth.users(id) on delete cascade,
  status text not null default 'queued' check (status in ('queued','running','completed','failed','cancelled')),
  worker_job_id text,
  idempotency_key text not null,
  request_hash text not null,
  retry_count integer not null default 0 check (retry_count >= 0),
  started_at timestamptz,
  completed_at timestamptz,
  error_message text,
  created_at timestamptz not null default now(),
  foreign key (scan_id, user_id) references public.scans(id, user_id) on delete cascade,
  unique (scan_id),
  unique (user_id, idempotency_key)
);

create index if not exists projects_user_created_idx on public.projects(user_id, created_at desc);
create index if not exists scans_user_created_idx on public.scans(user_id, created_at desc);
create index if not exists scans_project_created_idx on public.scans(project_id, created_at desc);
-- Supports the backend's bounded recovery query for queued and interrupted scans.
create index if not exists scans_worker_recovery_idx
  on public.scans (created_at asc)
  where status in ('queued', 'scanning', 'analyzing');
create index if not exists findings_user_severity_idx on public.findings(user_id, severity, status);
create index if not exists findings_scan_idx on public.findings(scan_id);
create index if not exists remediations_user_created_idx on public.remediations(user_id, created_at desc);
create index if not exists reports_user_created_idx on public.scan_reports(user_id, generated_at desc);

alter table public.profiles enable row level security;
alter table public.projects enable row level security;
alter table public.scans enable row level security;
alter table public.findings enable row level security;
alter table public.remediations enable row level security;
alter table public.scan_reports enable row level security;
alter table public.scan_jobs enable row level security;

drop policy if exists profiles_read_own on public.profiles;
create policy profiles_read_own on public.profiles for select using (id = (select auth.uid()));
drop policy if exists profiles_update_own on public.profiles;
create policy profiles_update_own on public.profiles for update using (id = (select auth.uid())) with check (id = (select auth.uid()));

create or replace function public.create_profile_for_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, nullif(new.raw_user_meta_data ->> 'full_name', ''))
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists create_profile_after_signup on auth.users;
create trigger create_profile_after_signup after insert on auth.users
for each row execute procedure public.create_profile_for_user();

drop policy if exists projects_own on public.projects;
create policy projects_own on public.projects for all using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
drop policy if exists scans_own on public.scans;
drop policy if exists scans_read_own on public.scans;
create policy scans_read_own on public.scans for select using (user_id = (select auth.uid()));
drop policy if exists findings_own on public.findings;
drop policy if exists findings_read_own on public.findings;
create policy findings_read_own on public.findings for select using (user_id = (select auth.uid()));
drop policy if exists remediations_own on public.remediations;
drop policy if exists remediations_read_own on public.remediations;
create policy remediations_read_own on public.remediations for select using (user_id = (select auth.uid()));
drop policy if exists scan_reports_own on public.scan_reports;
drop policy if exists scan_reports_read_own on public.scan_reports;
create policy scan_reports_read_own on public.scan_reports for select using (user_id = (select auth.uid()));
drop policy if exists scan_jobs_own on public.scan_jobs;
drop policy if exists scan_jobs_read_own on public.scan_jobs;
create policy scan_jobs_read_own on public.scan_jobs for select using (user_id = (select auth.uid()));

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('secure-source', 'secure-source', false, 26214400, array['application/zip','application/x-zip-compressed'])
on conflict (id) do update set public = false, file_size_limit = 26214400;

drop policy if exists secure_source_read_own on storage.objects;
create policy secure_source_read_own on storage.objects for select to authenticated
using (bucket_id = 'secure-source' and (storage.foldername(name))[1] = (select auth.uid())::text);
drop policy if exists secure_source_insert_own on storage.objects;
create policy secure_source_insert_own on storage.objects for insert to authenticated
with check (bucket_id = 'secure-source' and (storage.foldername(name))[1] = (select auth.uid())::text);
drop policy if exists secure_source_delete_own on storage.objects;
create policy secure_source_delete_own on storage.objects for delete to authenticated
using (bucket_id = 'secure-source' and (storage.foldername(name))[1] = (select auth.uid())::text);
