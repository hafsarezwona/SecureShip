-- Scanner worker support for recoverPendingScanJobs() in the API process.
-- Only unfinished scans are indexed, so recovery does not walk completed history.
create index if not exists scans_worker_recovery_idx
  on public.scans (created_at asc)
  where status in ('queued', 'scanning', 'analyzing');
