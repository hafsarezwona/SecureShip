# Security model

## Identity and data ownership

- The browser receives only the Supabase URL and anon key; server secrets never use a `VITE_` prefix.
- Express verifies bearer tokens with Supabase Auth and never accepts a client-supplied user ID.
- User-facing database requests use the verified user's access token and anon key, preserving RLS. The service-role key is limited to trusted scan-job processing and AI persistence.
- Tables use RLS and child rows carry owner IDs and composite foreign keys. Projects, scans, findings, remediations, and reports are scoped to the authenticated owner.
- Source uploads use the private `secure-source` bucket and an owner-folder policy. The trusted API creates a short-lived signed URL for one scan and streams the archive to the worker.

## Untrusted source and scanning

- Express limits upload bytes, entry count, expanded bytes, per-file size, and compression ratio. It checks normalized paths, duplicates, special files, encryption, and actual decompressed sizes before storage.
- The worker revalidates source bytes and the SHA-256 digest, extracts into a disposable job directory, and removes that directory after scanning.
- Uploaded source is never executed, dependency installation is never run, and the worker receives no Supabase or AI credentials.
- Docker drops capabilities, uses a read-only root filesystem, resource limits, a private network, and a read-only Trivy cache. Do not publish the worker port. Seed/update the Trivy database from a separate trusted job.
- Semgrep rules are local and version controlled. Trivy updates are disabled during scans; stale/missing DB must fail rather than imply a clean dependency scan.

## Secrets and findings

- The API calls the scanner over a private network using a worker secret in headers. The worker validates the scan ID, source hash, content type, size, and secret before scanning. Scanner results are validated by the API before persistence.
- Scanner outputs exclude code excerpts. Trivy secret results use a generic title and description; secret match values are not returned or persisted. Findings store normalized identifiers, paths, line numbers, scanner descriptions, and an empty redacted-evidence object.
- API errors are generic; server logs record error class/code, not source or credentials. Request bodies and signed source URLs are not logged.
- Scan jobs are idempotent, database-backed, recovered after API restart, and limited to one active worker job per API process. Repeated results upsert by scan and fingerprint.
- AI analysis reads the private source through the trusted API, rejects sensitive paths, extracts only the reported source file, and caps the excerpt at 48 lines/12,000 characters. Secret-like values are redacted before transmission; API keys remain server-side.
- The OpenAI request uses structured output validation, a fixed instruction that treats scanner/source fields as untrusted data, no tools, `store: false`, a 30-second timeout, bounded concurrency, and a per-user request limit. Only schema-valid results are stored in the existing AI JSONB field. Scanner severity and evidence remain intact.
- AI analysis is best-effort. Scanner results remain available if analysis fails. A digest of finding/source/model/prompt/owner inputs avoids repeating analysis for unchanged inputs; pending scans are recovered after API restart.

## Current limits and remaining work

- Authentication, project APIs, RLS migration, ZIP validation, direct scan orchestration, worker response validation, and worker service boundaries are implemented.
- AI suggestions are explanatory only and are not automatically applied. Model output is validated, but a reviewer should still assess a recommendation before acting on it.
- No scan establishes that an application is completely secure. Results cover only the configured scanners, rules, versions, source, and dependency database used for that run.
