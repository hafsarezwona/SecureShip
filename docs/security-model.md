# Security model

## Identity and data ownership

- The browser receives only the Supabase URL and anon key; server secrets never use a `VITE_` prefix.
- Express verifies bearer tokens with Supabase Auth and never accepts a client-supplied user ID.
- User-facing database requests use the verified user's access token and anon key, preserving RLS. The service-role key is limited to server-owned scanner records and callbacks.
- Tables use RLS and child rows carry owner IDs and composite foreign keys. Projects, scans, findings, remediations, and reports are scoped to the authenticated owner.
- Source uploads use the private `secure-source` bucket and an owner-folder policy. n8n receives a short-lived signed URL for a single scan.

## Untrusted source and scanning

- Express limits upload bytes, entry count, expanded bytes, per-file size, and compression ratio. It checks normalized paths, duplicates, special files, encryption, and actual decompressed sizes before storage.
- The worker revalidates source bytes and the SHA-256 digest, extracts into a disposable job directory, and removes that directory after scanning.
- Uploaded source is never executed, dependency installation is never run, and the worker receives no Supabase or AI credentials.
- Docker drops capabilities, uses a read-only root filesystem, resource limits, a private network, and a read-only Trivy cache. Do not publish the worker port. Seed/update the Trivy database from a separate trusted job.
- Semgrep rules are local and version controlled. Trivy updates are disabled during scans; stale/missing DB must fail rather than imply a clean dependency scan.

## Secrets, findings, and callbacks

- Internal n8n and worker requests use shared secrets in headers. The API compares callback secrets using constant-time equality and validates callback payloads.
- Scanner outputs exclude code excerpts. Trivy secret results use a generic title and description; secret match values are not returned or persisted. Findings store normalized identifiers, paths, line numbers, scanner descriptions, and an empty redacted-evidence object.
- API errors are generic; server logs record error class/code, not source or credentials. Do not enable request-body logging in n8n or the API.
- Callback records are owner-bound using the scan row and composite relationships. Repeated finding delivery upserts by scan and fingerprint.

## Current limits and remaining work

- Authentication, project APIs, RLS migration, ZIP validation, upload orchestration, scan callback validation, and worker service boundaries are implemented.
- AI prompt-injection controls, safe code-context selection, patch path/content validation, explicit approval records, verification rescans, private report links, and cross-user integration tests must be completed before production acceptance.
- No scan establishes that an application is completely secure. Results cover only the configured scanners, rules, versions, source, and dependency database used for that run.
