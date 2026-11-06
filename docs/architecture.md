# SecureShip architecture

## Current request path

```text
React/Vite browser → Express API → Supabase Auth/Postgres with the user's access token
                                    ↘ RLS scopes reads and writes to auth.uid()
```

The browser holds only the Supabase anon key and user session. Each protected API request sends its access token; Express verifies it with Supabase Auth and creates a user-scoped Supabase client so database RLS remains active. The service-role key is reserved for trusted server-only work and is not used by these user routes.

## Scan lifecycle

1. Express authenticates the user and confirms ownership of the selected project.
2. The ZIP is checked for file type, archive paths, links, entry count, expanded size, and compression ratio without extracting it into an application directory.
3. The archive is stored in a private Supabase bucket and a scan/job record is created.
4. A database-backed API job calls the restricted Docker worker over a private network.
5. Semgrep and Trivy return structured evidence. The API stores scanner evidence separately from AI interpretations.
6. AI may explain a real finding and propose a diff. The developer must approve it.
7. An approved patch is applied to an isolated copy and rescanned. Verification describes only the specific scanner evidence observed.
8. A report is generated and stored privately for its owner.

The authenticated scan upload, private storage, direct worker call, result validation, and finding persistence are implemented. Docker and scanner database services still need deployment configuration. Uploaded source code must never be executed by Express or the worker.

## Isolated scan flow

1. Express authenticates the user, checks project ownership, validates the ZIP, hashes the uploaded bytes, and streams source to the user's private storage path.
2. The API creates an idempotent scan/job and returns `202` while a bounded in-process job queue takes the job.
3. The API signs a short-lived source URL, retrieves the archive with byte limits, verifies SHA-256, and sends raw ZIP bytes to the internal worker with the scan ID and worker secret.
4. The worker validates and safely extracts into a per-job temporary directory. It runs only the configured Semgrep rules and Trivy filesystem scanners. It does not execute uploaded code or make network requests.
5. The API validates the worker response and stores normalized finding metadata; source excerpts and secret matches are not persisted.

Keep the worker on Docker's `internal: true` network and attach the API to that network plus its normal outbound network. Never expose port 4100 publicly. Populate the read-only Trivy cache volume using a separately managed update job before accepting vulnerability scans. An unavailable cache fails the scan rather than reporting an incomplete success.
