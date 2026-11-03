# SecureShip architecture

## Current request path

```text
React/Vite browser → Express API → Supabase Auth/Postgres with the user's access token
                                    ↘ RLS scopes reads and writes to auth.uid()
```

The browser holds only the Supabase anon key and user session. Each protected API request sends its access token; Express verifies it with Supabase Auth and creates a user-scoped Supabase client so database RLS remains active. The service-role key is reserved for trusted server-only work and is not used by these user routes.

## Planned scan lifecycle

1. Express authenticates the user and confirms ownership of the selected project.
2. The ZIP is checked for file type, archive paths, links, entry count, expanded size, and compression ratio without extracting it into an application directory.
3. The archive is stored in a private Supabase bucket and a scan/job record is created.
4. An authenticated, idempotent n8n workflow requests scanning from a restricted Docker worker.
5. Semgrep and Trivy return structured evidence. The API stores scanner evidence separately from AI interpretations.
6. AI may explain a real finding and propose a diff. The developer must approve it.
7. An approved patch is applied to an isolated copy and rescanned. Verification describes only the specific scanner evidence observed.
8. A report is generated and stored privately for its owner.

The authenticated scan upload, private storage, and worker callback routes are implemented. n8n, Docker, and scanner database services still need deployment configuration. Uploaded source code must never be executed by Express, n8n, or the worker.

## Isolated scan flow

1. Express authenticates the user, checks project ownership, validates the ZIP, hashes the uploaded bytes, and streams source to the user's private storage path.
2. The API creates an idempotent scan/job, signs a short-lived source URL, and sends the scan envelope to an authenticated n8n webhook.
3. n8n downloads the archive and sends raw ZIP bytes to the internal worker with the scan ID, expected SHA-256, and worker secret.
4. The worker validates and safely extracts into a per-job temporary directory. It runs only the configured Semgrep rules and Trivy filesystem scanners. It does not execute uploaded code or make network requests.
5. n8n submits normalized findings to the API's constant-time-secret-protected callback. The API stores finding metadata only; source excerpts and secret matches are not persisted.

Keep the worker on Docker's `internal: true` network. Attach n8n to that network and to its separate API connectivity network. Never expose port 4100 publicly. Populate the read-only Trivy cache volume using a separately managed update job before accepting vulnerability scans. An unavailable cache fails the scan rather than reporting an incomplete success.
