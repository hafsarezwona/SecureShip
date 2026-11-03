# API

Base URL: `http://localhost:4000`

Protected endpoints require `Authorization: Bearer <Supabase access token>`. Errors use `{ "error": { "message": "..." } }`.

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/health` | Service readiness; reports configured service names only |
| GET | `/api/profile` | Authenticated profile summary |
| GET | `/api/dashboard` | Current user's project, scan, and finding counts and latest scans |
| GET | `/api/projects` | List current user's projects |
| POST | `/api/projects` | Create a project (`name`, optional `description`, `primary_language`, `framework`) |
| GET | `/api/projects/:projectId` | Get one owned project |
| PATCH | `/api/projects/:projectId` | Update an owned project |
| DELETE | `/api/projects/:projectId` | Delete an owned project and dependent records |
| GET | `/api/findings` | List current user's findings; optional `severity` and `projectId` filters |
| GET | `/api/scans` | List current user's scans |
| GET | `/api/scans/:scanId/status` | Get one owned scan status |
| POST | `/api/scans` | Start a scan with multipart `file` and `projectId`; send UUID `Idempotency-Key` |
| POST | `/api/internal/scans/:scanId/results` | Internal n8n callback with normalized findings and scanner versions |
| POST | `/api/internal/scans/:scanId/failure` | Internal n8n callback to record a failed scan |

Internal callback routes require `x-secureship-secret` equal to the configured `N8N_INTERNAL_SECRET`. The worker endpoint is private to the scanner network and requires `x-secureship-secret`, `x-scan-id`, and `x-source-sha256` with a raw `application/zip` body. Callback finding records omit source excerpts and secret match values.

`POST /api/scans` returns `202 { scanId, status, archive }`, `503` when scanning is not configured, `400` for invalid archive/project/key input, `409` when an idempotency key is reused for different bytes, and `413` when compressed upload size exceeds the configured limit. The detailed n8n webhook and worker response contracts are in [n8n-workflows.md](n8n-workflows.md).
