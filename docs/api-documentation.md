# API

Base URL: `http://localhost:4000`

Protected endpoints require `Authorization: Bearer <Supabase access token>`. Errors use `{ "error": { "message": "..." } }`.

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/health` | API liveness and Supabase/AI configuration plus live scanner-worker reachability |
| GET | `/api/profile` | Authenticated profile summary |
| GET | `/api/dashboard` | Current user's project, scan, and finding counts and latest scans |
| GET | `/api/projects` | List current user's projects |
| POST | `/api/projects` | Create a project (`name`, optional `description`, `primary_language`, `framework`) |
| GET | `/api/projects/:projectId` | Get one owned project |
| PATCH | `/api/projects/:projectId` | Update an owned project |
| DELETE | `/api/projects/:projectId` | Delete an owned project and dependent records |
| GET | `/api/findings` | List current user's findings; optional `severity` and `projectId` filters |
| GET | `/api/findings/:findingId` | Get one owned finding, scanner evidence, and any saved AI analysis |
| POST | `/api/findings/:findingId/analyze` | Analyze one owned finding with OpenAI; cached unchanged analyses are reused |
| GET | `/api/scans` | List current user's scans |
| GET | `/api/scans/:scanId/status` | Get one owned scan status |
| POST | `/api/scans` | Start a scan with multipart `file` and `projectId`; send UUID `Idempotency-Key` |
The API creates scan jobs and calls the private scanner worker directly. The worker endpoint requires `x-secureship-secret`, `x-scan-id`, and `x-source-sha256` with a raw `application/zip` body. The worker is not exposed as a public API route.

When `AI_API_KEY` is configured, completed scanner findings enter `analyzing` and receive bounded, best-effort analysis before the scan becomes `completed`. The user-facing analyze endpoint allows up to 20 requests per user per hour. Set `OPENAI_MODEL` to choose the OpenAI model; the default is `gpt-6-luna`. Analysis uses a small sanitized excerpt from the private ZIP, when safely available, and persists in the existing `findings.ai_explanation` JSONB column. Automated tests mock the OpenAI SDK and make no paid API calls.

`POST /api/scans` returns `202 { scanId, status, archive }`, `503` when Supabase or the worker is not configured, `400` for invalid archive/project/key input, `409` when an idempotency key is reused for different bytes, and `413` when compressed upload size exceeds the configured limit. Scan status is available from `GET /api/scans/:scanId/status`.
