# SecureShip

SecureShip is an AI-assisted application security workflow for developers: upload a source ZIP, review real scanner findings, consider a proposed remediation, approve it explicitly, verify with a rescan, and produce an assessment report.

The interface and API foundation are in place. Supabase, n8n, Docker scanning, and AI integrations require service configuration before those workflows can run. SecureShip does not generate sample findings or claim that a scan proves an application is secure.

## Stack

- Frontend: React, Vite, JavaScript, Tailwind CSS, React Router, Lucide React
- API: Node.js 22+, Express, Supabase Auth/PostgreSQL/Storage
- Scan orchestration: n8n and a restricted Docker worker running Semgrep and Trivy

## Local setup

Use Node.js 22 or later. In separate terminals, install and start the frontend and API:

```powershell
cd frontend
npm install
Copy-Item .env.example .env.local
npm run dev
```

In a second terminal:

```powershell
cd backend
npm install
Copy-Item .env.example .env
npm run dev
```

Set the Supabase values in both local environment files. Apply `supabase/migrations/202611040001_initial_schema.sql` to the Supabase project before using authentication and project storage. Never put the service-role key in a `VITE_` variable.

The optional isolated scanner image is built from the repository root with `docker compose -f docker-compose.scanner.yml build`; start it only after setting `WORKER_API_SECRET` and populating its read-only Trivy database cache. Configure the n8n scan webhook and callback contract from [n8n workflow documentation](docs/n8n-workflows.md). Docker, n8n, and production credentials are required before ZIP scans can run.

Run the automated checks from their package directories with `npm test` in `backend/` and `scanner-worker/`, then `npm run lint` and `npm run build` in `frontend/`.

The frontend expects `VITE_API_BASE_URL=http://localhost:4000`; the API allows the local Vite origin by default. `/health` reports whether Supabase settings are present without exposing credentials.

## Current implementation

- Responsive SecureShip landing page and application workspace shell.
- Supabase Auth forms, password reset, session persistence, and protected workspace routes.
- Supabase-backed profile, project, dashboard, and findings API routes with user-scoped access and RLS migration.
- Project creation/deletion, scan upload UI, finding filters, and honest service setup/error states.
- Scan upload validates archive paths, size/ratio bounds, special files, and decompressed bytes before private storage. The API records idempotent scan jobs and supports authenticated result/failure callbacks.
- The scanner worker processes source only in per-job temporary directories and returns redacted Semgrep/Trivy metadata. n8n, Docker, and a current Trivy database are required to run scans.
- AI explanations, approved patch application, verification rescans, and PDF reports remain later milestones.

## Project layout

```text
frontend/                 React application
backend/                  Express REST API
supabase/migrations/      Versioned database schema and RLS
docs/                     Architecture, API, security, deployment notes
scanner-worker/            Isolated Semgrep and Trivy service
docker-compose.scanner.yml Restricted scanner worker deployment
```

See [architecture](docs/architecture.md), [API documentation](docs/api-documentation.md), and [security model](docs/security-model.md).
