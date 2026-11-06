# SecureShip

SecureShip is an AI-assisted application security workflow for developers: upload a source ZIP, review real scanner findings, consider a proposed remediation, approve it explicitly, verify with a rescan, and produce an assessment report.

The interface and API foundation are in place. Supabase, Docker scanning, and AI integrations require service configuration before those workflows can run. SecureShip does not generate sample findings or claim that a scan proves an application is secure.

The AI vulnerability analysis engine uses the backend-only `AI_API_KEY` and optional `OPENAI_MODEL` setting. See [API documentation](docs/api-documentation.md), [security model](docs/security-model.md), and the [manual AI integration check](docs/manual-ai-integration-test.md).

## Stack

- Frontend: React, Vite, JavaScript, Tailwind CSS, React Router, Lucide React
- API: Node.js 22+, Express, Supabase Auth/PostgreSQL/Storage
- Scan orchestration: the Express API runs durable scan jobs against a restricted Docker worker running Semgrep and Trivy

## Local setup

Use Node.js 22 or later. Install and start the frontend:

```powershell
cd frontend
npm install
Copy-Item .env.example .env.local
npm run dev
```

Set frontend Supabase values and backend Supabase, AI, and worker values in their respective environment files. Apply the SQL migrations in `supabase/migrations/` in filename order before using authentication, project storage, and billing. Keep the service-role key, payment credentials, and AI credentials in `backend/.env`; never put them in a `VITE_` variable. The root `.env` and `backend/.env` must contain the same `WORKER_API_SECRET`.

Billing uses SSLCOMMERZ hosted checkout. Configure `SSLCOMMERZ_STORE_ID`, `SSLCOMMERZ_STORE_PASSWORD`, `SSLCOMMERZ_SANDBOX=true` for tests (set false only for live credentials), `BILLING_API_PUBLIC_URL` to the public HTTPS API URL, and `PREMIUM_PRICE_BDT` in `backend/.env`. Configure that public URL as the SSLCOMMERZ IPN endpoint at `/api/billing/webhook`. Only a provider-validated, amount-matched, low-risk transaction activates Premium. Renewal is a new checkout; this integration does not automatically charge saved payment methods. The default price is ৳1,000/month and can be changed with `PREMIUM_PRICE_BDT`.

Start the API and isolated scanner from the repository root:

```powershell
docker compose -f .\docker-compose.scanner.yml up -d --build api scanner-worker
docker compose -f .\docker-compose.scanner.yml ps
```

The API is available to the frontend at `http://localhost:4000`. It joins an outbound network for Supabase/OpenAI and the private scanner network; the scanner worker stays on the private network and is not published to the host. Populate the read-only Trivy database cache before running scans.

Run the automated checks from their package directories with `npm test` in `backend/` and `scanner-worker/`, then `npm run lint` and `npm run build` in `frontend/`.

The frontend expects `VITE_API_BASE_URL=http://localhost:4000`; the API allows the local Vite origin by default. `/health` reports whether Supabase settings are present without exposing credentials.

## Current implementation

- Responsive SecureShip landing page and application workspace shell.
- Supabase Auth forms, password reset, session persistence, and protected workspace routes.
- Supabase-backed profile, project, dashboard, and findings API routes with user-scoped access and RLS migration.
- Project creation/deletion, scan upload UI, finding filters, and honest service setup/error states.
- Scan upload validates archive paths, size/ratio bounds, special files, and decompressed bytes before private storage. The API queues and recovers idempotent scan jobs, calls the isolated worker directly, and persists validated findings.
- The scanner worker processes source only in per-job temporary directories and returns redacted Semgrep/Trivy metadata. Docker and a current Trivy database are required to run scans.
- Approved patch application, verification rescans, and PDF reports remain later milestones.

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
