# Deployment guide

The frontend and API are separate services. The frontend can be built with `npm run build` from `frontend/`; the API starts with `npm start` from `backend/`.

Required frontend values are in `frontend/.env.example`. Required API values are in `backend/.env.example`. Set the production frontend origin in `WEB_ORIGIN`, and configure Supabase URL and anon key on the API. Never publish the service-role key or AI credentials to the browser. Apply the versioned Supabase migration before enabling account and project workflows.

Production deployment is not complete until HTTPS, Supabase Auth redirect URLs, storage policies, rate limits, worker networking/resource limits, a refreshed Trivy database, and full upload-to-report verification have been configured. Docker was unavailable in the inspected environment.

## Local API and scanner services

Set the root `.env` and `backend/.env` with the same `WORKER_API_SECRET`, then start the API and worker from the repository root with `docker compose -f docker-compose.scanner.yml up -d --build api scanner-worker`. The API is published on loopback port 4000, joins an outbound network for Supabase/OpenAI and the private scanner network, and calls `http://scanner-worker:4100`. The worker is not published to the host and has no outbound network route. The API container receives its environment from `backend/.env`; do not add secrets to the frontend environment.

The worker image pins Semgrep to `1.163.0` and Trivy to `0.76.1`; it checks the Trivy release checksum during image build. Review and update versions through dependency maintenance. Do not expose the worker publicly.

Before scans are enabled, seed the `secureship-trivy-cache` volume from a trusted update job with a current vulnerability database. Mount the populated cache read-only into the scanner. The worker passes `--skip-db-update`; an empty or unusable cache fails the scan instead of producing an incomplete success.

After upload, the API records the job, returns `202`, and runs it in a bounded in-process queue. The API fetches the private archive through a short-lived signed URL, checks its hash, sends raw ZIP bytes to the worker, validates the worker response, persists findings, and runs optional AI analysis. Queued and stale running jobs are recovered after API restart. Run at least one API instance with a persistent Supabase connection; if scaling API replicas, the database lease prevents concurrent claims for one scan.

Apply `supabase/migrations/202611040001_initial_schema.sql` before enabling the API. The browser should use only the Supabase anon key. Keep service-role and internal secrets on trusted servers. Match the source bucket limits to API and worker limits.
