# Deployment guide

The frontend and API are separate services. The frontend can be built with `npm run build` from `frontend/`; the API starts with `npm start` from `backend/`.

Required frontend values are in `frontend/.env.example`. Required API values are in `backend/.env.example`. Set the production frontend origin in `WEB_ORIGIN`, and configure Supabase URL and anon key on the API. Never publish the service-role key or AI credentials to the browser. Apply the versioned Supabase migration before enabling account and project workflows.

Production deployment is not complete until HTTPS, Supabase Auth redirect URLs, storage policies, rate limits, n8n secrets, worker networking/resource limits, a refreshed Trivy database, and full upload-to-report verification have been configured. Docker and n8n were unavailable in the inspected environment.

## Scanner worker and n8n

Build the worker from the repository root with `docker compose -f docker-compose.scanner.yml build`. Set `WORKER_API_SECRET` in the deployment environment before starting it. The worker image pins Semgrep to `1.163.0` and Trivy to `0.76.0-16-g1f93b251d`; it checks the Trivy release checksum during image build. Review and update versions through dependency maintenance.

The scanner service has no public ports and joins only `scanner-private`. Attach n8n to this network and to the network it uses for API connectivity. Set `WORKER_INTERNAL_URL=http://scanner-worker:4100`, `WORKER_API_SECRET`, `N8N_SCAN_WEBHOOK_URL`, and `N8N_INTERNAL_SECRET` on the API. Configure corresponding worker and callback secret values for n8n and restrict n8n environment access to workflow owners.

Before scans are enabled, seed the `secureship-trivy-cache` volume from a trusted update job with a current vulnerability database. Mount the populated cache read-only into the scanner. The worker passes `--skip-db-update`; an empty or unusable cache fails the scan instead of producing an incomplete success.

Configure n8n in this order: authenticated `POST` webhook receives the scan envelope; HTTP Request downloads `body.source.url` as binary; HTTP Request posts the raw binary to `WORKER_INTERNAL_URL/scan` with `Content-Type: application/zip`, `x-secureship-secret`, `x-scan-id`, and `x-source-sha256`; HTTP Request posts returned `scannerVersions` and `findings` to `${API_BASE}/api/internal/scans/{scanId}/results` with `x-secureship-secret`. Route download, scanner, and callback errors to `/api/internal/scans/{scanId}/failure`. Acknowledge the webhook immediately so the API does not wait for scanning.

Apply `supabase/migrations/202611040001_initial_schema.sql` before enabling the API. The browser should use only the Supabase anon key. Keep service-role and internal secrets on trusted servers. Match the source bucket limits to API and worker limits.
