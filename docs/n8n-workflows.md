# n8n workflow contracts

The repository defines the HTTP contracts; the workflow must be imported and configured in the deployment's n8n instance. No n8n instance was available here, so the workflow has not been imported or run.

## Scan orchestration

### Trigger

Create a `POST` Webhook node at `secure-scan`, protected with Header Auth. Configure its credential value to the API's `N8N_INTERNAL_SECRET`. Set its response mode to **Immediately** so the API can return the scan ID without waiting for the scanner.

The webhook input JSON is:

```json
{
  "scanId": "uuid",
  "project": { "id": "uuid", "name": "Example", "language": "JavaScript", "framework": "Express" },
  "source": { "url": "short-lived signed URL", "fileName": "source.zip", "size": 1234, "sha256": "hex digest" },
  "archive": { "entryCount": 1, "fileCount": 1, "expandedSize": 20 }
}
```

### Nodes

1. **Webhook** — authenticate with the header credential above; acknowledge immediately.
2. **Download source** — HTTP Request `GET` to `body.source.url`; response format **File**, binary property `data`. Set a request timeout and do not log the signed URL. Disable successful/failed execution payload retention for this workflow or configure n8n to prune binary data immediately.
3. **Run isolated scan** — HTTP Request `POST` to `WORKER_INTERNAL_URL/scan`; send binary property `data` as the raw body, `Content-Type: application/zip`, plus headers `x-secureship-secret: WORKER_API_SECRET`, `x-scan-id: body.scanId`, and `x-source-sha256: body.source.sha256`. Do not use multipart encoding.
4. **Store results** — HTTP Request `POST` to `${API_BASE}/api/internal/scans/{body.scanId}/results`; send JSON `{ scannerVersions, findings }` from the worker response and header `x-secureship-secret: N8N_INTERNAL_SECRET`.
5. **Failure handler** — on download, scan, or result callback failure, call `POST ${API_BASE}/api/internal/scans/{body.scanId}/failure` with the same callback secret. Configure bounded retries with backoff and keep execution records free of source bytes, signed URLs, and secrets.

The worker returns at most 1,000 normalized findings and scanner versions. The API validates each field, rechecks paths, stores finding metadata without source evidence, and completes the scan/job. Repeated result delivery upserts by `(scan_id, fingerprint)`.

The API provides dedicated callback routes for future analysis, remediation, verification, and report workflows only after those modules are implemented. Do not create placeholder nodes that claim these actions succeeded.
