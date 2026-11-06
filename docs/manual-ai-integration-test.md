# Manual AI analysis integration check

This check uses `examples/ai-vulnerable-sample/app.js`, an intentionally vulnerable sample that matches SecureShip's Semgrep dynamic evaluation rule. Keep the fixture isolated; do not deploy or run it.

## Before you start

- Configure the backend's `AI_API_KEY` and `OPENAI_MODEL` (the default is `gpt-6-luna`). Keep the key only in `backend/.env`.
- Start Supabase, the API, and the scanner worker. Set the API's `WORKER_INTERNAL_URL` to the worker address (`http://127.0.0.1:4100` for the scanner compose file). Confirm `/health` reports Supabase, scanner worker, and AI as configured.
- Sign in to the React app and create a disposable test project.

## Run the check

1. Create a ZIP containing only `app.js` from `examples/ai-vulnerable-sample/`.
2. Upload it for a scan in the SecureShip UI.
3. Wait for scan status to become `completed`, then open the Semgrep finding for `eval`.
4. Confirm original scanner evidence shows the dynamic evaluation rule, CWE-95, and its source line. Confirm AI analysis includes an uncertainty-aware explanation, root cause, attack scenario, business impact, separate severity assessment, confidence, remediation, and a secure-code example.
5. Reload the finding and confirm the stored analysis appears without submitting another analysis request.

The scan sends only a bounded, sanitized excerpt for this finding to OpenAI. This manual check uses the configured OpenAI API and may incur API usage. Automated tests use mocked responses and make no paid calls.
