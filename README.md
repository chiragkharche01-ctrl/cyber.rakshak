# CyberRakshak - Website Security Assessment Platform
Passive, non-destructive security posture assessment: HTTPS/redirects, TLS certificate, 8 security headers, cookies, DNS/SPF/DMARC/CAA, server disclosure, HTTP methods (OPTIONS), robots.txt, security.txt, technology clues. Score 0-100, remediation advice, history, PDF reports.

## Run (2 commands)
```
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt && uvicorn app:app --reload
```
Open http://localhost:8000 . API docs: /docs and /redoc.

## Architecture
Browser SPA (static/index.html) -> FastAPI REST (/api) -> scanner engine (app.py STEPS) -> SQLite -> PDF (ReportLab, reports/).
Scans run as background jobs; the UI polls `/api/scans/{id}/status` and progress reflects real completed checks.

## Risk score
Weights: LOW 2, MEDIUM 5, HIGH 10, CRITICAL 20 (by the severity a check carries when it fails). FAIL = full weight, WARN = half, ERROR (check couldn't run) excluded.
`score = 100 * (1 - penalty / total_weight_of_applicable_checks)`. Risk: >=85 LOW, >=65 MODERATE, >=45 HIGH, else CRITICAL (env T_LOW/T_MOD/T_HIGH).

## Security of the app itself
PBKDF2 password hashing, hashed server-side session tokens, per-user data isolation, parameterized SQL, SSRF guard (server-side DNS resolution, blocks private/loopback/link-local/metadata IPs, re-checked on every redirect, max 5 redirects), response size limit, timeouts, per-user rate limit (429), login throttling, mandatory authorization checkbox saved with timestamp, audit log, sanitized errors, HTML escaping in UI.

## Limitations / future scope
SQLite chosen for zero-setup demos (schema is portable to PostgreSQL via SQLAlchemy/Alembic); in-process background tasks (swap for Celery/Redis); DNS-rebinding between guard and connect is not fully pinned; no port scanning/exploitation by design. Future: scheduled scans, email alerts, CVE enrichment, admin dashboard, S3 report storage.
Demo mode (`#/demo`) uses clearly labelled sample data that is never stored.
