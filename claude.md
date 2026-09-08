# Build "NotAfter" — a certificate expiry board with upload, notifications and calendar invites

## Context

NotAfter is an open-source, self-hosted web app (MIT licence, no vendor or company references anywhere in code, docs or sample data). Its job: let non-technical people register a certificate by uploading the file, show everyone a plain-language expiry board, and notify the right people by email, Teams and calendar invite before expiry.

Typical use case: certificates for integration middleware (B2B/EDI — AS2 signing/encryption, TLS server certs, partner certificates, client certs) that are renewed by hand and tracked nowhere. The app never connects to the systems that use the certificates; it is only fed the files.

It runs as a single-container Docker Compose stack on a Linux VPS behind an existing host-level Cloudflare Tunnel with Cloudflare Access in front.

The app is a registry of expiry dates, not a key store. **It must never receive, parse server-side, persist, log or transmit private key material — under any circumstances.** Treat this as the primary design constraint; everything else is secondary.

## Non-negotiable security constraints

1. **Private keys never reach the server.** PKCS#12 (.pfx/.p12) files are parsed **in the browser only**. The browser extracts the end-entity certificate(s) as PEM and sends only that. The PFX bytes and any password entered stay in the browser tab and are discarded after extraction.
2. **The server rejects PKCS#12 outright.** Any upload whose bytes look like PKCS#12/DER SEQUENCE that isn't a bare certificate, or any PEM containing `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY` or `OPENSSH PRIVATE KEY` blocks, is rejected with HTTP 400 before any parsing, and nothing is written to disk, DB or logs. The rejection message tells the user to use the in-browser extraction or manual entry.
3. Server-side accepted inputs: PEM certificate(s), DER certificate, PKCS#7 (.p7b/.p7c) certificate bundles. Parse with the `cryptography` library only. Max upload 256 KB.
4. Store per certificate only: label, subject CN, subject (RFC 4514), issuer, serial (decimal), notBefore, notAfter, SHA-256 fingerprint, SANs, key algorithm/size, and the public certificate PEM itself (it's public; used for re-verification and dedupe). Nothing else from the file.
5. Never log request bodies, uploaded content, passwords or webhook URLs. Redact secrets in all log lines and error pages.
6. No external assets at runtime: no CDN scripts/fonts/styles. Everything vendored and served from the app. Strict CSP (`default-src 'self'`; no `unsafe-inline`, no `unsafe-eval`), `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors 'none'`.
7. Authentication is delegated to a trusted identity-aware proxy; Cloudflare Access is the built-in provider, behind a small `AuthProvider` interface so an OIDC or other trusted-header provider can be added later without touching the rest of the app. The app validates the `Cf-Access-Jwt-Assertion` JWT on every request (issuer `https://<TEAM>.cloudflareaccess.com`, audience = the app's AUD tag, keys from `/cdn-cgi/access/certs`, cached with refresh), and derives the user's email from it. Roles: `viewer` (everyone who passes Access) and `editor` (emails in `EDITOR_EMAILS` env). In `AUTH_MODE=cloudflare` the app refuses to start if `CF_ACCESS_TEAM` or `CF_ACCESS_AUD` is missing. `AUTH_MODE=dev` (local development only) reads `X-Dev-User` and only binds to 127.0.0.1.
8. CSRF protection on all state-changing forms/requests. Rate limit uploads and settings changes per user. Idempotent notification sending (no duplicates on restarts).
9. Container runs as non-root, read-only root filesystem, SQLite in a named volume, `no-new-privileges`, healthcheck, pinned base image. Outbound network needs: SMTP host and the Teams webhook URL only.
10. Secrets via environment only (`.env` git-ignored, `.env.example` committed). Dependencies pinned; `pip-audit` and `npm audit` run in CI script.

## Explicitly rejected approaches (do not drift toward these)

- Server-side PKCS#12 parsing "just to extract the cert" — no.
- Storing the uploaded file "temporarily" on disk or in a temp dir — no. Streams are parsed in memory and discarded.
- Azure Key Vault, Microsoft Graph, Entra app registrations, Azure Functions or any Azure dependency in v1. The app is cloud-agnostic; Graph calendar integration may be a documented *optional* later extension, not part of this build.
- Teams "Office 365 Connector" incoming webhooks (retired). Use a Teams **Workflows** webhook URL and post an Adaptive Card.
- Workflow-automation tools, reverse proxies or ACME clients inside the stack (n8n, Traefik, nginx-proxy, Let's Encrypt). Ingress is an existing **host-level** `cloudflared` service; the container publishes only to `127.0.0.1:8087`.
- A `cloudflared` container, sidecar or any tunnel configuration inside the repo. The compose file has exactly one service (the app). The README documents the two things the operator does outside the repo: add an ingress rule `<hostname> → http://127.0.0.1:8087` to the host's tunnel, and create the Cloudflare Access application (self-hosted, that hostname) whose AUD tag goes into `CF_ACCESS_AUD`.
- Heavy SPA frameworks. Server-rendered pages with a small amount of TypeScript for the upload flow.
- Storing "days remaining" — always compute from `not_after` at render/notification time.

## Functional requirements

### Board (`/`, viewer)
- One page, no login UI (Access already authenticated the user). Lists all active certificates sorted by soonest expiry. For each: label, big "N days left" (or "N days ago" if expired), status word and plain sentence, valid-until date in `8 April 2027` format, CN, owner, environment tag (e.g. TEST/PROD), and a "manual entry — unverified" marker where applicable.
- Status thresholds (global settings, defaults): green > 60 days, amber ≤ 60, red ≤ 30, expired < 0. Legend sentence at the bottom explaining what each colour means for a non-technical reader and who to contact (configurable contact line in settings).
- Visual language: light paper background `#f4f4f1`, graphite text `#232628`, muted `#6b7075`, brand orange `#ff4700` used only as the header rule, status colours green `#1b7f4c`, amber `#b8740a`, red `#b3261e`. One typeface (Inter if vendored, otherwise system stack). Big tabular-number countdown is the one bold element; everything else quiet. No cards, no shadows, no gradients, no all-caps labels. Responsive to mobile. Auto-refresh meta every hour.

### Register a certificate (`/certificates/new`, editor)
Three tabs/paths on one page:
1. **Upload a certificate file.** Accepts `.pfx .p12 .pem .crt .cer .der .p7b .p7c`. Browser logic (TypeScript, bundled locally with esbuild/Vite, using `pkijs` + `asn1js`; `node-forge` acceptable if PKCS#12 support is more robust):
   - Detect format. For PKCS#12: attempt to read the certificate bags with an empty password; if the cert bags are encrypted, prompt for the password in-page, use it in memory, never send it. Read only certificate bags; never touch key bags. Extract the end-entity certificate (the one whose public key matches the key bag is *not* needed — pick the leaf by chain analysis: the cert that is not an issuer of any other cert in the file; if ambiguous, let the user choose from a list showing CN + expiry).
   - For PEM/DER/P7B: extract leaf as above.
   - Show a preview (CN, issuer, valid from/until, fingerprint) and a clear line: "Only the public certificate will be saved. The private key and password stay on your computer."
   - Submit sends JSON `{ label, environment, owner_email, notes, pem }`. Progressive enhancement: if JS is unavailable, the form falls back to a plain file POST that the server accepts only for PEM/DER/P7B and rejects for PKCS#12 with guidance.
2. **Enter the expiry manually.** For users who don't have the password or only know the date: label, environment, owner, expiry date (required), optional CN/issuer/notes. Stored with `source = manual`, shown as unverified. An editor can later "attach the certificate" to upgrade it to verified — the new expiry must match or the user confirms the replacement.
3. **Renew / replace.** From a certificate's detail page, upload the successor. The old record is marked `superseded_by` and archived (kept for history), notifications for it stop, calendar event for it is cancelled/updated (see below).

Duplicate detection by SHA-256 fingerprint: uploading an already-registered certificate links to the existing record instead of creating a second one.

### Certificate detail (`/certificates/{id}`, viewer; actions for editor)
Fields, renewal chain (previous/next), notification history, calendar invite history, audit trail, actions: renew/replace, edit label/owner/recipients, archive (soft delete with reason), "send test notification for this certificate".

### Notifications
- Global settings (editor): default recipient emails, calendar recipient emails (may differ), Teams Workflows webhook URL, thresholds list (default `60, 30, 14, 7, 1`), and "notify daily while expired" toggle (default on). Per-certificate override: extra recipients, mute.
- Daily job (in-process scheduler, configurable time, plus `POST /api/jobs/run` for editors/cron): for each active certificate, for each threshold crossed since the last run, send once. `notification_log(cert_id, threshold, channel, sent_at, status, error)` guarantees idempotency across restarts. Failures are retried on the next run and surfaced on the settings page and `/healthz`.
- **Email**: SMTP with STARTTLS or implicit TLS (host, port, user, password, from, envelope settings via env). Subject like `Certificate "Integration PROD" expires in 30 days (8 April 2027)`. Plain-text and HTML parts. Body: what it is, when it expires, what to do, link to the detail page.
- **Teams**: Adaptive Card 1.4 with the same facts and a link. Post to the Workflows webhook; handle 429/5xx with backoff.
- **Calendar**: iCalendar via email. On registration, send a `METHOD:REQUEST` invite to the calendar recipients: an all-day event on the expiry date titled `Certificate expires: <label>`, plus a second all-day event at expiry − 30 days titled `Renew certificate: <label>`, each with `VALARM` reminders (7 days and 1 day). Stable `UID`s derived from certificate id (`cert-<id>-expiry@notafter`, `cert-<id>-renew@notafter`), `SEQUENCE` incremented on every change, `METHOD:CANCEL` when a certificate is archived or replaced, new invites for the successor. Must render correctly in Outlook and Google Calendar; use `ORGANIZER` = the SMTP from-address. Provide a "resend calendar invites" action.
- Settings page has "send test email", "send test Teams card", "send test invite to me".

### Audit
Every create/update/archive/settings change/notification is written to `audit_log(actor_email, action, target, at, details_json)` and shown at `/audit` (editor). No file contents in details.

## Stack and structure

- Python 3.12, FastAPI, SQLModel/SQLAlchemy on SQLite (WAL mode), Alembic migrations, Jinja2 templates, `cryptography`, `PyJWT` (with JWKS fetch), APScheduler, `aiosmtplib` or `smtplib`, `httpx`, `icalendar`, `python-multipart`, `slowapi` or equivalent for rate limiting.
- Frontend: Jinja2 pages + one TypeScript bundle for the upload/extraction flow (Vite or esbuild, output committed to `app/static/` or built in the Docker multi-stage). Strict TS, no `any`.
- Layout:
  ```
  notafter/
    app/            (FastAPI: main.py, auth.py, models.py, parsing.py, notify/{email,teams,ics}.py, jobs.py, templates/, static/)
    web/            (TypeScript source for the upload flow, vendored libs, build config)
    tests/          (pytest; see acceptance list)
    alembic/
    Dockerfile      (multi-stage: node build → python runtime, non-root, read-only)
    docker-compose.yml  (single service; port 127.0.0.1:8087:8000, volume notafter-data:/data, healthcheck, security_opt no-new-privileges, read_only, tmpfs /tmp; no cloudflared, no proxy)
    .env.example
    README.md       (setup, Cloudflare Access + Tunnel ingress steps, SMTP/Teams setup, backup/restore, runbook)
    Makefile or justfile (dev, test, lint, build, audit)
  ```
- Code values: clean and readable, strong typing (mypy strict passes), explicit error handling with user-facing messages that explain what to do, concise docstrings. Ruff for lint/format.

## Acceptance criteria (write tests for these)

- Uploading a PEM that contains a `PRIVATE KEY` block → 400, no DB row, nothing on disk, log line contains no key material.
- Uploading a PKCS#12 file directly to the server → 400 with guidance; no parsing attempted.
- Uploading a valid PEM/DER/P7B → record created with correct notAfter, CN, fingerprint; uploading it again → links to existing record.
- Manual entry → record shown as unverified; attaching a matching certificate later flips it to verified.
- Renewal: old record superseded and archived, old calendar events cancelled (METHOD:CANCEL emails generated with incremented SEQUENCE), new invites sent.
- Notification job run twice in a row → each threshold notification sent exactly once; restart between runs doesn't cause duplicates.
- Threshold crossing computed from `not_after` at run time; a certificate expiring in 30 days triggers the 30-day rule, not the 60-day one again.
- Access JWT with wrong audience/issuer/expired → 401; valid JWT with email not in `EDITOR_EMAILS` → can view but every editor action returns 403.
- CSP and security headers present on every response; no external origins referenced anywhere in served HTML/JS/CSS.
- Browser extraction (Playwright test, can be marked optional in CI): a PKCS#12 with password → user prompted, only PEM leaves the page (assert request body), no key material in the request.
- Container starts read-only as non-root and `/healthz` returns OK with scheduler status and last job result.

## How to work

1. Read this whole document first. Then write a short implementation plan (files, models, endpoints, job design) and list any question that would block you — only real blockers, otherwise proceed with sensible defaults and note them in the README's "Decisions" section.
2. Build in this order, committing after each: (a) models + migrations + parsing + rejection tests; (b) auth middleware; (c) board and detail pages; (d) upload flow incl. TypeScript extraction; (e) notifications (email, Teams, iCalendar) + scheduler + idempotency tests; (f) settings/audit pages; (g) Docker, compose, README, runbook. (c)/(d) and (e) are independent and can be done in either order.
3. Keep the board's visual language exactly as specified; don't add decoration.
4. Finish with: test run output, `pip-audit`/`npm audit` output, a `LICENSE` (MIT), a `CONTRIBUTING.md`, and a README section "What is and isn't stored" that a non-technical reviewer can understand. Sample data, screenshots and fixtures use fictional names only (e.g. `example.org`, "Integration PROD").