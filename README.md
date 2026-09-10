# No After

A certificate expiry board. Someone uploads a certificate, everyone else sees
a plain-language page saying how long is left, and the right people get an
email, a Teams message and a calendar invite before it runs out.

It was written for the certificates that middleware teams renew by hand and
track nowhere — AS2 signing and encryption certificates, TLS server
certificates, partner and client certificates. NotAfter never connects to the
systems that use those certificates. It is only fed the files.

**No After is a register of expiry dates, not a key store. It never receives,
parses, stores, logs or transmits a private key.** Everything else in the
design gives way to that.

- Self-hosted and MIT licensed. A private repository, not a public project.
- One container, SQLite, no cloud dependency.
- Server-rendered pages; the only JavaScript is the bundle that reads
  `.pfx` files inside your browser.
- No external assets at run time: no CDN, no web fonts, no analytics.

---

## What is and isn't stored

This section is for anyone reviewing NotAfter who does not work with
certificates every day.

A certificate file comes in two shapes. A **certificate** on its own is public
information — it is what a server hands to anyone who connects to it, and it
says who the certificate is for, who issued it, and when it expires. A
**keystore** (a `.pfx` or `.p12` file) is a certificate *plus its private
key* — the secret half, which proves ownership. Private keys must never be
copied around.

### What No After stores

For each certificate, exactly these fields:

| Field | Example | Why |
|---|---|---|
| Label | `Integration PROD` | The name people recognise |
| Environment, owner, notes | `PROD`, `owner@example.org` | Typed in by a person |
| Subject common name | `edi.example.org` | Which system it is for |
| Subject and issuer | `CN=edi.example.org,O=…` | Who it is for, who issued it |
| Serial number | `18374…` | Identifies it to the issuer |
| Valid from / valid until | `8 April 2027` | The point of the whole app |
| SHA-256 fingerprint | `A1:B2:…` | Spots a re-upload of the same file |
| Subject alternative names | `DNS:edi.example.org` | Other names it covers |
| Key algorithm and size | `RSA, 2048 bits` | Describes the key; is not the key |
| The public certificate (PEM) | `-----BEGIN CERTIFICATE-----…` | Public; used to re-check and de-duplicate |

Plus who registered it and when, which notifications went out, and an audit
line for every change.

### What No After never stores

- **Private keys.** No column in the database can hold one. There is no code
  path that reads one.
- **The uploaded file.** Nothing is written to disk or to a temporary
  directory. Uploads are parsed in memory and dropped.
- **The password of a `.pfx` file.** It is typed into the page and used by
  your browser. It is never sent to the server.
- **Request bodies, in any log.** Log lines are filtered so that PEM blocks,
  passwords, tokens and webhook URLs are masked even if a stack trace would
  otherwise print them.

### How a `.pfx` is handled

1. You pick the file. It is read by **your browser**, not uploaded.
2. If it is encrypted, the page asks for the password. That happens in the
   tab; nothing has left your machine yet.
3. The browser opens only the *certificate bags* of the file. The key bags are
   skipped — they are never decrypted or read. Files from Windows,
   `keytool` and older OpenSSL use RC2-40 or Triple DES, which browsers have
   no built-in support for, so those are decrypted in JavaScript by
   node-forge.
4. The page shows you what it found and sends the server **only the public
   certificate**, as text.
5. The file bytes and the password are discarded.

The server independently refuses anything that could carry a key. Send it a
`.pfx` directly — or a PEM file with a `PRIVATE KEY` block in it — and it
answers `400` before parsing anything, and writes nothing anywhere. There are
tests for each of those cases.

---

## How it works

### Global settings, and per-certificate ones

The settings page holds the defaults: which days before expiry send an email
and a Teams card, how far ahead the renewal event sits, what alarms attendees
get, how often an expired certificate re-alerts Teams, where amber and red
fall, and who is notified. The only timing fixed by the environment is what
time of day the job runs (`DAILY_RUN_TIME`).

Any certificate can depart from those defaults on its own page — its own
reminder days, its own calendar lead time and alarms, its own list of people,
or a mute. Each is an override: leave it empty and the certificate follows the
global setting, so a certificate differs only where somebody said it should.
Its page states which of the two it is following.

**One message, not one each.** Everyone on a certificate's list is addressed
on a single email, and they are the attendees on that certificate's two
calendar events — so people can see who else knows, and a reply reaches them.

**Teams stays global.** A channel is somewhere people are invited in Teams;
which of them should hear about which certificate is not something this
application can or should decide. Per-certificate control over Teams is
therefore the mute, and nothing finer.

| Page | Who | What |
|---|---|---|
| `/` | everyone | The board: every certificate, soonest expiry first |
| `/certificates/{id}` | everyone | One certificate, its history and its notifications |
| `/certificates/new` | editors | Upload a file, or type in an expiry date |
| `/settings` | editors | Recipients, thresholds, Teams webhook, test messages |
| `/audit` | editors | Every change anyone has made |
| `/healthz` | the container | Scheduler state and the last job result |

**Status colours.** Green above 60 days, amber at 60 or fewer, red at 30 or
fewer, red once expired. Both thresholds are configurable. "Days left" is
never stored — it is worked out from the expiry date every time a page is
rendered or a notification is considered.

**Who did what.** Access authenticates every request, so there is no login
page — the first request carrying a new Access token *is* the sign-in, and it
is recorded as `auth.signin` in the audit trail with the email from the JWT.
Subsequent requests on the same token are the same session, so this is one
line per person per session rather than one per request. Every change is
recorded against the same email. Neither record holds the token, a cookie or
an IP address.

**Notifications.** The job runs **once a day**, at `DAILY_RUN_TIME`. Each
certificate gets **at most one message per run**, on every configured channel —
so email and Teams carry the same reminder, on the same day.

Which day? The nearest reminder it has just crossed — 60, 30, 14, 7 and 1 day
before expiry by default, plus the expiry day itself, which is always notified
whatever the list says. Only the nearest one: a certificate registered with 20
days left gets the 30-day reminder, not the 60-day one as well. Each is sent
**exactly once, ever** — a unique constraint in the database means a restart, a
second run or a manual run cannot repeat one.

So over a certificate's last two months that is six messages per channel, on
six separate days.

**Once a certificate has expired the two channels part company.** Email stays
on the daily run. Teams escalates: a second job runs **every hour, on the
hour**, and re-posts the alert for every expired certificate until it is
**renewed, archived or muted** — the card itself says so, so nobody has to
work out how to make it stop. The interval is on the settings page ("Repeat
the Teams alert every … hours once expired"); 0 puts Teams back on the daily
run. Both jobs are idempotent, so a restart or a catch-up run inside the same
hour sends nothing extra.

Failures are retried on the next run and shown on the settings page and
`/healthz`.

**Calendar invites.** Registering a certificate sends **one** calendar event:
an all-day event on the expiry date, carrying every reminder as an alarm — 30 days ahead to start the renewal, then
7 days and 1 day, all configurable globally and per certificate. "Start
renewing" and "this expires soon" are the same event seen from different
distances, so a second invitation would only mean a second thing to accept and
keep in step.

It is **published, not invited** (`METHOD:PUBLISH`, no attendee list, no
RSVP). A meeting invitation would make Outlook email the organiser every time
somebody accepts or declines it — and the address these come from only sends,
so each of those replies bounces back to the person who clicked as a delivery
failure. Nobody needs to accept a notice that a certificate expires. Who else
was told is named in the event's description instead, which informs without
asking for an answer.

The UID is stable, so replacing or archiving the certificate updates or
cancels the event people already have in Outlook or Google Calendar rather
than leaving it behind. A cancellation also renames the event
"Cancelled: …", because a published event is an appointment rather than a
meeting and not every client acts on `METHOD:CANCEL`. Changing a timing re-sends the invitation for the same
reason: a calendar only moves an event when it receives an update for that
UID, so without it the new setting would apply to future registrations only
and quietly disagree with what is already out there.

---

## Requirements

- A Linux host with Docker and the Compose plugin.
- An existing **host-level** `cloudflared` service, already connected to your
  Cloudflare account.
- A Cloudflare Access application in front of the hostname you will use.
- A [Resend](https://resend.com) account with a verified sending domain,
  or any SMTP server.
- Optionally, a Microsoft Teams **Workflows** webhook.

NotAfter does not run a tunnel, a reverse proxy or an ACME client, and the
compose file has exactly one service. Ingress is the host's business.

---

## Setup

### 1. Get the code and write the configuration

```bash
git clone https://github.com/example/notafter.git
cd notafter
cp .env.example .env
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'   # SECRET_KEY
```

Fill in `.env`. The values that matter most:

| Variable | What it is |
|---|---|
| `BASE_URL` | The public URL. It goes into every email and invite. |
| `SECRET_KEY` | The value you just generated. |
| `CF_ACCESS_TEAM` | The `<team>` in `https://<team>.cloudflareaccess.com`. |
| `CF_ACCESS_AUD` | The Access application's Audience tag (step 3). |
| `EDITOR_EMAILS` | Who may change things. Everyone else is read-only. |
| `RESEND_API_KEY` | From the Resend dashboard. |
| `EMAIL_FROM` | The sending address, on a domain verified in Resend. It is also the organiser of every calendar invite. |

The app refuses to start in `AUTH_MODE=cloudflare` without `CF_ACCESS_TEAM`
and `CF_ACCESS_AUD`, or with the placeholder `SECRET_KEY` still in place.

### 2. Add the tunnel ingress rule (outside this repository)

In your Cloudflare dashboard, on the tunnel the host already runs, add an
ingress rule:

```
certs.example.org  →  http://127.0.0.1:8087
```

Or, if the host's `cloudflared` is configured from a file, add to its
`ingress:` list — *before* the catch-all rule:

```yaml
ingress:
  - hostname: noafter.example.org
    service: http://127.0.0.1:8087
  - service: http_status:404
```

then `sudo systemctl reload cloudflared`.

The container publishes only to `127.0.0.1:8087`, so nothing but the host —
and therefore nothing but the tunnel — can reach it.

### 3. Create the Cloudflare Access application (outside this repository)

In **Zero Trust → Access → Applications**, add a **self-hosted** application
for `certs.example.org`. Add a policy for the people who should see the board.
Then open the application's **Overview** tab and copy the **Application
Audience (AUD) Tag** into `CF_ACCESS_AUD` in your `.env`.

Every request now arrives with a `Cf-Access-Jwt-Assertion` header. NotAfter
validates that token against Cloudflare's published keys on every request, and
takes the user's email address from it. It never trusts a header on its own.

### 4. Start it

```bash
docker compose up -d --build
docker compose logs -f notafter
curl -s http://127.0.0.1:8087/healthz
```

Open `https://certs.example.org`, sign in through Access, and go to
**Settings** to add the notification recipients.

### 5. Tell the world the sending domain takes no mail

`EMAIL_FROM` only sends. Nothing this app produces asks for a reply — the
calendar event is published rather than invited, and every message says so in
as many words — but somebody will eventually press Reply anyway.

If the domain has no MX record at all, their mail server keeps trying to
connect, fails, and eventually hands them a delivery failure that reads as
though something is broken. A **null MX** ([RFC 7505](https://www.rfc-editor.org/rfc/rfc7505))
says the domain accepts no mail, so the rejection is immediate and its reason
is plain:

| Field | Value |
|---|---|
| Type | `MX` |
| Name | the sending subdomain, for example `notifications` |
| Mail server | `.` — a single dot |
| Priority | `0` |

Put it on the name in `EMAIL_FROM`, which is usually a subdomain of your own,
and check first that nothing else already answers there. It does not affect
sending: providers verify a domain with their own records on their own names,
and this one is separate from those.

If you would rather read replies, do the opposite — give the domain a real MX
and a mailbox. Cloudflare Email Routing does this for a subdomain under
**Email Routing → Settings → Subdomains**, and writes the records itself.

### 6. Microsoft Teams (optional)

In Teams, on the channel you want: **Workflows → "Post to a channel when a
webhook request is received"**. Create it, copy the URL, and paste it into
**Settings → Microsoft Teams**. Then press **Send test Teams card**.

**Read the result carefully.** A Workflows webhook replies `202 Accepted` as
soon as it has queued the flow run — *before* any of the flow's own steps
execute. So a 202 proves the URL is live and the request was accepted; it does
not prove a card reached the channel. If none appears, the flow ran and failed,
and its **run history in Power Automate** names the step that broke. The
settings page shows the exact JSON that is posted, so you can compare it with
what your flow expects: the card is in `attachments[0].content`.

The test posts the *same* card as a real reminder, with one extra line saying
it is a test — so if the test renders, real notifications will too.

The URL is a secret. It is stored in the database, never shown again after it
is saved, and masked in log lines. The retired "Office 365 connector" webhooks
are not supported — the payload NotAfter sends is an Adaptive Card 1.4.

### 7. Check that notifications work

On the settings page: **Send test email to me**, **Send test Teams card**,
**Send test invite to me**. Then **Run the notification job now** — it is
idempotent, so it is safe to press whenever you like.

---

## Day-to-day

**Registering a certificate.** Register → *Upload a file* → pick it. For a
`.pfx`, the page asks for the password if it needs one, and shows what it
found before anything is sent. If you do not have the file, use *Enter the
expiry by hand*; the record is marked unverified until someone attaches the
certificate later.

**Renewing.** Open the certificate, use **Renew or replace**, upload the
successor. The old record is archived and kept, its reminders stop, its
calendar events are cancelled, and new invites go out for the replacement.

**Quietening one certificate.** Open it and tick *Mute reminders*. Or archive
it, with a reason.

---

## Runbook

**Nothing is being sent.** Check `/healthz` (`scheduler.running` should be
`true`, `last_job` should be recent) and the *Recent problems* table on the
settings page, which shows the actual error. Failures retry on the next run;
**Run the notification job now** retries immediately.

**Someone can see the board but cannot change anything.** Their address is not
in `EDITOR_EMAILS`. Add it and restart the container.

**Everyone gets 401.** The Access application's AUD tag does not match
`CF_ACCESS_AUD`, or the request is not coming through Access at all. Compare
the AUD tag in the dashboard with your `.env`.

**A reminder went out twice.** It should not be possible; the database
prevents it. Check `notification_log` — if there really are two `sent` rows
for one `(certificate, channel, rule)`, that is a bug worth reporting.

**Backup.** Everything is in the `notafter-data` volume:

```bash
docker compose stop notafter
docker run --rm -v notafter-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/notafter-$(date +%F).tar.gz -C /data .
docker compose start notafter
```

**Restore.**

```bash
docker compose down
docker volume create notafter-data
docker run --rm -v notafter-data:/data -v "$PWD":/backup alpine \
  tar xzf /backup/notafter-2027-04-08.tar.gz -C /data
docker compose up -d
```

The database is SQLite in WAL mode, so back it up with the container stopped,
or copy `notafter.db`, `notafter.db-wal` and `notafter.db-shm` together.

**Upgrading.** `git pull && docker compose up -d --build`. Migrations run at
start-up. Take a backup first.

---

## Development

```bash
make setup      # virtual environment and npm packages
make dev        # http://127.0.0.1:8000 with AUTH_MODE=dev
make check      # lint, types, tests, dependency audit
```

`AUTH_MODE=dev` takes the user's email from an `X-Dev-User` header, which
anyone could forge — it is for local work only and binds to `127.0.0.1`.

```
app/                FastAPI application
  parsing.py          the refusal gate, then the parser
  auth.py             AuthProvider, Cloudflare Access, dev header
  notifier.py         who gets told, once
  notify/             email, Teams, iCalendar
  jobs.py             the daily job and the scheduler
web/src/            TypeScript: in-browser .pfx extraction
tests/              pytest, including an optional Playwright test
alembic/            migrations
```

Run the browser test — which proves that only PEM leaves the page — with:

```bash
.venv/bin/pip install playwright && .venv/bin/playwright install chromium
.venv/bin/pytest -m browser
```

`tests/test_pfx_extraction.py` runs the same TypeScript through Node against a
`.pfx` in every encryption scheme, including the legacy ones Windows and
`keytool` produce. Run those if you touch anything under `web/src/`.

### Rules to keep

Notes to a later self, each of which exists because ignoring it caused a
problem once.

**Never let a private key reach the server.** A change is wrong if it parses
PKCS#12 server-side "just to read the certificate", writes an upload to disk
or a temp directory even briefly, sends a password or a `.pfx` to the server,
or adds a column, log line or error page that could carry key material. The
tests in `tests/test_parsing.py`, `tests/test_upload_routes.py` and
`tests/test_browser_extraction.py` exist to make those mistakes loud — do not
weaken them to make a change pass.

**Read every generated migration before running it.** `alembic revision
--autogenerate` does not know about Python-side defaults, so it writes
`NOT NULL` columns with no `server_default`. Those cannot be added to a table
that already holds rows, and the failure appears as a crash-looping container
against real data, not in the test suite. This has happened three times. Test
each migration against a copy of the live database:

```bash
docker cp notafter:/data/notafter.db /tmp/copy.db
DATABASE_URL="sqlite:////tmp/copy.db" .venv/bin/alembic upgrade head
```

**Keep the identifiers stable.** iCalendar `UID`s and `PRODID`, the Python
package, the database file and the container all still say `notafter`. A
calendar client matches an update to the event someone already holds by
`UID`; renaming would orphan every invitation ever sent.

**Fictional data only.** Fixtures, examples and screenshots use `example.org`
and invented labels. Real hostnames and addresses live in `.env` and in the
database, and neither is committed.

**Explain, don't blame.** Every error a person can see should say what
happened and what to do next. The board is read by people who do not know
what a certificate is: no jargon, no abbreviations, no all-caps.

---

## Security

- **Authentication** is delegated to a trusted identity-aware proxy behind a
  small `AuthProvider` interface. Cloudflare Access is built in; adding OIDC
  means writing one class. The Access JWT is validated on every request —
  issuer, audience, expiry and signature, against keys fetched from
  `/cdn-cgi/access/certs` and cached. The email in that token is the identity
  used everywhere: it names who signed in and who made every change.
- **Roles** are `viewer` (anyone who passes Access) and `editor` (listed in
  `EDITOR_EMAILS`). Every editor action re-checks.
- **CSRF**: signed double-submit tokens on every state-changing request.
- **Rate limits** on uploads and settings changes, per user.
- **CSP** is `default-src 'self'` with no `unsafe-inline` and no
  `unsafe-eval`, plus `frame-ancestors 'none'`, `nosniff` and
  `Referrer-Policy: no-referrer`. There is a test asserting that no served
  page, script or stylesheet mentions an external origin.
- **The container** runs as uid 10001 with a read-only root filesystem, all
  capabilities dropped, `no-new-privileges`, and a pinned base image by
  digest. It needs outbound access to your SMTP server and, if you use it, the
  Teams webhook, and `api.resend.com` when email goes through Resend. Nothing
  else.

---

## Decisions

Choices made while building this, and why.

- **A small in-process rate limiter instead of `slowapi`.** The specification
  said "slowapi or equivalent". One container serves this app, so a
  sliding-window limiter in memory is exactly as effective and is 40 lines
  with a test, rather than another dependency.
- **The Teams webhook lives in the database, not the environment.** It is
  entered on the settings page so it can be rotated without a redeploy. It is
  never rendered back into the page and is masked in logs.
- **`/healthz` needs no authentication.** The container healthcheck calls it
  from inside the container, before any proxy. It exposes no certificate data
  — only whether the scheduler is running and how the last job went.
- **CSRF is a dependency, not middleware.** Reading the token out of a
  multipart body in middleware consumes the request stream before the endpoint
  can parse it. As a FastAPI dependency it shares Starlette's form cache with
  the endpoint, so both see the same fields.
- **Only the nearest crossed threshold is sent.** A certificate added with 20
  days left would otherwise fire 60, 30 *and* 14 at once. The thresholds it
  skipped are written to `notification_log` as `skipped`, so they cannot fire
  later either.
- **The built browser bundle is committed to `app/static/`.** The Dockerfile
  rebuilds it from source anyway; committing it means `make dev` and the test
  suite work without Node installed.
- **pkijs walks the PKCS#12 structure; node-forge decrypts it.** The
  specification allowed node-forge "if PKCS#12 support is more robust", and it
  is: pkijs implements only PBES2, so a `.pfx` from Windows, `keytool` or
  older OpenSSL — RC2-40 or Triple DES, neither of which WebCrypto has —
  could not be opened at all. Only the blob holding certificate bags is
  decrypted; the private key bag is encrypted separately and is never passed
  to the decryptor. Importing forge's individual modules rather than its index
  keeps 140 KB out of the bundle.
- **Email goes through Resend's HTTP API by default, and this costs something.**
  Resend has no way to express a `multipart/alternative` `text/calendar` part,
  which is what makes Outlook and Google Calendar render an invite with accept
  and decline buttons. Over the API an invite arrives as an `.ics` attachment
  with the right `method=` content type — openable, but not a native invite.
  Resend's own SMTP relay does not have this limitation, so
  `EMAIL_PROVIDER=smtp` with `SMTP_HOST=smtp.resend.com` is the setting to use
  if the calendar behaviour matters more than the API does. Both go through
  the same Resend account.
- **The display name is "No After"; the identifiers are not.** The wordmark,
  the page titles and the wording of every message say "No After". The
  iCalendar `UID`s and `PRODID` still say `notafter`, and must: a calendar
  client matches an update or a cancellation to the event someone already
  holds by `UID`, so changing it would orphan every invite ever sent. The
  Python package, the database file and the container keep the old name for
  the same reason — they are addresses, not branding.
- **Two vendored typefaces, both subset.** Inter for everything, subset to
  Latin with its weight and optical-size axes intact (119 KB). Nabla for the
  wordmark, subset to its eight characters (5 KB) — a chromatic COLRv1 face
  recoloured to the brand palette with `@font-palette-values`. Both are SIL
  OFL and their licences are served next to them. Sources and the rebuild
  step are in `assets/fonts/`.
- **`create_all` at start-up as well as Alembic.** Migrations are what runs in
  the container; `create_all` is what makes a fresh test database. Both derive
  from the same models.

## Licence

MIT — see [LICENSE](LICENSE).
