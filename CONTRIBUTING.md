# Contributing to NotAfter

Thanks for wanting to help. This document is short on purpose; the one part
that is not negotiable is the first section.

## The rule that shapes everything

**NotAfter must never receive, parse server-side, persist, log or transmit
private key material.**

A change is not acceptable if it:

- adds server-side PKCS#12 parsing, even "just to extract the certificate";
- writes an upload to disk or to a temporary directory, even briefly;
- sends a password or a `.pfx` file to the server for any reason;
- adds a database column, log line or error page that could carry a key;
- loosens the refusal gate in `app/parsing.py`.

If you think you have a case that genuinely needs one of these, open an issue
first and make the argument there. The tests in `tests/test_parsing.py` and
`tests/test_upload_routes.py` exist to make these mistakes loud, so please
don't weaken them to make a change pass.

## Getting set up

```bash
make setup      # Python virtual environment plus npm packages
make dev        # http://127.0.0.1:8000, AUTH_MODE=dev
make check      # what CI runs: lint, types, tests, dependency audit
```

You need Python 3.12 and Node 22 or newer.

## Before you open a pull request

```bash
make format     # ruff format and safe fixes
make check      # must pass
```

`make check` runs Ruff, `mypy --strict`, `tsc --noEmit`, the test suite,
`pip-audit` and `npm audit`. All of them must pass. There is also an optional
browser test that proves a `.pfx` never leaves the page:

```bash
.venv/bin/pip install playwright && .venv/bin/playwright install chromium
.venv/bin/pytest -m browser
```

Please run it if you touch anything in `web/src/`.

## House style

- **Explain, don't blame.** Every error a user can see should say what
  happened and what to do next. "That file contains a private key" is a start;
  "…so the upload was refused and nothing was saved. Upload only the
  certificate, or use manual entry" is the whole sentence.
- **Plain language on the board.** The board is read by people who do not know
  what a certificate is. No jargon, no abbreviations, no all-caps.
- **Keep the visual language.** Paper background, graphite text, one accent
  rule in orange, three status colours, one typeface. The countdown is the
  only bold thing on the page. No cards, no shadows, no gradients.
- **Type everything.** `mypy --strict` for Python, `strict` TypeScript with no
  `any`.
- **Docstrings say why.** What the code does is usually visible; why it exists
  usually is not.

## Changing the database

Edit `app/models.py`, then:

```bash
make migration m="what changed"
make migrate
```

Read the generated migration before committing it — autogenerate is a good
first draft, not a finished one. SQLite needs `render_as_batch`, which is
already configured.

## Fictional data only

Examples, fixtures, screenshots and sample data use `example.org` and invented
labels such as "Integration PROD". Never commit a real hostname, a real email
address or a real certificate — not even an expired one.

## Reporting a vulnerability

Please do not open a public issue. Email the maintainers listed in the
repository metadata with the details and how to reproduce it, and give them a
reasonable window to respond before disclosing.
