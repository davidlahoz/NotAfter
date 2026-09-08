# syntax=docker/dockerfile:1

# --------------------------------------------------------------------------
# Stage 1 — build the browser bundle.
#
# The TypeScript that reads .pfx files in the user's browser is bundled here
# so that the running app serves everything from itself: no CDN, no runtime
# download, nothing to trust at page load.
# --------------------------------------------------------------------------
FROM node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS web

WORKDIR /build
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/tsconfig.json ./
COPY web/src ./src
RUN npx tsc --noEmit \
 && npx esbuild src/upload.ts --bundle --minify --format=iife --target=es2020 \
      --outfile=/build/upload.js --legal-comments=none

# --------------------------------------------------------------------------
# Stage 2 — Python dependencies, into a virtual environment we can copy.
# --------------------------------------------------------------------------
FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS deps

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install -r requirements.txt

# --------------------------------------------------------------------------
# Stage 3 — the runtime image. Non-root, no build tools, no shell utilities
# beyond what the base image ships.
# --------------------------------------------------------------------------
FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS runtime

LABEL org.opencontainers.image.title="NotAfter" \
      org.opencontainers.image.description="A certificate expiry board with upload, notifications and calendar invites." \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/example/notafter"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    DATABASE_URL="sqlite:////data/notafter.db" \
    HOME=/tmp

# A fixed uid/gid so the named volume's ownership is predictable.
RUN groupadd --gid 10001 notafter \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin notafter \
 && mkdir -p /data \
 && chown 10001:10001 /data

COPY --from=deps /opt/venv /opt/venv

WORKDIR /app
COPY --chown=root:root alembic.ini ./
COPY --chown=root:root alembic ./alembic
COPY --chown=root:root app ./app
COPY --from=web --chown=root:root /build/upload.js ./app/static/upload.js
COPY --chown=root:root docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0555 /usr/local/bin/entrypoint.sh \
 && python -m compileall -q /app/app

USER 10001:10001
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=60s --timeout=10s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=8); sys.exit(0 if r.status==200 else 1)"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["uvicorn", "app.main:build", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
