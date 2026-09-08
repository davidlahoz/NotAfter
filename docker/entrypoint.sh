#!/bin/sh
# Bring the database schema up to date, then hand over to the app.
#
# Migrations run as the same unprivileged user as the app; /data is the only
# writable path in the container.
set -eu

echo "notafter: applying database migrations"
alembic upgrade head

exec "$@"
