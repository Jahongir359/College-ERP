# Deployment Guide

This document covers all deployment options for the Iceberg College ERP.

---

## 1. DigitalOcean App Platform (primary)

The primary deployment uses DigitalOcean App Platform, configured in `.do/app.yaml`.

### How it works

- **Service** (`web`): built from the repo's `Dockerfile`, which compiles the Flutter web app,
  installs the Python requirements, runs `collectstatic` and starts Gunicorn on port 8080.
- **Pre-deploy job** (`db-migrate`): the same image runs `manage.py migrate` before traffic is
  switched to the new release, guaranteeing zero-downtime schema changes.

The same `Dockerfile` runs on any container host. Where there is no pre-deploy step, set
`MIGRATE_ON_START=1` so the container migrates before Gunicorn starts.

### Required environment variables (set in App Platform dashboard)

| Variable | Description |
|---|---|
| `DJANGO_SECRET_KEY` | Long random string — generate with `get_random_secret_key()` |
| `DATABASE_URL` | DigitalOcean managed PostgreSQL connection string |
| `DJANGO_ALLOWED_HOSTS` | `${APP_DOMAIN},app.iceberglc.com` |
| `CORS_ALLOWED_ORIGINS` | Comma-separated allowed origins for the public website |
| `CSRF_TRUSTED_ORIGINS` | `https://${APP_DOMAIN},https://app.iceberglc.com` |
| `EMAIL_HOST_USER` | Gmail (or SMTP) sender address |
| `EMAIL_HOST_PASSWORD` | Gmail App Password |
| `RECOVERY_ADMIN_EMAIL` | Fallback admin email |
| `RECOVERY_ADMIN_PASSWORD` | Fallback admin password |
| `REGISTRATION_LEADS_API_TOKEN` | Shared secret for the public registration form |

### Deploying

Push to `main` — `deploy_on_push: true` triggers a deployment automatically.
Monitor progress in the DigitalOcean dashboard.

---

## 2. VPS / Self-hosted (Ubuntu 22.04)

Use `infra/deploy/setup.sh` to set up a fresh server.

```bash
# As root on a fresh Ubuntu 22.04 server:
curl -sSL https://raw.githubusercontent.com/Jahongir359/College-ERP/main/infra/deploy/setup.sh | sudo bash
```

The script:
1. Installs nginx, certbot, Python 3.11, PostgreSQL, and build tools.
2. Clones the repository to `/home/iceberg/College-ERP`.
3. Creates a virtualenv and installs `backend/requirements.txt`.
4. Creates `.env` from `.env.example` (edit before first run!).
5. Runs `migrate` and `collectstatic`.
6. Installs the Gunicorn systemd service (`infra/deploy/gunicorn.service`).
7. Configures nginx (`infra/deploy/nginx.conf`) and obtains an SSL certificate.

### Post-setup

Edit `/home/iceberg/College-ERP/.env` to set `DATABASE_URL`, email credentials, etc.,
then:

```bash
sudo systemctl start gunicorn-iceberg
sudo systemctl status gunicorn-iceberg
```

Logs: `sudo journalctl -u gunicorn-iceberg -f`

---

## 3. Local development

```bash
# 1. Clone the repo
git clone https://github.com/Jahongir359/College-ERP.git
cd College-ERP

# 2. Set up environment
cp .env.example .env    # edit DATABASE_URL, etc.

# 3. Create virtualenv and install dependencies
python3.11 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt

# 4. Run migrations
cd backend
python manage.py migrate

# 5. Start dev server
python manage.py runserver
```

Visit http://127.0.0.1:8000/

---

## 4. Database migrations

Migrations run automatically on DigitalOcean via the pre-deploy job.

On VPS or local dev:

```bash
cd backend
python manage.py migrate
```

After modifying models, generate a new migration:

```bash
python manage.py makemigrations
python manage.py migrate
```

---

## 5. Flutter web rebuild

The web app served at `/app/` is built during the deploy: the `Dockerfile` compiles it with
`flutter build web --release --base-href /app/` and copies it into the image, so the build output
is not committed. Push Flutter changes to `main` and the next deploy serves them.

For local development, `mobile/iceberg_app/build_web.sh` builds with the same flags into
`web/flutter_web/` (git-ignored).

---

## 6. Environment variables reference

See `/.env.example` for a complete, commented list of all environment variables.

| Variable | Required | Description |
|---|---|---|
| `DJANGO_SECRET_KEY` | Yes | Django secret key (50+ char random string) |
| `DATABASE_URL` | Prod only | PostgreSQL connection URL |
| `DJANGO_DEBUG` | No | `True` for dev, `False` (default) for prod |
| `DJANGO_ALLOWED_HOSTS` | Prod only | Comma-separated allowed hostnames |
| `DJANGO_MEDIA_ROOT` | No | Path to user uploads directory |
| `FLUTTER_WEB_DIR` | No | Override path to Flutter web build |
| `EMAIL_HOST_USER` | No | SMTP sender email |
| `EMAIL_HOST_PASSWORD` | No | SMTP password / App Password |
| `CORS_ALLOWED_ORIGINS` | No | Comma-separated CORS origins |
| `MIN_APP_VERSION` | No | Oldest supported app version, like `1.2.0`; older apps ask for an update (`GET /api/v1/app/version/`). Blank = no minimum |
| `MIN_APP_VERSION_ANDROID` | No | Overrides `MIN_APP_VERSION` for the Android app |
| `MIN_APP_VERSION_IOS` | No | Overrides `MIN_APP_VERSION` for the iPhone app |
| `APP_STORE_URL_ANDROID` | No | Google Play page the app's "update" screen opens |
| `APP_STORE_URL_IOS` | No | App Store page the app's "update" screen opens |
| `CSRF_TRUSTED_ORIGINS` | No | Comma-separated trusted origins |
| `REGISTRATION_LEADS_API_TOKEN` | No | Token for public registration API |
| `RECOVERY_ADMIN_EMAIL` | No | Fallback admin login email |
| `RECOVERY_ADMIN_PASSWORD` | No | Fallback admin login password |
| `SPACES_KEY` / `SPACES_SECRET` | No | DigitalOcean Spaces credentials for media |
| `SPACES_BUCKET` | No | Spaces bucket name |
| `SPACES_REGION` | No | Spaces region (e.g. `fra1`) |
| `BACKUP_DIR` | No | Where `backup_db` writes (default `backend/backups/`); see section 7 |
| `BACKUP_KEEP` | No | `backup_db` keeps only the newest N backups (default 0 = keep all) |
| `PG_DUMP` | No | `pg_dump` binary for `backup_db` (default: `pg_dump` on PATH) |

---

## 7. Database backups and restore (plan task P0.7)

### Two layers

1. **The database host's own backups (the main safety net).** DigitalOcean managed PostgreSQL
   keeps daily backups for 7 days with point-in-time restore, with nothing to set up: restore from
   the database cluster's **Backups** tab, which creates a new cluster from a chosen moment; then
   point `DATABASE_URL` at it. If PostgreSQL runs on the app's own VPS (D9), there is no such
   layer, so the off-site copies below become the only backups and must run daily.
2. **Extra off-site copies with `manage.py backup_db`.** One file per run, kept somewhere other than
   the database server (another provider, an office machine, object storage).

### `backup_db`

```bash
cd backend
python manage.py backup_db                                  # writes to $BACKUP_DIR or backend/backups/
python manage.py backup_db --output-dir /var/backups/iceberg --keep 14
```

- PostgreSQL: runs `pg_dump --format=custom --no-owner --no-acl` against `DATABASE_URL` and writes
  `iceberg-db-YYYYmmdd-HHMMSS.dump`. The password is passed in the environment, not on the command
  line. **`pg_dump`'s major version must be the server's or newer**: `pg_dump` 15 refuses a 16
  server. Run it from a machine with a matching client (`apt install postgresql-client-16` from
  the PostgreSQL apt repository, or `PG_DUMP=/usr/lib/postgresql/16/bin/pg_dump`). The production
  Docker image does **not** contain `pg_dump`, on purpose: Debian's client is too old for
  DigitalOcean's PostgreSQL 16/17.
- SQLite (local and test setups): copies `db.sqlite3` with SQLite's online backup API, safe while
  the app runs; writes `iceberg-db-YYYYmmdd-HHMMSS.sqlite3`.
- A file gets its final name only when complete (`….partial` while writing, deleted on failure).
- `--keep N` (or `BACKUP_KEEP`) deletes all but the newest N `iceberg-db-*` files in that directory;
  nothing else there is touched.
- Any failure exits non-zero with the reason (pg_dump missing, version mismatch, connection or
  disk errors), so cron or a systemd timer can report it.

Uploads (`DJANGO_MEDIA_ROOT`, or the Spaces bucket) are not in the database backup. On a VPS, copy
that folder with the same job (e.g. `rsync -a /home/iceberg/media/ backup-host:iceberg-media/`).

### Scheduling (owner, on the machine that runs the backups)

Nothing is scheduled by this repo. Example cron line on a backup machine with a matching `pg_dump`,
a checkout of this repo and the production `DATABASE_URL` in its `.env`, every night at 02:30
Tashkent time:

```cron
30 2 * * * cd /home/iceberg/College-ERP/backend && ../venv/bin/python manage.py backup_db --output-dir /var/backups/iceberg --keep 14 >> /var/log/iceberg-backup.log 2>&1
```

Copy `/var/backups/iceberg` off the machine as well (e.g. `rclone sync` to object storage) and check
the log, or add the job to the uptime alerts of P0.8.

### Restore

**PostgreSQL** (`.dump` file):

1. Stop the app, so nothing writes during the restore (App Platform: scale to 0, or
   `sudo systemctl stop gunicorn-iceberg` on a VPS).
2. Restore into the database named by `DATABASE_URL`. `--clean --if-exists` drops the existing
   tables first:

   ```bash
   pg_restore --clean --if-exists --no-owner --no-acl --dbname "$DATABASE_URL" iceberg-db-20261101-023000.dump
   ```

   Safer: restore into a **new, empty** database, check it, then point `DATABASE_URL` at it.
3. `python manage.py migrate` (a no-op unless the backup is older than the code), then start the
   app again and sign in.

**SQLite** (`.sqlite3` file): stop the app, copy the file over `backend/db.sqlite3`, start the app.

### Test the restore (once a month, and after any hosting change)

A backup only counts once it has been restored. Into a scratch database, never production:

```bash
createdb iceberg_restore_test
pg_restore --no-owner --no-acl --dbname iceberg_restore_test iceberg-db-20261101-023000.dump
psql iceberg_restore_test -c "select count(*) from main_app_customuser;"
psql iceberg_restore_test -c "select max(applied) from django_migrations;"
dropdb iceberg_restore_test
```

The counts should match production and the latest migration should be recent. Write the date and
the result in the plan's Progress log (P0.7).
