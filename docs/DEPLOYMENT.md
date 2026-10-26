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
| `CSRF_TRUSTED_ORIGINS` | No | Comma-separated trusted origins |
| `REGISTRATION_LEADS_API_TOKEN` | No | Token for public registration API |
| `RECOVERY_ADMIN_EMAIL` | No | Fallback admin login email |
| `RECOVERY_ADMIN_PASSWORD` | No | Fallback admin login password |
| `SPACES_KEY` / `SPACES_SECRET` | No | DigitalOcean Spaces credentials for media |
| `SPACES_BUCKET` | No | Spaces bucket name |
| `SPACES_REGION` | No | Spaces region (e.g. `fra1`) |
