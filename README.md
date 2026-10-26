<div align="center">

# Iceberg College ERP

**Enterprise Resource Planning for Language Learning Centers**

[![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)](https://www.python.org/)
[![Django](https://img.shields.io/badge/Django-5.x-green?style=flat-square&logo=django)](https://www.djangoproject.com/)
[![Flutter](https://img.shields.io/badge/Flutter-mobile%20%2B%20web-02569B?style=flat-square&logo=flutter)](https://flutter.dev/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

[Live Demo](https://app.iceberglc.com) · [Report Bug](https://github.com/Jahongir359/College-ERP/issues) · [Request Feature](https://github.com/Jahongir359/College-ERP/issues)

</div>

---

A full-featured ERP system for educational institutions: manage students, staff, attendance, results, assignments, invoices, and notifications — all from a unified Django backend with Flutter mobile and web clients.

## Repository layout

| Directory | Contents |
|---|---|
| `backend/` | Django ERP backend — REST API, web admin, templates |
| `mobile/` | Flutter mobile app (`iceberg_app`) — Android & iOS |
| `web/` | Where Django serves the Flutter web build (`/app/`, generated, not committed) |
| `infra/` | Deployment infra: nginx config, setup script, PWA assets |
| `docs/` | Contributing guide, security policy, deployment docs, screenshots |
| `.do/` | DigitalOcean App Platform spec (`app.yaml`; DigitalOcean is stopped, new host pending) |
| `.github/` | GitHub Actions workflows and issue templates |

## Quick start

```bash
# 1. Clone and configure
git clone https://github.com/Jahongir359/College-ERP.git
cd College-ERP
cp .env.example .env          # edit DJANGO_SECRET_KEY, DATABASE_URL

# 2. Install backend dependencies
python3.11 -m venv venv && source venv/bin/activate
pip install -r backend/requirements.txt

# 3. Set up the database and start
cd backend
python manage.py migrate
python manage.py runserver
```

Visit http://127.0.0.1:8000/ (web ERP) or http://127.0.0.1:8000/api/v1/ (REST API).

## Documentation

| Document | Description |
|---|---|
| [backend/README.md](backend/README.md) | Backend setup, API overview, linting |
| [mobile/README.md](mobile/README.md) | Flutter app setup, build instructions |
| [web/README.md](web/README.md) | Flutter web artifacts and rebuild steps |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Full deployment guide (DO, VPS, local) |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | How to contribute |
| [docs/SECURITY.md](docs/SECURITY.md) | Security policy |

## Tech stack

- **Backend**: Python 3.11, Django 5, Django REST Framework, SimpleJWT, Gunicorn
- **Database**: PostgreSQL (production), SQLite (dev)
- **Mobile/Web client**: Flutter (Dart)
- **Hosting**: one Docker image (`Dockerfile`); host to be chosen (see `docs/plans/ICEBERG_SCHOOL_APP_PLAN.md`, D9)
- **CI**: GitHub Actions (Django tests, Flutter APK build)
