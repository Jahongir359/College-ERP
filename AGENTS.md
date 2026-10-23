# AGENTS.md — guide for AI agents working on this repo

Read this first, then the plan for whatever you are working on in `docs/plans/`.

## Active initiative

**Iceberg School brand** — run the new Iceberg School on this same ERP with its own brand (maroon
crest) while the Iceberg Learning Center stays exactly as it is.
Full spec, architecture, phases, checklist and progress log:
**[`docs/plans/ICEBERG_SCHOOL_BRAND_PLAN.md`](docs/plans/ICEBERG_SCHOOL_BRAND_PLAN.md)**.
Brand assets: `docs/brand/iceberg-school/`. Update that plan's Progress log at the end of each session.

## Repo layout

| Path | What |
|---|---|
| `backend/` | Django 5.2 ERP: `college_management_system/` (settings, urls), `main_app/` (models, views, REST API in `api/`, templates, static) |
| `mobile/iceberg_app/` | Flutter app (Android/iOS/web), Riverpod + go_router, theme in `lib/core/theme/` |
| `web/flutter_web/` | Flutter web build output, served by Django at `/app/` — do not hand-edit |
| `infra/` | nginx, PWA/TWA assets, deploy scripts |
| `docs/` | plans, deployment, security, brand assets |

**Root `main_app/`, `college_management_system/`, `manage.py`, `requirements.txt`, `runtime.txt` are
symlinks into `backend/`** so the DigitalOcean build (`.do/app.yaml`) works from the repo root.
Edit files under `backend/`; never delete or replace the symlinks.

## Commands (run from `backend/`; CI runs the same in `.github/workflows/django.yml`)

```bash
python -m ruff check .              # CI pins ruff==0.15.15
python -m ruff format --check .
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py collectstatic --noinput --dry-run -v 0
python manage.py test               # 133 tests passing as of 2026-10-23
```

All must pass before a commit. Flutter (`flutter analyze`, `flutter test`) needs a machine with
Flutter installed — it is not installed in the codespace.

## Domain rules

- Roles: `CustomUser.user_type` `"1"` Admin/HOD, `"2"` Staff/Teacher, `"3"` Student. There is no
  parent role.
- Branch-scoped access lives **only** in `backend/main_app/branching.py`. Never filter by branch
  inline in views, forms or the API.
- Super admins see all branches; branch admins see `Admin.branches`; teachers see groups they teach;
  students see their own data.
- `/` and `/login/` are the ERP login page. Don't repurpose `/`.
- `main_app/middleware.py` `LoginCheckMiddleWare` redirects anonymous users to login unless the
  path is on its allow-list — any new public page must be added there (with a test).
- Every user-facing string must exist in Uzbek, Russian and English (web templates and
  `mobile/iceberg_app/lib/core/i18n/strings.dart`).

## Working conventions

- Prefer small, additive changes. Migrations: additive only, generated with `makemigrations`.
- Match the surrounding code style; don't reformat files you aren't changing.
- Don't change existing Learning Center colors or copy; brand work goes through the brand layer
  described in the plan.
- Commit messages follow `type(scope): summary`, e.g. `feat(brand): add Branch.brand field`,
  `fix(web): …`, `i18n(mobile): …`.
- Commit or push only when the owner asks; branch off `main` first.
- Secrets live in env vars (see `/.env.example`); never commit real values.
