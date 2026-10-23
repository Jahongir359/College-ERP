# ICEBERG Flutter Web App

Flutter web client for the College ERP Django API. It covers the student, staff,
admin, and superadmin frontend surfaces that are mapped in
`../FLUTTER_WEB_FRONTEND_PARITY_PLAN.md`.

## API Target

The app reads `API_BASE_URL` at build time:

```bash
flutter run -d chrome --dart-define=API_BASE_URL=http://127.0.0.1:8000/api/v1
flutter build web --release --dart-define=API_BASE_URL=https://app.iceberglc.com/api/v1
```

If `API_BASE_URL` is not provided, the app defaults to
`https://app.iceberglc.com/api/v1`.

## Local Checks

```bash
flutter pub get
dart format lib
flutter analyze
flutter build web --release --dart-define=API_BASE_URL=https://app.iceberglc.com/api/v1
```

## Django Serving

Django serves the built Flutter bundle from `web/flutter_web/` at `/app/`. Deploys build it in
the `Dockerfile`; locally, run `./build_web.sh` (it uses the required `--base-href /app/`).

## Current Parity Notes

- Staff attendance and results use the DRF contracts in `main_app/api/views.py`.
- Staff payments use `/api/v1/staff/payments/`, a read-only board matching the
  Django staff payment page.
- Notifications, messages, profile editing, and profile image upload are
  API-backed shared screens.
