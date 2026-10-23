# Web — files Django serves next to the ERP

| Path | What |
|---|---|
| `flutter_web/` | The Flutter web app, served at `/app/` by `main_app/flutter_view.py` (override with `FLUTTER_WEB_DIR`). **Generated, not committed** (`.gitignore`). |
| `downloads/iceberg.apk` | The Android APK offered at `/download/` (override with `DOWNLOADS_DIR`). |

## Where `flutter_web/` comes from

- **Deploys:** the `Dockerfile` builds the app with `flutter build web --release --base-href /app/`
  and copies the output here inside the image. Nothing to commit.
- **Local development:** run `mobile/iceberg_app/build_web.sh`, which builds with the same flags
  and copies the output here.

`--base-href /app/` is required: Django only serves the bundle under `/app/`, and a build
without it shows a blank screen.
