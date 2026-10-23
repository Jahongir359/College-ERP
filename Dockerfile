# The ERP as one image: Django + Gunicorn, with the Flutter web app (served at /app/)
# compiled during the build, so its output no longer lives in git.
#
#   docker build -t iceberg-erp .
#   docker run -p 8080:8080 --env-file .env iceberg-erp
#
# Set MIGRATE_ON_START=1 on hosts without a separate pre-deploy step to run
# `migrate` before Gunicorn starts.

# ---- Flutter web build -------------------------------------------------------
FROM debian:bookworm-slim AS flutter
ARG FLUTTER_VERSION=3.47.7
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git unzip xz-utils \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${FLUTTER_VERSION}" https://github.com/flutter/flutter.git /opt/flutter
ENV PATH="/opt/flutter/bin:${PATH}"
RUN flutter config --no-analytics --enable-web && flutter precache --web
WORKDIR /src/mobile/iceberg_app
COPY mobile/iceberg_app/pubspec.yaml mobile/iceberg_app/pubspec.lock ./
RUN flutter pub get
COPY mobile/iceberg_app/ ./
# --base-href /app/ is required: Django only serves the bundle under /app/ (see build_web.sh).
RUN flutter build web --release --base-href /app/

# ---- Django --------------------------------------------------------------------
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080
WORKDIR /srv
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY . .
COPY --from=flutter /src/mobile/iceberg_app/build/web/ web/flutter_web/
RUN cd backend \
    && DJANGO_DEBUG=False DJANGO_SECRET_KEY=collectstatic-only DJANGO_ALLOWED_HOSTS=localhost \
       python manage.py collectstatic --noinput \
    && useradd --create-home --uid 10001 app \
    && mkdir -p media \
    && chown -R app /srv/backend/media
USER app
EXPOSE 8080
CMD ["sh", "-c", "cd backend && if [ \"${MIGRATE_ON_START:-0}\" = 1 ]; then python manage.py migrate --noinput; fi && exec gunicorn college_management_system.wsgi --workers 3 --timeout 120 --bind 0.0.0.0:${PORT}"]
