from django.contrib import admin
from django.urls import path, include, re_path
from django.conf.urls.static import static
from django.views.generic import RedirectView
from django.views.static import serve
from rest_framework_simplejwt.views import TokenRefreshView
from . import settings
from main_app.flutter_view import flutter_app, deploy_flutter, download_apk

urlpatterns = [
    path("", include("main_app.urls")),
    # Redirect the Django auth login to our branded login page.
    path("accounts/login/", RedirectView.as_view(url="/login/", permanent=False)),
    path("admin/", admin.site.urls),
    # Mobile API v1
    path("api/v1/", include("main_app.api.urls")),
    # JWT token refresh (stateless — no login required)
    path("api/v1/auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    # Flutter web app — served at /app/
    re_path(r"^app(?P<path>/.*)$", flutter_app, name="flutter_app"),
    path("app", RedirectView.as_view(url="/app/", permanent=False)),
    # Deploy webhook — triggers git pull on the VPS (HMAC-protected)
    path("api/deploy/flutter/", deploy_flutter, name="deploy_flutter"),
    # APK download
    path("download/app.apk", download_apk, name="download_apk"),
]

# Serve uploaded media files (profile pictures, etc.) in all environments.
# Django's serve() view is used here because:
#   - static() helper returns [] when DEBUG=False, breaking production uploads.
#   - For a college ERP the traffic volume is low enough that Django serving
#     media is acceptable. For high traffic, replace with nginx or DO Spaces.
urlpatterns += [
    re_path(r"^media/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT}),
]

# In development also serve the static files via Django (not needed in
# production because WhiteNoise handles them at the WSGI layer).
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)


# Branded error pages (Django uses these automatically when DEBUG=False).
handler400 = "main_app.views.bad_request"
handler403 = "main_app.views.permission_denied"
handler404 = "main_app.views.page_not_found"
handler500 = "main_app.views.server_error"
