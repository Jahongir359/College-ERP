import os
import mimetypes
from pathlib import Path
from django.http import FileResponse, Http404
from django.conf import settings
from django.shortcuts import render

FLUTTER_DIR = os.environ.get(
    "FLUTTER_WEB_DIR", str(Path(settings.BASE_DIR).parent / "web" / "flutter_web")
)

DOWNLOADS_DIR = os.environ.get(
    "DOWNLOADS_DIR", str(Path(settings.BASE_DIR).parent / "web" / "downloads")
)


def flutter_app(request, path="/"):
    # Strip leading slash and default to index.html
    rel = path.lstrip("/")

    if not rel:
        rel = "index.html"

    file_path = os.path.realpath(os.path.join(FLUTTER_DIR, rel))

    # Security: block path traversal
    if not file_path.startswith(os.path.realpath(FLUTTER_DIR)):
        raise Http404

    if os.path.isfile(file_path):
        mime, _ = mimetypes.guess_type(file_path)
        response = FileResponse(
            open(file_path, "rb"), content_type=mime or "application/octet-stream"
        )
        # Never cache the entry HTML, JS bundle or the (self-destruct) service
        # worker — this guarantees a redeploy is picked up immediately and the
        # browser can't get stuck on a stale boot.
        if rel == "index.html" or rel.endswith(".js") or rel.endswith(".json"):
            response["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response

    # SPA fallback: any unknown path returns index.html so Flutter's router handles it
    index = os.path.join(FLUTTER_DIR, "index.html")
    if os.path.isfile(index):
        response = FileResponse(open(index, "rb"), content_type="text/html")
        response["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response

    raise Http404


def download_apk(request):
    """Serve the latest ICEBERG Android APK for direct download."""
    apk_path = os.path.join(DOWNLOADS_DIR, "iceberg.apk")
    if not os.path.isfile(apk_path):
        raise Http404("APK not yet available")
    response = FileResponse(
        open(apk_path, "rb"),
        content_type="application/vnd.android.package-archive",
        as_attachment=True,
        filename="ICEBERG.apk",
    )
    response["Cache-Control"] = "no-cache"
    return response


def download_page(request):
    """Landing page with installation instructions for the Android APK."""
    apk_path = os.path.join(DOWNLOADS_DIR, "iceberg.apk")
    apk_size_mb = ""
    if os.path.isfile(apk_path):
        apk_size_mb = f"{os.path.getsize(apk_path) / 1_048_576:.0f}"
    return render(
        request,
        "main_app/download.html",
        {"apk_size_mb": apk_size_mb},
    )
