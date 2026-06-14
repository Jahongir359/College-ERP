import hashlib
import hmac
import os
import mimetypes
import subprocess
from pathlib import Path
from django.http import FileResponse, Http404, JsonResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

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


# ---------------------------------------------------------------------------
# Deploy webhook — POST /api/deploy/flutter/
# Pulls the latest code from GitHub and hot-reloads the Flutter web files.
# Protected by HMAC-SHA256 signature (X-Deploy-Signature header) derived from
# DEPLOY_SECRET env var.  Set DEPLOY_SECRET on the VPS then call:
#
#   SECRET=<value>
#   PAYLOAD='{"ref":"refs/heads/main"}'
#   SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')
#   curl -X POST https://app.iceberglc.com/api/deploy/flutter/ \
#        -H "Content-Type: application/json" \
#        -H "X-Deploy-Signature: sha256=$SIG" \
#        -d "$PAYLOAD"
# ---------------------------------------------------------------------------

REPO_ROOT = str(Path(settings.BASE_DIR).parent)
_DEPLOY_SECRET = os.environ.get("DEPLOY_SECRET", "")


def _verify_signature(body: bytes, header: str) -> bool:
    if not _DEPLOY_SECRET:
        return False
    if not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(_DEPLOY_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


@csrf_exempt
@require_POST
def deploy_flutter(request):
    sig = request.headers.get("X-Deploy-Signature", "")
    if not _verify_signature(request.body, sig):
        return JsonResponse({"error": "forbidden"}, status=403)

    try:
        result = subprocess.run(
            ["git", "pull", "origin", "main"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return JsonResponse(
            {
                "ok": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            },
            status=200 if result.returncode == 0 else 500,
        )
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=500)
